"""
Playwright-based JavaScript renderer for dark web content.

Used as a fallback when aiohttp returns empty content from JS-heavy sites.
Routes traffic through Tor SOCKS5 proxy same as the main scraper.
"""

import logging
from typing import Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Playwright browser instance — shared across scrape calls
_BROWSER = None
_BROWSER_LOCK = None

# Maximum time to wait for page content (ms)
PAGE_TIMEOUT_MS = 30_000  # 30 seconds

# Selectors to wait for — indicates page has rendered
CONTENT_SELECTORS = [
    "article",
    "main",
    ".post",
    ".thread",
    ".message",
    "#content",
    ".content",
    "[role='main']",
]

# JS app markers for detection
JS_APP_MARKERS = [
    'id="app"',
    'id="root"',
    'id="__next"',
    "ng-app",
    "data-reactroot",
    "window.__INITIAL_STATE__",
    "window.__NUXT__",
    "<script>window.location",
    # Dark web forum specific
    "Dread",
    "phpBB",
]


def is_js_rendered(html: str, extracted_text: str) -> bool:
    """
    Returns True if the page appears to be a JS-rendered app
    that requires browser execution to get content.

    Criteria:
    - Extracted text is very short (< 300 chars)
    - Raw HTML contains JS app markers
    - HTML has significant script tags but minimal content tags
    """
    if len(extracted_text) >= 300:
        return False  # Already got content, no need for JS

    if not html:
        return False

    html_lower = html.lower()

    # Check for JS app markers
    has_marker = any(marker.lower() in html_lower for marker in JS_APP_MARKERS)

    # Check script-to-content ratio
    script_count = html_lower.count("<script")
    content_count = html_lower.count("<p") + html_lower.count("<div") + html_lower.count("<article")

    high_script_ratio = script_count > 3 and content_count < script_count

    return has_marker or high_script_ratio


async def get_browser(tor_proxy_host: str = "tor", tor_proxy_port: int = 9050):
    """
    Get or create a shared Playwright browser instance.
    Browser routes all traffic through Tor SOCKS5 proxy.
    Launched once, reused across scrape calls.
    """
    global _BROWSER, _BROWSER_LOCK

    if _BROWSER_LOCK is None:
        import asyncio

        _BROWSER_LOCK = asyncio.Lock()

    async with _BROWSER_LOCK:
        if _BROWSER is not None:
            try:
                if _BROWSER.is_connected():
                    return _BROWSER
            except Exception:
                pass

        try:
            from playwright.async_api import async_playwright

            playwright = await async_playwright().start()

            _BROWSER = await playwright.chromium.launch(
                headless=True,
                proxy={
                    "server": f"socks5://{tor_proxy_host}:{tor_proxy_port}",
                },
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--no-first-run",
                    "--no-zygote",
                    "--single-process",
                    # Privacy — match Tor Browser fingerprint loosely
                    "--disable-blink-features=AutomationControlled",
                ],
            )
            logger.info("Playwright browser launched (via Tor proxy)")
            return _BROWSER

        except Exception as e:
            logger.error(f"Failed to launch Playwright browser: {e}")
            raise


async def fetch_with_playwright(
    url: str,
    tor_proxy_host: str = "tor",
    tor_proxy_port: int = 9050,
    timeout_ms: int = PAGE_TIMEOUT_MS,
) -> dict:
    """
    Fetch a URL using Playwright (headless Chromium through Tor).

    Waits for JS to execute and content to render before extracting.
    Returns same dict shape as aiohttp scraper for compatibility.

    Returns:
        {link, content, raw_html, status, posted_at, via}
    """
    result = {
        "link": url,
        "content": "",
        "raw_html": "",
        "status": 0,
        "posted_at": None,
        "via": "playwright",
        "error": None,
    }

    page = None
    context = None
    try:
        import trafilatura
        from scraper.scrape import extract_post_timestamp

        browser = await get_browser(tor_proxy_host, tor_proxy_port)

        # Create a new browser context per request (isolation)
        context = await browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; rv:109.0) "
                "Gecko/20100101 Firefox/115.0"
            ),
            # Disable unnecessary resource loading
            java_script_enabled=True,
            bypass_csp=False,
        )

        # Block images, fonts, media — we only need text content
        await context.route(
            "**/*.{png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,mp4,webm}",
            lambda route: route.abort(),
        )

        page = await context.new_page()

        # Navigate to URL
        response = await page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")

        if response:
            result["status"] = response.status

        # Wait for content to appear (try each selector)
        content_appeared = False
        for selector in CONTENT_SELECTORS:
            try:
                await page.wait_for_selector(
                    selector,
                    timeout=5000,  # 5s per selector attempt
                    state="visible",
                )
                content_appeared = True
                break
            except Exception:
                continue

        if not content_appeared:
            # No known content selector found — wait a fixed time
            # for JS to do whatever it does
            await page.wait_for_timeout(3000)

        # Extract rendered HTML
        raw_html = await page.content()
        result["raw_html"] = raw_html

        # Extract text with trafilatura (same as aiohttp scraper)
        content = trafilatura.extract(
            raw_html,
            include_comments=False,
            include_tables=True,
            no_fallback=False,
        ) or ""

        # Fallback: get visible text directly if trafilatura returns nothing
        if len(content) < 100:
            content = await page.evaluate(
                """() => {
                    const body = document.body;
                    const scripts = body.querySelectorAll('script, style, nav, header, footer');
                    scripts.forEach(s => s.remove());
                    return body.innerText || body.textContent || '';
                }"""
            )
            content = content.strip() if content else ""

        result["content"] = content[:15000]  # Cap at 15k chars

        # Extract post timestamp from rendered HTML
        result["posted_at"] = extract_post_timestamp(raw_html)

        logger.debug(
            f"Playwright scraped {url[:40] if len(url) > 40 else url}... "
            f"→ {len(result['content'])} chars, status={result['status']}"
        )

    except Exception as e:
        result["error"] = str(e)[:100]
        logger.warning(
            f"Playwright failed for {url[:40] if len(url) > 40 else url}...: {e}"
        )

    finally:
        if page:
            try:
                await page.close()
            except Exception:
                pass
        if context:
            try:
                await context.close()
            except Exception:
                pass

    return result


async def close_browser():
    """Shutdown the shared browser. Call on app shutdown."""
    global _BROWSER

    if _BROWSER is not None:
        try:
            await _BROWSER.close()
            logger.info("Playwright browser closed")
        except Exception:
            pass
        _BROWSER = None