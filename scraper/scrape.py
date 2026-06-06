"""
scrape.py — async .onion / clearnet page fetcher for Open_Intel.

Public API (unchanged from Phase 0 — ui.py compatibility guaranteed):
    scrape_multiple(urls_data, max_workers=5)  -> Dict[str, str]
    scrape_single(url_data, ...)               -> Tuple[str, str]
    get_tor_session()                          -> requests.Session

Internals rewritten in Phase 1B:
    ThreadPoolExecutor + requests  →  asyncio + aiohttp-socks
    BeautifulSoup-only extraction  →  trafilatura first, BeautifulSoup fallback
    hardcoded 127.0.0.1:9050      →  TOR_PROXY_HOST / TOR_PROXY_PORT from config
    no retry                      →  3-attempt exponential backoff (2 s / 4 s / 8 s)
    no DB persistence             →  pages written to Phase 1A db/ layer when DATABASE_URL is set
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import random
import re
import warnings
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

import aiohttp
import requests
import trafilatura
from aiohttp_socks import ProxyConnector
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config import TOR_PROXY_HOST, TOR_PROXY_PORT, PLAYWRIGHT_ENABLED

warnings.filterwarnings("ignore")

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants (identical to Phase 0 — ui.py depends on these)
# ---------------------------------------------------------------------------

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (X11; Linux i686; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.3179.54",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.3179.54",
]

MAX_DOWNLOAD_BYTES = 1_000_000
MAX_EXTRACTED_TEXT_CHARS = 50_000
MAX_RETURN_CHARS = 15_000
ALLOWED_CONTENT_TYPES = ("text/html", "application/xhtml+xml", "text/plain")

# Retry configuration
MAX_RETRIES = 1
RETRY_DELAYS = (1.0,)  # seconds before attempt 1
RETRYABLE_STATUS = {500, 502, 503, 504}

# Tor circuit error patterns - indicates circuit failure, not URL failure
SOCKS_ERRORS = (
    "SOCKS5",
    "socks5",
    "Host unreachable",
    "Connection refused",
    "General SOCKS",
    "circuit",
    "Tor circuit",
)

# Internal / link-local ranges — block clearnet fetches (SSRF prevention)
_BLOCKED_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

_BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "metadata.google.internal",
        "169.254.169.254",
    }
)

# Common HTML timestamp patterns (forums / JSON-LD)
_TIMESTAMP_PATTERNS = [
    (r'<time[^>]+datetime="([^"]+)"', "iso"),
    (r"[Pp]osted[:\s]+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", "%Y-%m-%d %H:%M:%S"),
    (r"[Dd]ate[:\s]+(\d{2}/\d{2}/\d{4})", "%d/%m/%Y"),
    (r'data-timestamp="(\d{10})"', "unix10"),
    (
        r'"datePublished":\s*"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"',
        "%Y-%m-%dT%H:%M:%S",
    ),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def extract_post_timestamp(html: str) -> Optional[datetime]:
    """
    Attempt to extract the original post timestamp from raw HTML.

    Returns timezone-aware UTC datetime if found, None if not extractable.
    Never raises — all failures return None.
    """
    try:
        if not html:
            return None

        for pattern, fmt in _TIMESTAMP_PATTERNS:
            try:
                match = re.search(pattern, html)
                if not match:
                    continue
                value = match.group(1).strip()

                if fmt == "iso":
                    s = value.replace("Z", "+00:00")
                    if len(s) >= 19 and "T" not in s[:19]:
                        s = value
                    dt = datetime.fromisoformat(s[:32])
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    else:
                        dt = dt.astimezone(timezone.utc)
                    if datetime(2010, 1, 1, tzinfo=timezone.utc) <= dt <= datetime.now(
                        timezone.utc
                    ):
                        return dt
                    continue

                if fmt == "unix10":
                    ts = int(value)
                    if 1_000_000_000 < ts < 9_999_999_999:
                        return datetime.fromtimestamp(ts, tz=timezone.utc)
                    continue

                sample = value[:19] if len(value) >= 19 else value
                dt = datetime.strptime(sample, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                    if datetime(2010, 1, 1, tzinfo=timezone.utc) <= dt <= datetime.now(
                        timezone.utc
                    ):
                        return dt
            except (ValueError, OverflowError, OSError, TypeError):
                continue

        return None
    except Exception:
        return None


def is_safe_url(url: str) -> bool:
    """
    Return False if URL targets internal/reserved addresses (SSRF prevention).
    .onion hostnames are always allowed (Tor handles routing).
    """
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").strip()
        if hostname.lower().endswith(".onion"):
            return True
        if hostname.lower() in _BLOCKED_HOSTNAMES:
            _logger.warning("SSRF blocked hostname: %s", hostname)
            return False
        try:
            import socket
            resolved_ip_str = socket.gethostbyname(hostname)
        except Exception:
            resolved_ip_str = None

        ips_to_check = [hostname]
        if resolved_ip_str and resolved_ip_str != hostname:
            ips_to_check.append(resolved_ip_str)

        for ip_str in ips_to_check:
            try:
                ip = ipaddress.ip_address(ip_str)
                for blocked_range in _BLOCKED_IP_RANGES:
                    if ip in blocked_range:
                        _logger.warning("SSRF blocked IP %s (from %s) in %s", ip_str, hostname, blocked_range)
                        return False
            except ValueError:
                pass
        return True
    except Exception:
        return False


def validate_urls_for_scraping(
    url_dicts: List[dict],
) -> Tuple[List[dict], List[str]]:
    """
    Filter URL dicts before scraping. Returns (safe_dicts, blocked_url_strings).
    """
    safe: List[dict] = []
    blocked: List[str] = []
    for url_dict in url_dicts:
        link = url_dict.get("link", url_dict) if isinstance(url_dict, dict) else str(url_dict)
        if is_safe_url(link):
            safe.append(url_dict)
        else:
            blocked.append(link)
    if blocked:
        _logger.warning(
            "SSRF prevention blocked %d URLs: %s",
            len(blocked),
            blocked[:5],
        )
    return safe, blocked

def _normalize_url_data(url_data) -> Tuple[str, str]:
    """Extract (url, title) from a search result dict."""
    if not isinstance(url_data, dict):
        return "", "Untitled"
    url = str(url_data.get("link") or "").strip()
    title = str(url_data.get("title") or "Untitled").strip() or "Untitled"
    return url, title


def is_onion_url(url: str) -> bool:
    """Return True if URL is a .onion address requiring Tor."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        return hostname.lower().endswith(".onion")
    except Exception:
        return False


def normalize_url(url: str) -> str:
    """
    Normalize a URL for consistent storage/dedup.
    Uses crawler.utils.normalize_url for consistency.
    """
    try:
        from crawler.utils import normalize_url as _norm
        return _norm(url)
    except ImportError:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path.rstrip("/") if parsed.path else ""
        return urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))


def classify_urls(urls: List[dict]) -> Tuple[List[dict], List[dict]]:
    """
    Split URLs into onion (needs Tor) and clearnet (direct fetch).

    Malformed URLs are treated as clearnet.
    """
    onion_urls: List[dict] = []
    clearnet_urls: List[dict] = []
    for url_dict in urls:
        link = url_dict.get("link", "") if isinstance(url_dict, dict) else str(url_dict)
        if is_onion_url(link):
            onion_urls.append(url_dict)
        else:
            clearnet_urls.append(url_dict)
    return onion_urls, clearnet_urls


def _is_onion(url: str) -> bool:
    """Return True if the URL targets a .onion hostname."""
    return is_onion_url(url)


def _build_proxy_url() -> str:
    """
    SOCKS URL for ``requests`` / urllib3 (PySocks understands ``socks5h`` =
    remote DNS at the proxy, required for ``.onion``).

    ``aiohttp_socks`` uses ``python_socks.parse_proxy_url``, which does *not*
    accept the ``socks5h`` scheme — use :func:`_tor_aiohttp_connector` instead.
    """
    return f"socks5h://{TOR_PROXY_HOST}:{TOR_PROXY_PORT}"


def _tor_aiohttp_connector() -> ProxyConnector:
    """SOCKS5 with remote DNS (same behavior as socks5h) for aiohttp-socks."""
    return ProxyConnector.from_url(
        f"socks5://{TOR_PROXY_HOST}:{TOR_PROXY_PORT}",
        rdns=True,
        limit=20,
        limit_per_host=10,
    )


def _direct_tcp_connector() -> aiohttp.TCPConnector:
    """Direct TCP connector with connection pooling."""
    return aiohttp.TCPConnector(
        limit=30,
        limit_per_host=10,
    )


_tor_session: Optional[aiohttp.ClientSession] = None
_direct_session: Optional[aiohttp.ClientSession] = None


def get_tor_session_cached() -> aiohttp.ClientSession:
    """Return a cached Tor-proxied session for connection reuse."""
    global _tor_session
    if _tor_session is None or _tor_session.closed:
        connector = _tor_aiohttp_connector()
        _tor_session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(connect=3, sock_read=5),
        )
    return _tor_session


def get_direct_session_cached() -> aiohttp.ClientSession:
    """Return a cached direct session for connection reuse."""
    global _direct_session
    if _direct_session is None or _direct_session.closed:
        connector = _direct_tcp_connector()
        _direct_session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(connect=5, sock_read=25),
        )
    return _direct_session


async def close_cached_sessions() -> None:
    """Close cached sessions - call on shutdown."""
    global _tor_session, _direct_session
    if _tor_session and not _tor_session.closed:
        await _tor_session.close()
        _tor_session = None
    if _direct_session and not _direct_session.closed:
        await _direct_session.close()
        _direct_session = None


async def _reset_tor_session_on_error() -> None:
    """Reset cached Tor session on circuit error to force reconnection."""
    global _tor_session
    if _tor_session is not None and not _tor_session.closed:
        try:
            await _tor_session.close()
        except Exception:
            pass
    _tor_session = None


# ---------------------------------------------------------------------------
# Content extraction
# ---------------------------------------------------------------------------

def _extract_text(html: str) -> str:
    """
    Extract main textual content from an HTML string.

    trafilatura is tried first — it strips navbars, footers, ads, and scripts,
    leaving the body text.  If trafilatura returns nothing (or crashes), we fall
    back to the BeautifulSoup path used in Phase 0.

    Always truncates to MAX_EXTRACTED_TEXT_CHARS before returning.
    """
    try:
        text = trafilatura.extract(html, include_comments=False, include_tables=True)
        if text and text.strip():
            return text[:MAX_EXTRACTED_TEXT_CHARS]
    except Exception:
        pass  # lxml parse failure or trafilatura bug → fall through

    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style"]):
        tag.extract()
    text = " ".join(soup.get_text(separator=" ").split())
    return text[:MAX_EXTRACTED_TEXT_CHARS]


def _score_content_quality(text: str) -> str:
    """
    Score scraped content quality for prioritization.

    Returns:
        "empty"  - < 100 chars (likely failed fetch)
        "thin"   - 100-500 chars (minimal content)
        "medium" - 500-2000 chars (decent content)
        "rich"   - > 2000 chars (full content)
    """
    length = len(text) if text else 0
    if length < 100:
        return "empty"
    if length < 500:
        return "thin"
    if length < 2000:
        return "medium"
    return "rich"


# ---------------------------------------------------------------------------
# Async core — fetch with retry
# ---------------------------------------------------------------------------

async def _fetch_one(
    session: aiohttp.ClientSession,
    url_data: dict,
    semaphore: asyncio.Semaphore,
) -> Tuple[str, str, Optional[bytes], Optional[str], Optional[datetime]]:
    """
    Fetch a single URL with exponential-backoff retry.

    Returns:
        (url, display_text, raw_bytes, db_text, posted_at)
        - display_text: "{title} - {extracted_text}" — returned in the public dict
        - raw_bytes:    raw downloaded content (for SHA-256 hash + DB byte_size)
        - db_text:      extracted text only, no title prefix — stored in Page.cleaned_text
        - posted_at:    extracted from HTML when possible, else None

    On any unrecoverable failure returns (url, title, None, None, None).
    Failures never propagate as exceptions — graceful degradation is preserved.
    """
    url, title = _normalize_url_data(url_data)
    if not url:
        return "", title, None, None, None

    if not is_safe_url(url):
        _logger.warning("SSRF blocked fetch: %s", url)
        return url, title, None, None, None

    try:
        from utils.content_safety import is_blocked_url
        url_blocked, _reason = is_blocked_url(url)
        if url_blocked:
            _logger.warning(
                "URL blocked — prohibited content. URL hash: %s",
                hashlib.sha256(url.encode()).hexdigest()[:16],
            )
            return url, title, None, None, None
    except Exception:
        pass

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return url, title, None, None, None

    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8",
    }

    last_exc: object = None

    async with semaphore:
        for attempt in range(MAX_RETRIES + 1):  # attempts: 0, 1, 2, 3
            if attempt > 0:
                await asyncio.sleep(RETRY_DELAYS[attempt - 1])

            try:
                async def _get_with_timeout():
                    connector = _tor_aiohttp_connector() if is_onion_url(url) else _direct_tcp_connector()
                    async with aiohttp.ClientSession(
                        connector=connector,
                        timeout=aiohttp.ClientTimeout(connect=5, sock_read=25 if not is_onion_url(url) else 5),
                    ) as local_session:
                        async with local_session.get(url, headers=headers) as resp:
                            if resp.status in RETRYABLE_STATUS:
                                return "retry", f"HTTP {resp.status}", None, None, None

                            if resp.status != 200:
                                return "fail", None, None, None, None

                            content_type = (resp.headers.get("Content-Type") or "").lower()
                            if content_type and not any(
                                t in content_type for t in ALLOWED_CONTENT_TYPES
                            ):
                                return "fail", None, None, None, None

                            chunks: List[bytes] = []
                            bytes_read = 0
                            async for chunk in resp.content.iter_chunked(8192):
                                if not chunk:
                                    continue
                                bytes_read += len(chunk)
                                if bytes_read > MAX_DOWNLOAD_BYTES:
                                    break
                                chunks.append(chunk)

                            raw_bytes = b"".join(chunks)
                            encoding = resp.charset or "utf-8"
                            return "ok", raw_bytes, encoding, None, None

                status_res, r_bytes, enc, _, _ = await asyncio.wait_for(
                    _get_with_timeout(), timeout=10.0
                )

                if status_res == "retry":
                    last_exc = r_bytes
                    continue
                elif status_res == "fail":
                    return url, title, None, None, None

                raw_bytes = r_bytes
                html = raw_bytes.decode(enc, errors="replace")

                db_text = _extract_text(html)
                posted_at = extract_post_timestamp(html)
                display_text = f"{title} - {db_text}" if db_text else title

                # --- Playwright fallback for JS-rendered pages ---
                if PLAYWRIGHT_ENABLED and db_text and len(db_text) < 300:
                    # Import lazily to avoid import errors when playwright not installed
                    try:
                        from scraper.scrape_js import fetch_with_playwright, is_js_rendered

                        if is_js_rendered(html, db_text):
                            _logger.debug(
                                "Playwright fallback triggered for %s...",
                                url[:40] if len(url) > 40 else url,
                            )
                            js_result = await fetch_with_playwright(
                                url=url,
                                tor_proxy_host=TOR_PROXY_HOST,
                                tor_proxy_port=TOR_PROXY_PORT,
                            )
                            # Use JS result if it got more content
                            if js_result.get("content") and len(js_result.get("content", "")) > len(
                                db_text
                            ):
                                html = js_result.get("raw_html", html)
                                db_text = js_result.get("content", "")
                                posted_at = js_result.get("posted_at", posted_at)
                                display_text = f"{title} - {db_text}" if db_text else title
                                _logger.info(
                                    "Playwright improved content: %d chars from %s...",
                                    len(db_text),
                                    url[:40] if len(url) > 40 else url,
                                )
                    except ImportError:
                        # Playwright not installed - skip silently
                        pass
                    except Exception as e:
                        # Keep original aiohttp result if Playwright fails
                        _logger.debug("Playwright fallback failed: %s", e)
                        pass

                return url, display_text, raw_bytes, db_text, posted_at

            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                error_str = str(exc)
                if any(err.lower() in error_str.lower() for err in SOCKS_ERRORS):
                    _logger.warning(
                        "Tor circuit error for %s: %s",
                        url[:50] if len(url) > 50 else url,
                        error_str[:100],
                    )
                    await _reset_tor_session_on_error()
                    return url, title, None, None, None
                last_exc = exc
            except Exception as exc:
                error_str = str(exc)
                if any(err.lower() in error_str.lower() for err in SOCKS_ERRORS):
                    _logger.warning(
                        "Tor circuit error for %s: %s",
                        url[:50] if len(url) > 50 else url,
                        error_str[:100],
                    )
                    await _reset_tor_session_on_error()
                    return url, title, None, None, None
                last_exc = exc

        # All retries exhausted
        _logger.debug("All retries exhausted for url=%s: %s", url, last_exc)
        return url, title, None, None, None


# ---------------------------------------------------------------------------
# Async orchestrator
# ---------------------------------------------------------------------------

async def _gather_all(
    unique_urls_data: List[dict],
    max_workers: int,
) -> List[Tuple[str, str, Optional[bytes], Optional[str], Optional[datetime]]]:
    """
    Fan out fetches: .onion URLs through Tor (separate concurrency limit),
    clearnet URLs directly (higher concurrency). Results preserve input order.
    """
    onion_urls, clearnet_urls = classify_urls(unique_urls_data)
    _logger.warning(
        "Scraping %d onion URLs (via Tor) + %d clearnet URLs (direct)",
        len(onion_urls),
        len(clearnet_urls),
    )

    sem_tor = asyncio.Semaphore(max_workers)
    sem_clearnet = asyncio.Semaphore(15)

    async def run_onion_batch() -> dict[
        str, Tuple[str, str, Optional[bytes], Optional[str], Optional[datetime]]
    ]:
        if not onion_urls:
            return {}
        out: dict[
            str, Tuple[str, str, Optional[bytes], Optional[str], Optional[datetime]]
        ] = {}
        tor_session = get_tor_session_cached()
        tasks = [
            _fetch_one(tor_session, item, sem_tor) for item in onion_urls
        ]
        rows = await asyncio.gather(*tasks)
        for row in rows:
            if row[0]:
                out[row[0]] = row
        return out

    async def run_clearnet_batch() -> dict[
        str, Tuple[str, str, Optional[bytes], Optional[str], Optional[datetime]]
    ]:
        if not clearnet_urls:
            return {}
        out: dict[
            str, Tuple[str, str, Optional[bytes], Optional[str], Optional[datetime]]
        ] = {}
        direct_session = get_direct_session_cached()
        tasks = [
            _fetch_one(direct_session, item, sem_clearnet)
            for item in clearnet_urls
        ]
        rows = await asyncio.gather(*tasks)
        for row in rows:
            if row[0]:
                out[row[0]] = row
        return out

    tor_map, clearnet_map = await asyncio.gather(
        run_onion_batch(),
        run_clearnet_batch(),
    )

    merged: List[
        Tuple[str, str, Optional[bytes], Optional[str], Optional[datetime]]
    ] = []
    for item in unique_urls_data:
        url, _title = _normalize_url_data(item)
        if not url:
            merged.append(("", _title, None, None, None))
            continue
        if is_onion_url(url):
            merged.append(tor_map.get(url, (url, _title, None, None, None)))
        else:
            merged.append(clearnet_map.get(url, (url, _title, None, None, None)))

    tor_ok = sum(1 for r in merged if r[0] and is_onion_url(r[0]) and r[2])
    clear_ok = sum(
        1 for r in merged if r[0] and not is_onion_url(r[0]) and r[2]
    )
    _logger.warning(
        "Total scraped: %d pages (%d onion, %d clearnet) with stored content",
        tor_ok + clear_ok,
        tor_ok,
        clear_ok,
    )

    return merged


# ---------------------------------------------------------------------------
# DB persistence (runs synchronously after asyncio.run() returns)
# ---------------------------------------------------------------------------

def _persist_pages(
    items: List[
        Tuple[str, str, Optional[bytes], Optional[str], Optional[datetime]]
    ],
) -> None:
    """
    Write successfully scraped pages to the database.

    Gracefully skips if:
    - DATABASE_URL is not configured
    - db/ module is not importable (e.g., sqlalchemy not installed)
    - Any per-URL error (IntegrityError on url uniqueness, etc.)

    One session per URL: a failure on one URL cannot roll back others.
    Content-hash deduplication: identical content at a new URL is not re-inserted.
    """
    try:
        from config import DATABASE_URL as _db_url  # re-import for testability
        if not _db_url:
            return
        from db.queries import create_page, get_or_create_source, get_page_by_hash
        from db.session import get_session
    except ImportError:
        return

    for url, _display, raw_bytes, db_text, posted_at in items:
        if not raw_bytes or not url:
            continue

        content_hash = hashlib.sha256(raw_bytes).hexdigest()

        try:
            with get_session() as session:
                # Content-hash dedup: skip if identical content already stored
                if get_page_by_hash(session, content_hash):
                    continue

                hostname = (urlparse(url).hostname or "").lower()
                source_id = None
                if hostname.endswith(".onion"):
                    src, _ = get_or_create_source(session, hostname)
                    source_id = src.id

                create_page(
                    session,
                    url=url,
                    source_id=source_id,
                    cleaned_text=db_text,
                    raw_content_hash=content_hash,
                    byte_size=len(raw_bytes),
                    posted_at=posted_at,
                )
        except Exception as exc:
            # Swallow silently: URL-uniqueness violations, connection errors, etc.
            # DB persistence must never break the scraping pipeline.
            _logger.debug("DB persist failed url=%s: %s", url, exc)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def scrape_multiple(urls_data, max_workers: int = 5) -> Dict[str, str]:
    """
    Scrape a list of URLs concurrently and return a dict mapping URL → content.

    Arguments and return type are identical to Phase 0 — ui.py is unchanged.

    Pipeline:
        1. Deduplicate input URLs
        2. await _gather_all(...)  — async fetch
        3. Truncate each result to MAX_RETURN_CHARS
        4. Write pages to DB if DATABASE_URL is configured
        5. Return {url: content} dict
    """
    if not isinstance(urls_data, (list, tuple)):
        return {}

    max_workers = max(1, min(int(max_workers), 16))

    # Deduplicate by URL (preserve first occurrence)
    unique_urls_data: List[dict] = []
    seen_links: set = set()
    for item in urls_data:
        url, title = _normalize_url_data(item)
        if not url or url in seen_links:
            continue
        seen_links.add(url)
        unique_urls_data.append({"link": url, "title": title})

    safe_urls, blocked = validate_urls_for_scraping(unique_urls_data)
    if blocked:
        _logger.warning("SSRF: blocked %d unsafe URLs from scrape batch", len(blocked))
    unique_urls_data = safe_urls

    if not unique_urls_data:
        return {}

    # Async fetch phase
    raw_results = await _gather_all(unique_urls_data, max_workers)

    # Assemble public dict with MAX_RETURN_CHARS truncation
    suffix = "...(truncated)"
    results: Dict[str, str] = {}
    db_items: List[
        Tuple[str, str, Optional[bytes], Optional[str], Optional[datetime]]
    ] = []

    for url, display_text, raw_bytes, db_text, posted_at in raw_results:
        if not url:
            continue
        if len(display_text) > MAX_RETURN_CHARS:
            available = MAX_RETURN_CHARS - len(suffix)
            if available > 0:
                display_text = display_text[:available] + suffix
            else:
                display_text = suffix[:MAX_RETURN_CHARS]
        results[url] = display_text
        db_items.append((url, display_text, raw_bytes, db_text, posted_at))

    # DB persistence phase
    await asyncio.to_thread(_persist_pages, db_items)

    return results


async def scrape_single(
    url_data,
    rotate: bool = False,
    rotate_interval: int = 5,
    control_port: int = 9051,
    control_password: Optional[str] = None,
) -> Tuple[str, str]:
    """
    Scrape a single URL.  Public signature identical to Phase 0.

    Extra kwargs (rotate, rotate_interval, control_port, control_password) are
    accepted as no-ops.
    # TODO: Tor circuit rotation — Phase 1C
    """
    url, title = _normalize_url_data(url_data)
    if not url:
        return "", title
    results = await scrape_multiple([url_data], max_workers=1)
    return url, results.get(url, title)


def get_tor_session() -> requests.Session:
    """
    Return a requests.Session pre-configured with the Tor SOCKS5 proxy.

    Kept for backward compatibility with health.py and search.py.
    Proxy host/port are now read from config (TOR_PROXY_HOST / TOR_PROXY_PORT).
    """
    session = requests.Session()
    retry = Retry(
        total=3,
        read=3,
        connect=3,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    proxy_url = _build_proxy_url()
    session.proxies = {
        "http": proxy_url,
        "https": proxy_url,
    }
    return session
