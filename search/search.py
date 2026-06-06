import asyncio
import logging
import random
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Optional

import aiohttp
import requests
from aiohttp_socks import ProxyConnector
from bs4 import BeautifulSoup

from config import TOR_PROXY_HOST, TOR_PROXY_PORT
from search.circuit_breaker import record_failure, record_success, is_open
from utils.async_utils import run_async

logger = logging.getLogger(__name__)

ENGINE_TIMEOUT = 30

ENGINE_WEIGHTS = {
    "darksearch": 1.0,
    "ahmia": 0.9,
    "torch": 0.7,
}


def _normalize_for_dedup(url: str) -> str:
    url = url.lower().rstrip("/")
    url = url.replace("https://", "http://")
    return url


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (X11; Linux i686; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.3179.54",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.3179.54"
]

SEARCH_ENGINES = [
    # confirmed working (zero failures in QA Run 5)
    {"name": "Ahmia (Clearnet Proxy)", "url": "https://ahmia.fi/search/?q={query}"},
    {"name": "Ahmia", "url": "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q={query}"},
    {"name": "Torland", "url": "http://torlbmqwtudkorme6prgfpmsnile7ug2zm4u3ejpcncxuhpu4k2j4kyd.onion/index.php?a=search&q={query}"},
    {"name": "OnionLand", "url": "http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion/search?q={query}"},
    {"name": "Find Tor", "url": "http://findtorroveq5wdnipkaojfpqulxnkhblymc7aramjzajcvpptd4rjqd.onion/search?q={query}"},
    {"name": "TorNet", "url": "http://tornetupfu7gcgidt33ftnungxzyfq2pygui5qdoyss34xbgx2qruzid.onion/search?q={query}"},
    {"name": "Excavator", "url": "http://2fd6cemt4gmccflhm6imvdfvli3nf7zn6rfrwpsy7uhxrgbypvwf5fad.onion/search?query={query}"},
    # unverified - may be intermittent (2 failures in QA Run 5)
    {"name": "Torgle", "url": "http://iy3544gmoeclh5de6gez2256v6pjh4omhpqdh2wpeeppjtvqmjhkfwad.onion/torgle/?query={query}"},
    {"name": "The Deep Searches", "url": "http://searchgf7gdtauh7bhnbyed4ivxqmuoat3nm6zfrg3ymkq6mtnpye3ad.onion/search?q={query}"},
    {"name": "Torgol", "url": "http://torgolnpeouim56dykfob6jh5r2ps2j73enc42s2um4ufob3ny4fcdyd.onion/?q={query}"},
    {"name": "Onionway", "url": "http://oniwayzz74cv2puhsgx4dpjwieww4wdphsydqvf5q7eyz4myjvyw26ad.onion/search.php?s={query}"},
    {"name": "Tor66", "url": "http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion/search?q={query}"},
]

DEFAULT_SEARCH_ENGINES = [e["url"] for e in SEARCH_ENGINES]

_ONION_URL_RE = re.compile(r'https?://[a-z0-9._-]+\.onion(?:/[^\s"\'<>]*)?', re.IGNORECASE)

MAX_CONCURRENT = 10
SEARCH_TIMEOUT = 30
ENGINE_RETRY_COUNT = 2

_ENGINE_STATUS: dict[str, dict] = {}


@dataclass
class EngineResult:
    name: str
    links: list[dict]
    error: Optional[str] = None
    took_ms: int = 0


def _get_tor_session():
    session = requests.Session()
    session.proxies = {
        "http": f"socks5h://{TOR_PROXY_HOST}:{TOR_PROXY_PORT}",
        "https": f"socks5h://{TOR_PROXY_HOST}:{TOR_PROXY_PORT}",
    }
    return session


def _is_onion_url(url: str) -> bool:
    return bool(_ONION_URL_RE.search(url))


def _tor_aiohttp_connector() -> ProxyConnector:
    """SOCKS5 with remote DNS for aiohttp-socks with connection pooling."""
    return ProxyConnector.from_url(
        f"socks5://{TOR_PROXY_HOST}:{TOR_PROXY_PORT}",
        rdns=True,
        limit=10,
        limit_per_host=2,
    )


async def fetch_with_timeout(
    url: str,
    session: aiohttp.ClientSession,
) -> aiohttp.ClientResponse:
    """Fetch a URL with timeout using the provided session."""
    return await session.get(url, timeout=aiohttp.ClientTimeout(total=SEARCH_TIMEOUT))


async def _fetch_engine(
    engine: dict,
    query: str,
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
) -> EngineResult:
    url = engine["url"].format(query=query)
    name = engine["name"]
    is_onion = _is_onion_url(url)
    
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    
    async with semaphore:
        for attempt in range(ENGINE_RETRY_COUNT + 1):
            try:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=SEARCH_TIMEOUT)) as resp:
                    if resp.status != 200:
                        if attempt < ENGINE_RETRY_COUNT:
                            await asyncio.sleep(0.5 * (attempt + 1))
                            continue
                        return EngineResult(
                            name=name,
                            links=[],
                            error=f"HTTP {resp.status}",
                        )
                    
                    text = await resp.text()
                    
                    if "darksearch.io/api" in url:
                        try:
                            import json
                            data = json.loads(text)
                            links = [
                                {"title": hit.get("title", "No Title"), "link": hit.get("onion")}
                                for hit in data.get("data", [])
                                if hit.get("onion")
                            ]
                            return EngineResult(name=name, links=links)
                        except Exception as e:
                            return EngineResult(name=name, links=[], error=f"JSON parse: {e}")
                    
                    links = _parse_html_links(text, url)
                    return EngineResult(name=name, links=links)

            except asyncio.TimeoutError:
                if attempt < ENGINE_RETRY_COUNT:
                    await asyncio.sleep(0.5 * (attempt + 1))
                    continue
                return EngineResult(name=name, links=[], error="timeout")
            except Exception as e:
                if attempt < ENGINE_RETRY_COUNT:
                    await asyncio.sleep(0.5 * (attempt + 1))
                    continue
                return EngineResult(name=name, links=[], error=str(e))
        
        return EngineResult(name=name, links=[], error="max retries")


def _parse_html_links(html: str, base_url: str) -> list[dict]:
    """Extract .onion result links from a search engine result page.

    Handles three common formats:
    - Direct href:    <a href="http://x.onion/path">
    - Redirect param: <a href="/results?url=http://x.onion/path">
    - Plain text:     URLs mentioned in body text but not hyperlinked
    """
    from urllib.parse import urlparse, parse_qs, unquote  # noqa: PLC0415

    links: list[dict] = []
    seen: set[str] = set()
    base_host = (urlparse(base_url).hostname or "").lower()

    def _add(url: str, title: str) -> None:
        host = (urlparse(url).hostname or "").lower()
        if host == base_host:
            return
        norm = url.lower().rstrip("/")
        if norm not in seen:
            seen.add(norm)
            links.append({"title": title[:200], "link": url})

    try:
        soup = BeautifulSoup(html, "html.parser")

        for a in soup.find_all("a"):
            href = (a.get("href") or "").strip()
            title = a.get_text(strip=True)
            if not href or len(title) < 3:
                continue

            # 1. Direct absolute .onion URL in href
            for match in _ONION_URL_RE.findall(href):
                _add(match, title)

            # 2. .onion URL hidden in a query parameter (redirect, url, link, site)
            if ".onion" in href and not _ONION_URL_RE.search(href):
                try:
                    qs = parse_qs(urlparse(href).query)
                    for param in ("url", "redirect", "link", "site", "address", "q"):
                        for val in qs.get(param, []):
                            decoded = unquote(val)
                            for match in _ONION_URL_RE.findall(decoded):
                                _add(match, title)
                except Exception:
                    pass

        # 3. Any .onion URLs in the raw HTML text not captured via <a> tags
        for match in _ONION_URL_RE.findall(html):
            host = (urlparse(match).hostname or "").lower()
            if host != base_host:
                norm = match.lower().rstrip("/")
                if norm not in seen:
                    seen.add(norm)
                    links.append({"title": host, "link": match})

    except Exception:
        pass

    return links


async def _search_async(query: str, max_workers: int = MAX_CONCURRENT) -> list[EngineResult]:
    semaphore = asyncio.Semaphore(max_workers)

    connector = _tor_aiohttp_connector()
    async with aiohttp.ClientSession(
        connector=connector,
        timeout=aiohttp.ClientTimeout(total=SEARCH_TIMEOUT),
    ) as session:

        async def run_engine(engine: dict) -> EngineResult:
            name = engine["name"]
            if await is_open(name):
                logger.warning(f"Skipping unhealthy engine: {name}")
                return EngineResult(name=name, links=[], error="circuit_open")

            url = engine["url"].format(query=query)

            async def fetch_with_engine_session():
                result = await _fetch_engine(engine, query, session, semaphore)
                if result.error:
                    if "HTTP 4" not in result.error:
                        await record_failure(name)
                    logger.warning(f"Engine {name} failed: {result.error}")
                else:
                    await record_success(name)
                    if not result.links:
                        logger.warning(f"Engine {name} returned 0 results")
                return result

            try:
                return await asyncio.wait_for(fetch_with_engine_session(), timeout=ENGINE_TIMEOUT)
            except asyncio.TimeoutError:
                await record_failure(name)
                logger.warning(f"Engine {name} timed out")
                return EngineResult(name=name, links=[], error="timeout")
            except Exception as e:
                await record_failure(name)
                logger.warning(f"Engine {name} exception: {e}")
                return EngineResult(name=name, links=[], error=str(e))

        tasks = [run_engine(e) for e in SEARCH_ENGINES]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        processed: list[EngineResult] = []
        for r in results:
            if isinstance(r, Exception):
                logger.warning(f"Engine task exception: {r}")
                continue
            processed.append(r)

        return processed


def get_search_results_async(query: str, max_workers: int = MAX_CONCURRENT) -> list[dict]:
    """Async search - call from async context."""
    import time
    start = time.monotonic()

    results = run_async(_search_async(query, max_workers))

    all_links = []
    for result in results:
        engine_name = result.name.lower()
        weight = 0.5
        for known in ENGINE_WEIGHTS:
            if known in engine_name:
                weight = ENGINE_WEIGHTS[known]
                break
        for link in result.links:
            link["source_engine"] = result.name
            link["source_weight"] = weight
            all_links.append(link)
        status = "ok" if not result.error else result.error
        logger.debug(f"Engine {result.name}: {len(result.links)} links ({status})")

    unique = _dedupe_links(all_links)
    unique.sort(key=lambda r: r.get("source_weight", 0.5), reverse=True)

    elapsed = (time.monotonic() - start) * 1000
    logger.info(f"Search completed: {len(unique)} unique links in {elapsed:.0f}ms")

    return unique


def _dedupe_links(links: list[dict]) -> list[dict]:
    seen: set[str] = set()
    unique = []
    for link_dict in links:
        link = link_dict.get("link", "")
        normalized = _normalize_for_dedup(link)
        if normalized and normalized not in seen:
            seen.add(normalized)
            unique.append(link_dict)
    return unique


def get_search_results(query: str, max_workers: int = MAX_CONCURRENT) -> list[dict]:
    """Sync wrapper for backward compatibility."""
    return get_search_results_async(query, max_workers)