"""
sources/pastes.py — .onion paste site monitor for Phase 1D.

Fetches the recent-pastes index page from known .onion paste services,
then checks each paste for query keyword matches.  Only matching pastes
are returned and persisted to the DB pages table.

All requests go through the Tor SOCKS5 proxy.

Public API:
    async def fetch_recent_pastes(query, max_results=20) -> list[dict]

Each result dict has:
    title           str   — paste title or URL fallback
    url             str   — canonical paste URL
    content_snippet str   — first 500 chars of paste text
    posted_at       datetime | None
    source          str   — paste site name
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urljoin, urlparse

import aiohttp
from aiohttp_socks import ProxyConnector
from bs4 import BeautifulSoup

from config import TOR_PROXY_HOST, TOR_PROXY_PORT

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known .onion paste sites
# ---------------------------------------------------------------------------
# Each entry provides the index URL (recent-pastes listing) and an optional
# URL pattern for individual pastes.  Sites that don't expose a listing will
# simply return no results (graceful empty).

_PASTE_SITES = [
    {
        "name": "DeepPaste",
        "index_url": "http://depastedihryjugl7sxhstlqjmqbedofrm3r5vynzw7rl7mwkv4zmcid.onion/",
        "paste_path_re": re.compile(r"/paste/[a-z0-9]+", re.IGNORECASE),
    },
    {
        "name": "ZeroBin",
        "index_url": "http://zgjnkivynuasfwog7rkkphv5gdtyrcaxp4ihczgyuep2ulokhmuuduuqd.onion/",
        "paste_path_re": re.compile(r"/\?[a-z0-9]+", re.IGNORECASE),
    },
    {
        "name": "Tor Paste",
        "index_url": "http://torpastezlufkmanojgjcrgb4pi7g7fqmr4kuf6fcx46qlc3jhkara6ad.onion/",
        "paste_path_re": re.compile(r"/[a-z0-9]{6,}", re.IGNORECASE),
    },
]

_TIMEOUT = aiohttp.ClientTimeout(connect=15, sock_read=30)
_SNIPPET_LEN = 500


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tor_connector() -> ProxyConnector:
    # python_socks only accepts socks5/socks4/http — use socks5 + rdns (like socks5h)
    return ProxyConnector.from_url(
        f"socks5://{TOR_PROXY_HOST}:{TOR_PROXY_PORT}",
        rdns=True,
    )


def _matches(text: str, query: str) -> bool:
    """Case-insensitive match: every whitespace-separated term must appear."""
    text_lower = text.lower()
    return all(term in text_lower for term in query.lower().split())


def _extract_paste_links(html: str, base_url: str, path_re: re.Pattern) -> List[str]:
    """Return absolute paste URLs found in *html* that match *path_re*."""
    links: List[str] = []
    seen: set[str] = set()
    try:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all("a", href=True):
            href = str(tag["href"]).strip()
            if path_re.search(href):
                absolute = urljoin(base_url, href)
                if absolute not in seen:
                    seen.add(absolute)
                    links.append(absolute)
    except Exception:
        pass
    return links


def _extract_title(soup: BeautifulSoup, url: str) -> str:
    tag = soup.find("title")
    if tag and tag.get_text(strip=True):
        return tag.get_text(strip=True)
    return url


def _extract_posted_at(soup: BeautifulSoup) -> Optional[datetime]:
    """Try common timestamp patterns; returns UTC-aware datetime or None."""
    for tag in soup.find_all(["time", "span", "div"], attrs={"datetime": True}):
        try:
            return datetime.fromisoformat(
                str(tag["datetime"]).replace("Z", "+00:00")
            )
        except (ValueError, KeyError):
            continue
    return None


def _persist_paste(url: str, text: str) -> None:
    """Write a matching paste to the DB pages table. Silent on failure."""
    try:
        from config import DATABASE_URL as _db_url
        if not _db_url:
            return
        from db.queries import create_page, get_or_create_source, get_page_by_hash
        from db.session import get_session
    except ImportError:
        return

    content_hash = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
    try:
        with get_session() as session:
            if get_page_by_hash(session, content_hash):
                return
            hostname = (urlparse(url).hostname or "").lower()
            source_id = None
            if hostname.endswith(".onion"):
                src, _ = get_or_create_source(session, hostname, source_type="crawled")
                source_id = src.id
            create_page(
                session,
                url=url,
                source_id=source_id,
                cleaned_text=text,
                raw_content_hash=content_hash,
                byte_size=len(text.encode("utf-8", errors="replace")),
            )
    except Exception as exc:
        _logger.debug("Paste DB persist failed url=%s: %s", url, exc)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def fetch_recent_pastes(query: str, max_results: int = 20) -> List[dict]:
    """
    Fetch recent paste listings from known .onion paste services and return
    matching pastes (keyword match on title + content).

    Args:
        query:       investigation query; pastes must contain all terms.
        max_results: hard cap on returned results across all sites.

    Returns list[dict] with keys: title, url, content_snippet, posted_at, source.
    Returns [] on any failure — never raises.
    """
    results: List[dict] = []

    try:
        connector = _tor_connector()
        async with aiohttp.ClientSession(
            connector=connector, timeout=_TIMEOUT
        ) as session:
            for site in _PASTE_SITES:
                if len(results) >= max_results:
                    break
                site_results = await _scrape_site(session, site, query, max_results)
                results.extend(site_results)
    except Exception as exc:
        _logger.debug("fetch_recent_pastes session error: %s", exc)

    return results[:max_results]


async def _scrape_site(
    session: aiohttp.ClientSession,
    site: dict,
    query: str,
    max_results: int,
) -> List[dict]:
    """Scrape one paste site and return matching pastes."""
    name = site["name"]
    index_url = site["index_url"]
    path_re: re.Pattern = site["paste_path_re"]
    results: List[dict] = []

    try:
        async with session.get(
            index_url,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) "
                    "Gecko/20100101 Firefox/137.0"
                )
            },
        ) as resp:
            if resp.status != 200:
                return []
            html = await resp.text(errors="replace")
    except Exception as exc:
        _logger.debug("%s index fetch failed: %s", name, exc)
        return []

    paste_links = _extract_paste_links(html, index_url, path_re)
    _logger.debug("%s: found %d paste links", name, len(paste_links))

    for paste_url in paste_links:
        if len(results) >= max_results:
            break
        entry = await _fetch_paste(session, paste_url, name, query)
        if entry:
            results.append(entry)

    return results


async def _fetch_paste(
    session: aiohttp.ClientSession,
    url: str,
    source_name: str,
    query: str,
) -> Optional[dict]:
    """Fetch and keyword-check a single paste URL. Returns None if no match."""
    try:
        async with session.get(url) as resp:
            if resp.status != 200:
                return None
            html = await resp.text(errors="replace")
    except Exception as exc:
        _logger.debug("Paste fetch failed url=%s: %s", url, exc)
        return None

    try:
        soup = BeautifulSoup(html, "html.parser")
        # Extract raw text — prefer <pre> or <textarea> blocks (common for pastes)
        content_tags = soup.find_all(["pre", "textarea", "code"])
        if content_tags:
            text = "\n".join(t.get_text() for t in content_tags).strip()
        else:
            text = soup.get_text(separator="\n").strip()

        title = _extract_title(soup, url)

        # Keyword match against title + content
        haystack = f"{title} {text}"
        if not _matches(haystack, query):
            return None

        posted_at = _extract_posted_at(soup)

        # Persist to DB (silently skips on failure)
        _persist_paste(url, text)

        return {
            "title": title,
            "url": url,
            "content_snippet": text[:_SNIPPET_LEN],
            "posted_at": posted_at,
            "source": source_name,
        }
    except Exception as exc:
        _logger.debug("Paste parse failed url=%s: %s", url, exc)
        return None
