"""
crawler/utils.py — Link extraction and URL helpers for the .onion crawler.

Public API:
    extract_onion_links(html, base_url)  → List[str]
    is_valid_onion(url)                  → bool
    normalize_url(url)                   → str
"""

from __future__ import annotations

import re
from typing import List
from urllib.parse import urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Compiled regexes
# ---------------------------------------------------------------------------

# Base32 alphabet: a-z and 2-7 (RFC 4648)
# v2 onion: exactly 16 base32 chars  (deprecated but still in the wild)
# v3 onion: exactly 56 base32 chars
_ONION_HOST_RE = re.compile(
    r"^(?:[a-z2-7]{16}|[a-z2-7]{56})\.onion$",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def extract_onion_links(html: str, base_url: str = "") -> List[str]:
    """
    Extract all .onion hrefs from raw HTML and return as absolute URLs.

    - Resolves relative hrefs against *base_url* when provided.
    - Filters out non-.onion results using is_valid_onion().
    - Deduplicates within the returned list (first occurrence wins).
    - Never raises — returns [] on any parse failure.
    """
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return []

    seen: set[str] = set()
    results: List[str] = []

    for tag in soup.find_all("a", href=True):
        href = str(tag["href"]).strip()
        if not href or href.startswith("#") or href.lower().startswith("javascript:"):
            continue

        # Resolve relative URLs
        if base_url:
            try:
                absolute = urljoin(base_url, href)
            except Exception:
                continue
        else:
            absolute = href

        normalized = normalize_url(absolute)
        if not normalized or normalized in seen:
            continue

        if is_valid_onion(normalized):
            seen.add(normalized)
            results.append(normalized)

    return results


def is_valid_onion(url: str) -> bool:
    """
    Return True if *url* is a syntactically valid .onion URL.

    Accepts both v2 (16-char base32) and v3 (56-char base32) hostnames.
    Scheme must be http or https.  Port, path, and query are allowed.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return False

    if parsed.scheme not in ("http", "https"):
        return False

    hostname = (parsed.hostname or "").lower()
    return bool(_ONION_HOST_RE.match(hostname))


def normalize_url(url: str) -> str:
    """
    Return a canonical form of *url* suitable for deduplication.

    Transformations applied:
      - Lowercase scheme and host
      - Strip URL fragment (#…)
      - Strip trailing slashes from path (root "/" preserved as empty)
      - Preserve query string and params unchanged
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return url

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path

    # Strip trailing slashes but keep the path otherwise intact
    if path and path != "/":
        path = path.rstrip("/")
    elif path == "/":
        path = ""

    # Rebuild without fragment
    return urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))
