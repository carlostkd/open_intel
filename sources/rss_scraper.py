"""
sources/rss_scraper.py — RSS/Atom feed scraper for Open_Intel.

Fetches recent articles from curated threat intelligence blogs and feeds
relevant to the investigation query.  Runs over CLEARNET — these are public
security blogs that do not require Tor.

Feed results are cached per-URL for 1 hour (feeds update infrequently).
Articles are scored by relevance to the query and filtered by age (max 90 days).

Public API:
    async def scrape_rss_feeds(
        query: str,
        refined_query: str = "",
        max_results: int = MAX_TOTAL_ARTICLES,
    ) -> list[dict]

Returns page dicts compatible with the extraction pipeline:
    {
        "url": str,
        "text_content": str,
        "title": str,
        "source_type": "rss_feed",
        "source_name": str,
        "feed_category": str,
        "published_at": str,
        "relevance": int,
        "feed_weight": int,
        "scraped_at": str,
        "word_count": int,
    }
"""

from __future__ import annotations

import asyncio
import aiohttp
import hashlib
import json
import logging
import os
import re
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from utils.content_safety import is_blocked_query, sanitize_content

logger = logging.getLogger(__name__)

CACHE_DIR = Path("/tmp/open_intel_rss_cache")
CACHE_TTL_SECONDS = 3600  # 1 hour

MAX_ARTICLE_AGE_DAYS = 90
MAX_ARTICLES_PER_FEED = 3
MAX_TOTAL_ARTICLES = 20
MAX_ARTICLE_SIZE = 100 * 1024  # 100 KB

RSS_FEEDS = [
    {
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/",
        "category": "journalism",
        "tags": ["breach", "fraud", "cybercrime", "ransomware", "dark web", "banking"],
        "weight": 10,
    },
    {
        "name": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/feed/",
        "category": "journalism",
        "tags": ["ransomware", "malware", "breach", "vulnerability", "darkweb", "leak"],
        "weight": 10,
    },
    {
        "name": "The Record by Recorded Future",
        "url": "https://therecord.media/feed",
        "category": "journalism",
        "tags": ["cybercrime", "espionage", "ransomware", "government", "critical infrastructure"],
        "weight": 9,
    },
    {
        "name": "Dark Reading",
        "url": "https://www.darkreading.com/rss.xml",
        "category": "journalism",
        "tags": ["vulnerability", "threat", "attack", "malware", "breach", "security"],
        "weight": 8,
    },
    {
        "name": "SecurityWeek",
        "url": "https://feeds.feedburner.com/Securityweek",
        "category": "journalism",
        "tags": ["vulnerability", "ransomware", "breach", "malware", "exploit"],
        "weight": 8,
    },
    {
        "name": "Threatpost",
        "url": "https://threatpost.com/feed/",
        "category": "journalism",
        "tags": ["vulnerability", "ransomware", "malware", "breach", "APT"],
        "weight": 7,
    },
    {
        "name": "SANS Internet Storm Center",
        "url": "https://isc.sans.edu/rssfeed_full.xml",
        "category": "technical",
        "tags": ["IOC", "malware", "exploit", "vulnerability", "incident"],
        "weight": 9,
    },
    {
        "name": "Malwarebytes Labs",
        "url": "https://www.malwarebytes.com/blog/feed/",
        "category": "technical",
        "tags": ["malware", "ransomware", "threat", "stealer", "trojan", "adware"],
        "weight": 8,
    },
    {
        "name": "Cisco Talos Intelligence",
        "url": "https://blog.talosintelligence.com/rss/",
        "category": "technical",
        "tags": ["malware", "IOC", "APT", "exploit", "vulnerability", "threat actor"],
        "weight": 10,
    },
    {
        "name": "Sophos News",
        "url": "https://news.sophos.com/en-us/feed/",
        "category": "technical",
        "tags": ["ransomware", "malware", "threat", "exploit", "attack"],
        "weight": 8,
    },
    {
        "name": "Mandiant Blog",
        "url": "https://www.mandiant.com/resources/blog/rss.xml",
        "category": "threat_intel",
        "tags": ["APT", "threat actor", "espionage", "malware", "incident response", "zero day"],
        "weight": 10,
    },
    {
        "name": "CrowdStrike Blog",
        "url": "https://www.crowdstrike.com/blog/feed/",
        "category": "threat_intel",
        "tags": ["APT", "threat actor", "ransomware", "malware", "eCrime", "adversary"],
        "weight": 10,
    },
    {
        "name": "Secureworks CTU",
        "url": "https://www.secureworks.com/rss?feed=blog",
        "category": "threat_intel",
        "tags": ["threat actor", "malware", "APT", "ransomware", "darkweb", "TTPs"],
        "weight": 9,
    },
    {
        "name": "US-CERT Alerts",
        "url": "https://www.cisa.gov/uscert/ncas/alerts.xml",
        "category": "government",
        "tags": ["vulnerability", "alert", "advisory", "critical infrastructure", "KEV"],
        "weight": 10,
    },
    {
        "name": "CISA News",
        "url": "https://www.cisa.gov/news.xml",
        "category": "government",
        "tags": ["vulnerability", "advisory", "ransomware", "critical infrastructure"],
        "weight": 9,
    },
    {
        "name": "FBI Cyber Division News",
        "url": "https://www.fbi.gov/feeds/fbi-in-the-news/rss.xml",
        "category": "government",
        "tags": ["cybercrime", "ransomware", "darkweb", "arrest", "seizure", "takedown"],
        "weight": 9,
    },
    {
        "name": "Recorded Future Intelligence",
        "url": "https://www.recordedfuture.com/feed",
        "category": "threat_intel",
        "tags": ["threat actor", "dark web", "IOC", "malware", "vulnerability", "APT"],
        "weight": 9,
    },
    {
        "name": "Palo Alto Unit 42",
        "url": "https://unit42.paloaltonetworks.com/feed/",
        "category": "threat_intel",
        "tags": ["malware", "APT", "threat actor", "ransomware", "phishing", "exploit"],
        "weight": 10,
    },
    {
        "name": "Microsoft Security Blog",
        "url": "https://www.microsoft.com/en-us/security/blog/feed/",
        "category": "threat_intel",
        "tags": ["APT", "ransomware", "vulnerability", "threat actor", "malware", "nation state"],
        "weight": 9,
    },
    {
        "name": "Google Project Zero",
        "url": "https://googleprojectzero.blogspot.com/feeds/posts/default",
        "category": "technical",
        "tags": ["zero day", "exploit", "vulnerability", "CVE", "browser", "kernel"],
        "weight": 9,
    },
]

_KNOWN_ACTORS = [
    "lockbit", "blackcat", "alphv", "cl0p", "clop", "play", "akira",
    "blackbasta", "black basta", "revil", "conti", "ryuk", "maze",
    "darkside", "hive", "ragnarlocker", "cobalt strike", "metasploit",
    "mimikatz", "beacon", "sliver", "havoc", "brute ratel", "covenant",
    "lazarus", "apt28", "apt29", "cozy bear", "fancy bear",
    "sandworm", "volt typhoon", "scattered spider", "lapsus",
]


class RSSCache:
    """Simple file-based cache for RSS feed article lists."""

    def __init__(self):
        CACHE_DIR.mkdir(parents=True, exist_ok=True)

    def _cache_path(self, url: str) -> Path:
        key = hashlib.md5(url.encode()).hexdigest()
        return CACHE_DIR / f"{key}.json"

    def get(self, url: str) -> Optional[list]:
        path = self._cache_path(url)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
            age = time.time() - data.get("cached_at", 0)
            if age > CACHE_TTL_SECONDS:
                path.unlink(missing_ok=True)
                return None
            return data.get("articles", [])
        except Exception:
            return None

    def set(self, url: str, articles: list) -> None:
        path = self._cache_path(url)
        try:
            path.write_text(json.dumps({
                "cached_at": time.time(),
                "articles": articles,
            }))
        except Exception as e:
            logger.debug("RSS cache write failed: %s", e)


class RSSFeedScraper:
    """Fetches and parses RSS/Atom feeds from curated threat intelligence sources."""

    def __init__(self):
        self._session: Optional[aiohttp.ClientSession] = None
        self._cache = RSSCache()

    async def __aenter__(self):
        self._session = aiohttp.ClientSession(
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; RSS-Reader/1.0; +https://github.com/Open_Intel/Open_Intel)",
                "Accept": (
                    "application/rss+xml, application/atom+xml, "
                    "application/xml, text/xml"
                ),
            },
            timeout=aiohttp.ClientTimeout(total=15),
        )
        return self

    async def __aexit__(self, *args):
        if self._session:
            await self._session.close()

    async def fetch_relevant_articles(
        self,
        query: str,
        refined_query: str = "",
        max_results: int = MAX_TOTAL_ARTICLES,
    ) -> list[dict]:
        """
        Fetch articles from all feeds relevant to the query.
        Returns page dicts compatible with the extraction pipeline.
        """
        blocked, _ = is_blocked_query(query)
        if blocked:
            logger.warning("RSS scraping blocked — prohibited query")
            return []

        search_terms = self._extract_search_terms(query, refined_query)

        logger.info(
            "RSS feeds: fetching for '%s' (%d feeds)",
            query[:50],
            len(RSS_FEEDS),
        )

        tasks = [self._fetch_feed(feed, search_terms) for feed in RSS_FEEDS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_articles: list[dict] = []
        seen_urls: set[str] = set()

        for result in results:
            if isinstance(result, list):
                for article in result:
                    url = article.get("url", "")
                    if url and url not in seen_urls:
                        seen_urls.add(url)
                        all_articles.append(article)

        all_articles.sort(
            key=lambda x: x.get("relevance", 0) * x.get("feed_weight", 1),
            reverse=True,
        )

        final = all_articles[:max_results]
        logger.info("RSS feeds: %d relevant articles found", len(final))
        return final

    def _extract_search_terms(self, query: str, refined_query: str) -> list[str]:
        """Extract key terms for relevance matching."""
        text = f"{query} {refined_query}".lower()
        words = [w for w in re.split(r"\W+", text) if len(w) > 3]
        terms = list(set(words))

        terms.append(query.lower())
        if refined_query:
            terms.append(refined_query.lower())

        cves = re.findall(r"CVE-\d{4}-\d+", query, re.IGNORECASE)
        terms.extend(c.lower() for c in cves)

        for actor in _KNOWN_ACTORS:
            if actor in text:
                terms.append(actor)

        return list(set(terms))

    async def _fetch_feed(self, feed: dict, search_terms: list[str]) -> list[dict]:
        """Fetch one RSS feed and return relevant articles."""
        feed_url = feed["url"]
        feed_name = feed["name"]

        cached = self._cache.get(feed_url)
        if cached is not None:
            logger.debug("RSS cache hit: %s", feed_name)
            raw_articles = cached
        else:
            raw_articles = await self._fetch_and_parse(feed_url, feed_name)
            if raw_articles:
                self._cache.set(feed_url, raw_articles)

        if not raw_articles:
            return []

        relevant: list[dict] = []
        for article in raw_articles:
            relevance = self._score_article(article, search_terms, feed)
            if relevance <= 0:
                continue

            full_content = await self._fetch_article_content(article.get("url", ""))
            content = full_content or article.get("summary", "")

            if not content or len(content.strip()) < 100:
                continue

            clean, flagged = sanitize_content(content)
            if flagged or not clean:
                continue

            relevant.append({
                "url": article.get("url", ""),
                "text_content": clean,
                "title": article.get("title", feed_name),
                "source_type": "rss_feed",
                "source_name": feed_name,
                "feed_category": feed.get("category", "unknown"),
                "published_at": article.get("published", ""),
                "relevance": relevance,
                "feed_weight": feed.get("weight", 5),
                "scraped_at": datetime.now(timezone.utc).isoformat(),
                "word_count": len(clean.split()),
            })

            if len(relevant) >= MAX_ARTICLES_PER_FEED:
                break

        return relevant

    async def _fetch_and_parse(self, feed_url: str, feed_name: str) -> list[dict]:
        """Fetch and parse an RSS/Atom feed XML."""
        if not self._session:
            return []
        try:
            async with self._session.get(feed_url, allow_redirects=True) as resp:
                if resp.status != 200:
                    return []
                content = await resp.text(encoding="utf-8", errors="ignore")
            return self._parse_feed(content, feed_url)
        except asyncio.TimeoutError:
            logger.debug("RSS timeout: %s", feed_name)
            return []
        except Exception as e:
            logger.debug("RSS fetch error %s: %s", feed_name, e)
            return []

    def _parse_feed(self, content: str, feed_url: str) -> list[dict]:
        """
        Parse RSS 2.0 or Atom feed XML.
        Returns list of article dicts: title, url, summary, published.
        """
        articles: list[dict] = []
        try:
            # Strip namespace declarations and prefixes so ET can parse any RSS/Atom
            content = re.sub(r'\s+xmlns(?::[a-zA-Z0-9_]+)?="[^"]*"', "", content)
            def _strip_ns(m: re.Match) -> str:
                slash, ns, tag = m.group(1), m.group(2), m.group(3)
                if ns.lower() == "http":
                    return m.group(0)
                return f"<{slash}{ns}_{tag}"
            content = re.sub(r"<(/?)([a-zA-Z][a-zA-Z0-9_]*):([a-zA-Z][a-zA-Z0-9_]*)", _strip_ns, content)

            root = ET.fromstring(content)
            is_atom = "feed" in root.tag.lower()

            if is_atom:
                for entry in root.findall("entry")[:20]:
                    url = ""
                    for link in entry.findall("link"):
                        if link.get("rel") in ("alternate", None):
                            url = link.get("href", "")
                            break
                    title_el = entry.find("title")
                    summary_el = entry.find("summary") or entry.find("content")
                    pub_el = entry.find("published") or entry.find("updated")
                    if url:
                        articles.append({
                            "url": url,
                            "title": (title_el.text or "") if title_el else "",
                            "summary": (summary_el.text or "") if summary_el else "",
                            "published": (pub_el.text or "") if pub_el else "",
                        })
            else:
                channel = root.find("channel") or root
                for item in channel.findall("item")[:20]:
                    link_el = item.find("link")
                    title_el = item.find("title")
                    desc_el = item.find("description")
                    pub_el = item.find("pubDate")
                    url = (link_el.text or "").strip() if link_el is not None else ""
                    if url:
                        articles.append({
                            "url": url,
                            "title": (title_el.text or "") if title_el else "",
                            "summary": self._strip_html(
                                (desc_el.text or "") if desc_el else ""
                            ),
                            "published": (pub_el.text or "") if pub_el else "",
                        })

        except ET.ParseError as e:
            logger.debug("RSS parse error %s: %s", feed_url, e)
        except Exception as e:
            logger.debug("RSS parse unexpected error: %s", e)

        return articles

    async def _fetch_article_content(self, url: str) -> Optional[str]:
        """Fetch and extract plain text from an article URL."""
        if not url or not self._session:
            return None
        try:
            async with self._session.get(
                url,
                allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status != 200:
                    return None
                html = await resp.text(encoding="utf-8", errors="ignore")
                if len(html) > MAX_ARTICLE_SIZE:
                    html = html[:MAX_ARTICLE_SIZE]
                text = self._extract_article_text(html)
                return text if len(text) > 100 else None
        except Exception:
            return None

    def _extract_article_text(self, html: str) -> str:
        """Strip scripts, styles, and tags; collapse whitespace."""
        html = re.sub(r"<script[^>]*>.*?</script>", " ", html, flags=re.DOTALL)
        html = re.sub(r"<style[^>]*>.*?</style>", " ", html, flags=re.DOTALL)
        text = re.sub(r"<[^>]+>", " ", html)
        for entity, char in {
            "&amp;": "&", "&lt;": "<", "&gt;": ">",
            "&quot;": '"', "&#39;": "'", "&nbsp;": " ", "&apos;": "'",
        }.items():
            text = text.replace(entity, char)
        return re.sub(r"\s+", " ", text).strip()

    def _strip_html(self, html: str) -> str:
        """Strip HTML tags from a string."""
        text = re.sub(r"<[^>]+>", " ", html)
        return re.sub(r"\s+", " ", text).strip()

    def _score_article(
        self,
        article: dict,
        search_terms: list[str],
        feed: dict,
    ) -> int:
        """Score article relevance to search terms (0 = exclude)."""
        score = 0

        title = article.get("title", "").lower()
        summary = article.get("summary", "").lower()

        pub_str = article.get("published", "")
        if pub_str:
            try:
                from email.utils import parsedate_to_datetime
                try:
                    pub_dt = parsedate_to_datetime(pub_str)
                except Exception:
                    import dateutil.parser
                    pub_dt = dateutil.parser.parse(pub_str)

                now = datetime.now(timezone.utc)
                if pub_dt.tzinfo is None:
                    pub_dt = pub_dt.replace(tzinfo=timezone.utc)

                age_days = (now - pub_dt).days
                if age_days > MAX_ARTICLE_AGE_DAYS:
                    return 0
                elif age_days <= 7:
                    score += 5
                elif age_days <= 30:
                    score += 3
                else:
                    score += 1
            except Exception:
                score += 1

        for term in search_terms:
            if len(term) > 3:
                if term in title:
                    score += 5
                elif term in summary:
                    score += 2

        feed_tags = [t.lower() for t in feed.get("tags", [])]
        for term in search_terms:
            if term in feed_tags:
                score += 1

        return score


async def scrape_rss_feeds(
    query: str,
    refined_query: str = "",
    max_results: int = MAX_TOTAL_ARTICLES,
) -> list[dict]:
    """
    Main entry point.  Returns page dicts compatible with the extraction pipeline.
    Opt-out via RSS_FEEDS_ENABLED=false.
    """
    if os.getenv("RSS_FEEDS_ENABLED", "true").lower() != "true":
        logger.info("RSS feeds disabled")
        return []

    async with RSSFeedScraper() as scraper:
        return await scraper.fetch_relevant_articles(
            query=query,
            refined_query=refined_query,
            max_results=max_results,
        )
