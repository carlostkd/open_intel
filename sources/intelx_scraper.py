from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timezone
from typing import Any, Optional

import aiohttp

from utils.content_safety import is_blocked_query, sanitize_content

logger = logging.getLogger(__name__)

INTELX_BASE = "https://free.intelx.io"
INTELX_SEARCH_URL = f"{INTELX_BASE}/intelligent/search"
INTELX_RESULT_URL = f"{INTELX_BASE}/intelligent/search/result"

MAX_RESULTS_TOTAL = 50
POLL_INTERVAL = 1.5
MAX_POLL_ATTEMPTS = 40
SEARCH_TIMEOUT = 20
MAX_RESULT_TEXT_LENGTH = 5000

OSINT_BUCKETS = [
    "darknet.tor",
    "darknet.i2p",
    "pastes",
    "leaks.public.general",
    "dumpster",
    "leaks.private",
]

HEADERS = {
    "User-Agent": "Open_Intel-OSINT/1.1",
    "Accept": "application/json",
}


def _creds_available() -> bool:
    key = (os.getenv("INTELX_API_KEY") or "").strip()
    user = (os.getenv("INTELX_USER") or "").strip()
    return bool(key) and bool(user)


def _auth_headers() -> dict[str, str]:
    h = dict(HEADERS)
    key = (os.getenv("INTELX_API_KEY") or "").strip()
    user = (os.getenv("INTELX_USER") or "").strip()
    if key:
        h["x-key"] = key
    if user:
        h["x-user"] = user
    return h


def _build_search_body(query: str) -> dict[str, Any]:
    return {
        "term": query,
        "buckets": OSINT_BUCKETS,
        "lookuplevel": 0,
        "maxresults": MAX_RESULTS_TOTAL,
        "timeout": SEARCH_TIMEOUT,
        "datefrom": "",
        "dateto": "",
        "sort": 2,
        "media": 0,
        "terminate": [],
    }


class IntelXScraper:
    def __init__(self) -> None:
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self) -> "IntelXScraper":
        self._session = aiohttp.ClientSession(
            headers=_auth_headers(),
            timeout=aiohttp.ClientTimeout(total=60),
        )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    async def search_and_fetch(
        self,
        query: str,
        refined_query: str = "",
        max_results: int = MAX_RESULTS_TOTAL,
    ) -> list[dict]:
        blocked, _ = is_blocked_query(query)
        if blocked:
            logger.warning("IntelX scraping blocked — prohibited query")
            return []

        if not _creds_available():
            logger.info("IntelX credentials not configured — skipping")
            return []

        search_term = (refined_query or query).strip()[:200]
        logger.info("IntelX search: '%s'", search_term[:60])

        search_id = await self._start_search(search_term)
        if not search_id:
            return []

        records = await self._poll_results(search_id)
        results = self._parse_records(records, search_term)

        final = results[:max_results]
        logger.info("IntelX: %d results", len(final))
        return final

    async def _start_search(self, term: str) -> Optional[str]:
        if not self._session:
            return None
        body = _build_search_body(term)
        try:
            async with self._session.post(
                INTELX_SEARCH_URL, json=body
            ) as resp:
                if resp.status == 401:
                    logger.warning("IntelX: invalid API key or user")
                    return None
                if resp.status == 402:
                    logger.warning("IntelX: no credits available")
                    return None
                if resp.status != 200:
                    logger.debug("IntelX search POST returned %d", resp.status)
                    return None
                data = await resp.json()
                search_id = data.get("id") or data.get("uuid") or ""
                if not search_id:
                    return None
                status = data.get("status", "")
                logger.debug("IntelX search started: id=%s status=%s", search_id, status)
                return str(search_id)
        except asyncio.TimeoutError:
            logger.debug("IntelX search POST timed out")
            return None
        except Exception as exc:
            logger.debug("IntelX search POST error: %s", exc)
            return None

    async def _poll_results(self, search_id: str) -> list[dict]:
        if not self._session:
            return []
        for attempt in range(1, MAX_POLL_ATTEMPTS + 1):
            try:
                params = {"id": search_id, "limit": MAX_RESULTS_TOTAL, "offset": 0}
                async with self._session.get(
                    INTELX_RESULT_URL, params=params
                ) as resp:
                    if resp.status == 204:
                        await asyncio.sleep(POLL_INTERVAL)
                        continue
                    if resp.status != 200:
                        logger.debug(
                            "IntelX poll attempt %d: %d", attempt, resp.status
                        )
                        await asyncio.sleep(POLL_INTERVAL)
                        continue

                    data = await resp.json()
                    status = (data.get("status") or "").lower()

                    records = data.get("records") or data.get("selectors") or []
                    if status in ("query_complete", "no_results"):
                        return records

                    await asyncio.sleep(POLL_INTERVAL)
            except asyncio.TimeoutError:
                logger.debug("IntelX poll attempt %d timed out", attempt)
                await asyncio.sleep(POLL_INTERVAL)
            except Exception as exc:
                logger.debug("IntelX poll error: %s", exc)
                await asyncio.sleep(POLL_INTERVAL)
        logger.debug("IntelX poll exhausted after %d attempts", MAX_POLL_ATTEMPTS)
        return []

    def _parse_records(
        self, records: list[dict], search_term: str
    ) -> list[dict]:
        results: list[dict] = []
        seen: set[str] = set()

        for rec in records:
            name = (rec.get("name") or rec.get("selector") or "").strip()
            bucket = (rec.get("bucket") or "").strip()
            date_str = (rec.get("date") or rec.get("added") or "").strip()
            system_id = (rec.get("systemid") or "").strip()

            url = name
            dedup_key = system_id or url
            if not dedup_key or dedup_key in seen:
                continue
            seen.add(dedup_key)

            content_parts = [name]
            if bucket:
                content_parts.append(f"Bucket: {bucket}")
            if date_str:
                content_parts.append(f"Date: {date_str}")

            kvs = rec.get("keyvalues") or []
            for kv in kvs:
                k = (kv.get("key") or "").strip()
                v = (kv.get("value") or "").strip()
                if k and v:
                    content_parts.append(f"{k}: {v}")

            text_content = " | ".join(content_parts)
            if len(text_content) > MAX_RESULT_TEXT_LENGTH:
                text_content = text_content[:MAX_RESULT_TEXT_LENGTH]

            clean, flagged = sanitize_content(text_content)
            if flagged:
                continue

            if not clean or len(clean.strip()) < 20:
                continue

            relevance = 0
            search_lower = search_term.lower()
            if search_lower in clean.lower():
                relevance += 10
            if bucket in ("darknet.tor", "darknet.i2p"):
                relevance += 3

            title = f"IntelX — {bucket}: {name[:80]}"

            results.append({
                "url": url,
                "text_content": clean,
                "title": title,
                "source_type": "intelx",
                "source_name": "IntelX",
                "intelx_bucket": bucket,
                "intelx_system_id": system_id,
                "intelx_date": date_str,
                "scraped_at": datetime.now(timezone.utc).isoformat(),
                "word_count": len(clean.split()),
                "relevance": relevance,
            })

        results.sort(key=lambda x: x.get("relevance", 0), reverse=True)
        return results


async def scrape_intelx(
    query: str,
    refined_query: str = "",
    max_results: int = MAX_RESULTS_TOTAL,
) -> list[dict]:
    if not _creds_available():
        logger.info("IntelX disabled — INTELX_API_KEY or INTELX_USER not set")
        return []

    async with IntelXScraper() as scraper:
        return await scraper.search_and_fetch(
            query=query,
            refined_query=refined_query,
            max_results=max_results,
        )
