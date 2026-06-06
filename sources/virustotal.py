"""
sources/virustotal.py — VirusTotal hash enrichment (file hash lookup).

Requires VT_API_KEY in config. Free tier: 4 requests/minute.
Max 20 hashes per investigation.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

import aiohttp

from config import VT_API_KEY

logger = logging.getLogger(__name__)

_VT_BASE = "https://www.virustotal.com/api/v3"
_VT_HASH_LIMIT = 20
_VT_RATE_LIMIT_DELAY = 15.0


def _is_enabled() -> bool:
    key = getattr(VT_API_KEY, "strip", lambda: "")()
    return bool(key)


async def _fetch_hash(hash_value: str, session: aiohttp.ClientSession) -> Optional[dict]:
    try:
        headers = {"x-apikey": VT_API_KEY.strip()}
        timeout = aiohttp.ClientTimeout(total=15)
        async with session.get(
            f"{_VT_BASE}/files/{hash_value}", headers=headers, timeout=timeout
        ) as resp:
            if resp.status == 404:
                return None
            if resp.status == 401:
                logger.warning("VirusTotal: invalid API key")
                return None
            if resp.status == 429:
                logger.warning("VirusTotal: rate limited")
                return None
            if resp.status != 200:
                return None
            return await resp.json()
    except asyncio.TimeoutError:
        logger.warning("VirusTotal: timeout for hash %s", hash_value[:16])
        return None
    except Exception as e:
        logger.warning("VirusTotal: error for hash %s: %s", hash_value[:16], e)
        return None


async def enrich_virustotal(entities: list[dict]) -> list[dict]:
    """
    For each FILE_HASH_MD5 / FILE_HASH_SHA1 / FILE_HASH_SHA256 entity,
    query VirusTotal and return detection stats.
    """
    if not _is_enabled():
        logger.debug("VirusTotal skipped — no API key configured")
        return []

    hash_type_map = {
        "FILE_HASH_MD5": "md5",
        "FILE_HASH_SHA1": "sha1",
        "FILE_HASH_SHA256": "sha256",
    }

    hash_entities = [
        e for e in entities
        if (e.get("type") or e.get("entity_type", "")) in hash_type_map
        and (e.get("value") or e.get("entity_value", ""))
    ]

    hashes_to_query = [
        (e.get("value") or e.get("entity_value", ""), (e.get("type") or e.get("entity_type", "")))
        for e in hash_entities
    ][:_VT_HASH_LIMIT]

    results: list[dict] = []
    async with aiohttp.ClientSession() as session:
        for hash_val, hash_type in hashes_to_query:
            data = await _fetch_hash(hash_val, session)
            if data is None:
                await asyncio.sleep(_VT_RATE_LIMIT_DELAY)
                continue

            attr = data.get("data", {}).get("attributes", {})
            stats = attr.get("last_analysis_stats", {})
            mal = stats.get("malicious", 0)
            total = sum(stats.values())
            detection_ratio = mal / total if total > 0 else 0.0

            results.append({
                "source": "virustotal",
                "entity_type": hash_type_map.get(hash_type, "FILE_HASH"),
                "entity_value": hash_val,
                "malicious_count": mal,
                "total_engines": total,
                "detection_ratio": detection_ratio,
                "suggested_threat_label": attr.get("popular_threat_classification", {}).get("suggested_threat_label", ""),
                "first_seen": attr.get("creation_date", ""),
                "last_seen": attr.get("last_analysis_date", ""),
                "confirmed_malicious": detection_ratio > 0.5,
            })

            await asyncio.sleep(_VT_RATE_LIMIT_DELAY)

    if results:
        logger.info("VirusTotal: %d results", len(results))
    return results
