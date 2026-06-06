"""
sources — Phase 1D expanded source coverage + threat intelligence enrichment.

Public API:
    collect_all_sources(query, ...)  async  — unified aggregator
    enrich_investigation(query, otx_api_key)  async  — threat intel enrichment

Sub-modules:
    engines.py     — DarkSearch JSON API + OnionSearch HTML scraping
    seeds.py       — curated .onion seed URL list
    pastes.py      — .onion paste site monitor
    telegram.py    — Telegram public channel monitor (clearnet, optional)
    enrichment.py  — AlienVault OTX + Abuse.ch threat intelligence
"""

from __future__ import annotations

import asyncio
import logging
from typing import Dict, List, Optional

from sources.enrichment import enrich_investigation

_logger = logging.getLogger(__name__)

__all__ = ["collect_all_sources", "enrich_investigation"]


async def collect_all_sources(
    query: str,
    include_telegram: bool = False,
    telegram_channels: Optional[List[str]] = None,
    seed_categories: Optional[List[str]] = None,
) -> Dict:
    """
    Aggregate all Phase 1D intelligence sources for *query*.

    Search engines (DarkSearch + OnionSearch) and the paste monitor run
    concurrently via asyncio.gather().  Telegram runs separately, and only
    when *include_telegram=True* and credentials exist.

    Args:
        query:             investigation query string.
        include_telegram:  if True, also fetch matching Telegram messages.
        telegram_channels: list of channel usernames to monitor; ignored when
                           include_telegram=False.
        seed_categories:   list of seed categories to include (e.g. ["forum",
                           "index"]); None returns all categories.

    Returns dict with keys:
        "search_results"   list[dict]  — from DarkSearch + OnionSearch
        "paste_results"    list[dict]  — from paste site monitor
        "telegram_results" list[dict]  — from Telegram (empty if skipped)
        "seed_urls"        list[dict]  — from seeds.py (for crawler to consume)
    """
    from sources.engines import search_darksearch, search_onionsearch
    from sources.pastes import fetch_recent_pastes
    from sources.seeds import get_seeds

    # --- Search + pastes run concurrently -----------------------------------
    (darksearch_results, onionsearch_results), paste_results = await asyncio.gather(
        asyncio.gather(
            search_darksearch(query),
            search_onionsearch(query),
        ),
        fetch_recent_pastes(query),
    )
    search_results: List[dict] = darksearch_results + onionsearch_results

    # --- Telegram (optional, sequential after gather) -----------------------
    telegram_results: List[dict] = []
    if include_telegram:
        from sources.telegram import fetch_telegram_messages
        telegram_results = await fetch_telegram_messages(
            channel_usernames=telegram_channels or [],
            query=query,
        )

    # --- IntelX (clearnet, optional) ---------------------------------------
    intelx_pages: list[dict] = []
    try:
        from sources.intelx_scraper import scrape_intelx
        intelx_pages = await scrape_intelx(query)
    except Exception as exc:
        logger.debug("IntelX skipped: %s", exc)

    # --- Seeds (synchronous) ------------------------------------------------
    if seed_categories:
        seen_urls: set[str] = set()
        seeds: List[dict] = []
        for cat in seed_categories:
            for s in get_seeds(category=cat):
                if s["url"] not in seen_urls:
                    seen_urls.add(s["url"])
                    seeds.append(s)
    else:
        seeds = get_seeds()

    return {
        "search_results": search_results,
        "paste_results": paste_results,
        "telegram_results": telegram_results,
        "intelx_results": intelx_pages,
        "seed_urls": seeds,
    }
