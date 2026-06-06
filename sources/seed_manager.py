"""
sources/seed_manager.py — Curated .onion seed list manager.

Maintains a JSON-backed catalogue of known-active dark-web addresses
organized by category (ransomware leak sites, hacker forums, carding shops,
search engines, etc.).

At investigation time, get_relevant_seeds(query) scores each seed against
the user query using tag and name matching, and returns the top-N most
relevant entries.  Those seed URLs are injected into the scrape queue
ahead of the search-engine fan-out so that known intelligence sources are
always visited for an applicable query.

The seed JSON lives at data/onion_seeds.json and is community-editable.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import aiohttp
import aiohttp_socks

from utils.content_safety import is_blocked_url

logger = logging.getLogger(__name__)

# The seed file lives in open_intel/data/onion_seeds.json (sibling of sources/)
SEED_FILE = Path(__file__).resolve().parent.parent / "data" / "onion_seeds.json"
TOR_PROXY = "socks5://127.0.0.1:9050"


class SeedManager:
    """
    Manages the curated .onion seed list.
    Provides relevance matching and availability checking.
    """

    def __init__(self) -> None:
        self._seeds: list[dict] = []
        self._loaded: bool = False

    def load(self) -> None:
        """Load seeds from JSON file."""
        if not SEED_FILE.exists():
            logger.warning("Seed file not found: %s", SEED_FILE)
            self._seeds = []
            self._loaded = True
            return

        try:
            data = json.loads(SEED_FILE.read_text(encoding="utf-8"))
            self._seeds = []

            for category, cat_data in data.get("categories", {}).items():
                for seed in cat_data.get("seeds", []):
                    self._seeds.append({
                        **seed,
                        "category": category,
                        "category_tags": cat_data.get("tags", []),
                    })

            logger.info(
                "Loaded %d seeds from %s",
                len(self._seeds),
                SEED_FILE,
            )
            self._loaded = True

        except Exception as e:
            logger.error("Failed to load seeds: %s", e)
            self._seeds = []
            self._loaded = True

    def get_relevant_seeds(
        self,
        query: str,
        refined_query: str = "",
        max_seeds: int = 10,
    ) -> list[dict]:
        """
        Return seeds relevant to a query.
        Uses tag matching and keyword scoring.
        """
        if not self._loaded:
            self.load()

        if not self._seeds:
            return []

        search_text = f"{query} {refined_query}".lower()

        scored: list[tuple[int, dict]] = []
        for seed in self._seeds:
            # Skip content-safety blocked URLs
            blocked, _ = is_blocked_url(seed.get("url", ""))
            if blocked:
                continue

            score = 0
            all_tags = list(seed.get("tags", [])) + list(seed.get("category_tags", []))

            # Score by tag matches
            for tag in all_tags:
                if tag.lower() in search_text:
                    score += 3

            # Score by name match (only words longer than 3 chars)
            name = seed.get("name", "").lower()
            for word in search_text.split():
                if len(word) > 3 and word in name:
                    score += 2

            # Boost known-active seeds
            if seed.get("status") == "active":
                score += 1

            # Always include search engines with a base score so generic
            # queries still get a directory to crawl.
            category = seed.get("category", "")
            if "search" in category or "search" in [t.lower() for t in all_tags]:
                score = max(score, 1)

            if score > 0:
                scored.append((score, seed))

        scored.sort(key=lambda x: x[0], reverse=True)
        results = [s for _, s in scored[:max_seeds]]

        logger.info(
            "Seed matching: %d relevant seeds for query '%s'",
            len(results),
            query[:50],
        )

        return results

    async def check_seed_availability(
        self,
        url: str,
        timeout: int = 15,
    ) -> bool:
        """
        Check if a seed URL is reachable over Tor.
        Returns True if reachable, False otherwise.
        """
        try:
            connector = aiohttp_socks.ProxyConnector.from_url(TOR_PROXY)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    headers={"User-Agent": "Mozilla/5.0 (compatible)"},
                    ssl=False,
                ) as resp:
                    return resp.status < 500
        except Exception:
            return False

    async def validate_seeds(self, concurrency: int = 5) -> dict:
        """
        Check which seeds are currently reachable.
        Updates status in the JSON file.
        Returns summary of results.
        """
        if not self._loaded:
            self.load()

        if not self._seeds:
            return {"checked": 0, "active": 0, "dead": 0}

        sem = asyncio.Semaphore(concurrency)
        results = {"active": 0, "dead": 0, "checked": 0}

        async def check_one(seed: dict) -> None:
            async with sem:
                url = seed.get("url", "")
                if not url:
                    return

                is_up = await self.check_seed_availability(url)

                results["checked"] += 1
                if is_up:
                    results["active"] += 1
                    seed["status"] = "active"
                    seed["last_seen"] = datetime.now(timezone.utc).isoformat()
                else:
                    results["dead"] += 1
                    seed["status"] = "unreachable"

                logger.debug(
                    "Seed %s %s",
                    "ok" if is_up else "down",
                    seed.get("name", url[:30]),
                )

        await asyncio.gather(*[check_one(s) for s in self._seeds])

        # Persist status updates back to disk
        self._save_status_updates()

        logger.info(
            "Seed validation: %d/%d active",
            results["active"],
            results["checked"],
        )

        return results

    def add_discovered_seed(
        self,
        url: str,
        name: str,
        tags: list[str],
        category: str = "discovered",
    ) -> bool:
        """
        Add a newly discovered onion URL to seeds.
        Called by the pipeline when new onions are found.
        Returns True if added, False if duplicate or blocked.
        """
        if not self._loaded:
            self.load()

        existing_urls = {s.get("url") for s in self._seeds}
        if url in existing_urls:
            return False

        blocked, _ = is_blocked_url(url)
        if blocked:
            return False

        new_seed = {
            "name": name,
            "url": url,
            "tags": list(tags),
            "category": category,
            "category_tags": [category],
            "status": "discovered",
            "added": datetime.now(timezone.utc).date().isoformat(),
        }

        self._seeds.append(new_seed)
        self._save()

        logger.info("Added new seed: %s", url[:50])
        return True

    def summary(self) -> dict:
        """Return counts grouped by category and status."""
        if not self._loaded:
            self.load()

        by_category: dict[str, int] = {}
        by_status: dict[str, int] = {}
        last_validated: Optional[str] = None

        for seed in self._seeds:
            cat = seed.get("category", "unknown")
            by_category[cat] = by_category.get(cat, 0) + 1
            status = seed.get("status", "unknown")
            by_status[status] = by_status.get(status, 0) + 1
            seen = seed.get("last_seen")
            if seen and (last_validated is None or seen > last_validated):
                last_validated = seen

        return {
            "total": len(self._seeds),
            "by_category": by_category,
            "by_status": by_status,
            "last_validated": last_validated,
        }

    def list_seeds(self) -> list[dict]:
        """Return a snapshot of every seed (admin view)."""
        if not self._loaded:
            self.load()
        return [dict(s) for s in self._seeds]

    def _load_raw(self) -> dict:
        """Load the on-disk file structure (preserving category metadata)."""
        if SEED_FILE.exists():
            try:
                return json.loads(SEED_FILE.read_text(encoding="utf-8"))
            except Exception as e:
                logger.warning("Could not parse existing seed file: %s", e)
        return {
            "version": "1.0.0",
            "last_updated": datetime.now(timezone.utc).date().isoformat(),
            "description": "Curated list of known dark web addresses for Open_Intel intelligence seeding",
            "categories": {},
        }

    def _save_status_updates(self) -> None:
        """Persist status/last_seen changes for known seeds back to disk."""
        try:
            data = self._load_raw()
            categories = data.setdefault("categories", {})

            # Build a (category, url) → in-memory seed map
            updates = {(s.get("category"), s.get("url")): s for s in self._seeds}

            for cat_name, cat_data in categories.items():
                for seed in cat_data.get("seeds", []):
                    key = (cat_name, seed.get("url"))
                    in_mem = updates.get(key)
                    if in_mem is None:
                        continue
                    if "status" in in_mem:
                        seed["status"] = in_mem["status"]
                    if "last_seen" in in_mem:
                        seed["last_seen"] = in_mem["last_seen"]

            data["last_updated"] = datetime.now(timezone.utc).date().isoformat()
            SEED_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as e:
            logger.error("Failed to save seed status updates: %s", e)

    def _save(self) -> None:
        """Save current seeds (including discovered ones) back to JSON."""
        try:
            data = self._load_raw()
            categories = data.setdefault("categories", {})

            # Add discovered seeds to their category bucket
            discovered = [s for s in self._seeds if s.get("category") == "discovered"]
            if discovered:
                bucket = categories.setdefault(
                    "discovered",
                    {
                        "description": "Auto-discovered during investigations",
                        "tags": ["discovered"],
                        "seeds": [],
                    },
                )
                existing_urls = {s["url"] for s in bucket.get("seeds", [])}
                for s in discovered:
                    if s["url"] not in existing_urls:
                        bucket["seeds"].append({
                            "name": s["name"],
                            "url": s["url"],
                            "tags": s["tags"],
                            "status": s["status"],
                            "added": s["added"],
                        })
                        existing_urls.add(s["url"])

            data["last_updated"] = datetime.now(timezone.utc).date().isoformat()
            SEED_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as e:
            logger.error("Failed to save seeds: %s", e)


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------

_seed_manager: Optional[SeedManager] = None


def get_seed_manager() -> SeedManager:
    """Return the process-wide SeedManager, loading on first access."""
    global _seed_manager
    if _seed_manager is None:
        _seed_manager = SeedManager()
        _seed_manager.load()
    return _seed_manager
