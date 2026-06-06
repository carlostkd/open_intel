"""
crawler/dedup.py — Two-level deduplication for the .onion crawler.

Level 1 — URL dedup:
    In-memory set; never visits the same normalized URL twice within a run.

Level 2 — Content dedup:
    SHA-256 of extracted text is checked against the pages table before a DB
    write.  If the hash already exists the write is skipped, but the URL is
    still counted as visited (content was seen elsewhere — no need to store it
    again, but crawling this URL was not wasted work).
"""

from __future__ import annotations

import hashlib
import logging
from typing import Optional

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Level 1 — URL deduplication
# ---------------------------------------------------------------------------

class UrlDedup:
    """
    In-memory URL deduplication scoped to a single crawl run.

    Thread-safety: designed for asyncio (single-threaded event loop).
    All operations are synchronous and O(1).
    """

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def is_new(self, url: str) -> bool:
        """Return True if *url* has not been seen in this run."""
        return url not in self._seen

    def mark_seen(self, url: str) -> None:
        """Mark *url* as seen so future is_new() calls return False."""
        self._seen.add(url)

    def __len__(self) -> int:
        return len(self._seen)


# ---------------------------------------------------------------------------
# Level 2 — Content deduplication
# ---------------------------------------------------------------------------

class ContentDedup:
    """
    Content-hash deduplication backed by the database pages table.

    Uses SHA-256 of raw download bytes (same convention as scrape.py's
    _persist_pages so hashes are consistent across both pipelines).

    Falls back to "not a duplicate" when DATABASE_URL is not set or the DB
    is unreachable — this keeps the crawler running even without a database.
    """

    @staticmethod
    def hash_bytes(data: bytes) -> str:
        """Return SHA-256 hex digest of raw bytes."""
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def hash_text(text: str) -> str:
        """Return SHA-256 hex digest of text (UTF-8 encoded)."""
        return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()

    @staticmethod
    def is_duplicate(content_hash: str, db_url: Optional[str] = None) -> bool:
        """
        Return True if *content_hash* already exists in the pages table.

        *db_url* overrides DATABASE_URL — used in tests to point at the
        test SQLite database without modifying the real config.

        Any exception (DB unreachable, import error, etc.) is silently
        swallowed and returns False so the crawler never crashes on dedup.
        """
        try:
            from config import DATABASE_URL as _cfg_db_url
            target = db_url or _cfg_db_url
            if not target:
                return False
            from db.queries import get_page_by_hash
            from db.session import get_session
            with get_session(target) as session:
                return get_page_by_hash(session, content_hash) is not None
        except Exception as exc:
            _logger.debug("ContentDedup DB check failed: %s", exc)
            return False
