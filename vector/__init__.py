"""
vector — Phase 4 embedding storage and semantic search.

Re-exports the public API from embedder, store, and search.
"""

from vector.embedder import embed_batch, embed_text, get_embedder
from vector.search import (
    cross_investigation_recall,
    find_pages_similar_to,
    find_related_pages,
)
from vector.store import (
    bulk_check_cache,
    get_cached_page,
    get_collection,
    get_collection_stats,
    is_duplicate,
    search_similar,
    store_page,
    upsert_page,
)

__all__ = [
    "get_embedder",
    "embed_text",
    "embed_batch",
    "get_collection",
    "upsert_page",
    "search_similar",
    "is_duplicate",
    "get_collection_stats",
    "find_related_pages",
    "find_pages_similar_to",
    "cross_investigation_recall",
    "get_cached_page",
    "store_page",
    "bulk_check_cache",
]
