"""
extractor — Phase 2 entity extraction pipeline.

Public exports
--------------
ExtractionResult               — dataclass returned by extraction functions
extract_entities_from_page     — extract entities from a single page (async)
extract_entities_from_pages    — extract entities from multiple pages concurrently (async)
"""

from extractor.pipeline import (
    ExtractionResult,
    extract_entities_from_page,
    extract_entities_from_pages,
)

__all__ = [
    "ExtractionResult",
    "extract_entities_from_page",
    "extract_entities_from_pages",
]
