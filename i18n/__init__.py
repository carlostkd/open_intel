"""
i18n — Multilingual intelligence: language detection, translation pipeline,
and query expansion for broader dark web coverage.

Public interface
---------------
from i18n.detect       import detect_language, detect_language_batch, is_non_english
from i18n.translate    import translate_to_english, translate_batch
from i18n.query_expand import expand_query, get_multilingual_search_terms
"""

from i18n.detect import detect_language, detect_language_batch, is_non_english
from i18n.query_expand import expand_query, get_multilingual_search_terms
from i18n.translate import translate_batch, translate_to_english

__all__ = [
    "detect_language",
    "detect_language_batch",
    "is_non_english",
    "translate_to_english",
    "translate_batch",
    "expand_query",
    "get_multilingual_search_terms",
]
