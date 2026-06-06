"""
i18n/query_expand.py — Expands a search query into multiple languages for
broader dark web coverage.

Russian, Chinese, and Arabic dark web communities contain high-value
intelligence that is almost entirely missed by English-only tools.
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)

_DEFAULT_TARGET_LANGUAGES = ["ru", "zh", "ar", "es", "de", "fr", "pt"]


def expand_query(
    query: str,
    target_languages: Optional[list[str]] = None,
) -> dict[str, str]:
    """
    Translate the query into multiple languages.

    Default target languages: ru, zh, ar, es, de, fr, pt.
    Returns dict: {"en": original_query, "ru": translated, ...}
    Skips languages where translation fails — never returns None values.

    Args:
        query: Original English query
        target_languages: List of ISO 639-1 codes. If None, uses I18N_LANGUAGES
                         from config.py, or falls back to default languages.
    """
    from i18n.translate import _translate_from_english

    if target_languages is None:
        try:
            from config import I18N_LANGUAGES
            if I18N_LANGUAGES:
                target_languages = I18N_LANGUAGES
        except ImportError:
            pass
        if not target_languages:
            target_languages = ["en"] + _DEFAULT_TARGET_LANGUAGES

    result: dict[str, str] = {"en": query}

    for lang in target_languages:
        if lang == "en":
            continue
        try:
            translated = _translate_from_english(query, lang)
            if translated is not None and translated != query:
                result[lang] = translated
        except Exception as exc:
            logger.debug("expand_query: skipping lang=%s (%s)", lang, exc)

    return result


def get_multilingual_search_terms(
    query: str,
    target_languages: Optional[list[str]] = None,
) -> list[str]:
    """
    Return a flat list of all query translations (including original English).

    Used by search.py to fan out searches in multiple languages.
    """
    translations = expand_query(query, target_languages)
    return list(translations.values())
