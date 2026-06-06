"""
i18n/detect.py — Language detection for scraped content.

Uses the langdetect library for per-text language identification.
Returns ISO 639-1 language codes ("en", "ru", "zh", "ar", "es", "pt", etc.).
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)


def detect_language(text: str) -> Optional[str]:
    """
    Return the ISO 639-1 language code for *text*.

    Returns None for very short text (<50 chars), undetectable text, or
    when langdetect is not installed. Never raises.
    """
    try:
        if not text or len(text) < 50:
            return None

        from langdetect import detect as ld_detect, LangDetectException  # type: ignore

        try:
            return ld_detect(text)
        except Exception:
            return None

    except ImportError:
        logger.debug("detect_language: langdetect not installed")
        return None
    except Exception:
        return None


def detect_language_batch(texts: list[str]) -> list[Optional[str]]:
    """
    Batch language detection. More efficient than calling detect_language
    in a loop for large datasets.
    """
    try:
        from langdetect import detect as ld_detect  # type: ignore

        results: list[Optional[str]] = []
        for text in texts:
            if not text or len(text) < 50:
                results.append(None)
                continue
            try:
                results.append(ld_detect(text))
            except Exception:
                results.append(None)
        return results

    except ImportError:
        logger.debug("detect_language_batch: langdetect not installed")
        return [None] * len(texts)
    except Exception:
        return [None] * len(texts)


def is_non_english(text: str) -> bool:
    """
    Return True if the detected language is not English (or detection fails).

    Used as a quick gate before running translation.
    """
    lang = detect_language(text)
    if lang is None:
        return True
    return lang != "en"
