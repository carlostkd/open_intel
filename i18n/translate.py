"""
i18n/translate.py — Translation pipeline.

Strategy (tried in order, falls back on failure):
  1. DeepL API if DEEPL_API_KEY is set
  2. Helsinki-NLP/opus-mt local model if transformers is available
  3. Returns None if both are unavailable

Text longer than 2000 chars is split into sentences, each translated,
then rejoined.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Optional

logger = logging.getLogger(__name__)

# Module-level cache: {(src_lang, tgt_lang): (tokenizer, model)}
_model_cache: dict[tuple[str, str], tuple] = {}

_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")


def _split_sentences(text: str) -> list[str]:
    parts = _SENTENCE_SPLIT_RE.split(text.strip())
    return [p for p in parts if p.strip()]


def _deepl_translate(
    text: str, target_lang: str, source_lang: Optional[str] = None
) -> Optional[str]:
    """Call the DeepL API to translate *text* to *target_lang*."""
    api_key = os.getenv("DEEPL_API_KEY", "")
    if not api_key:
        return None

    try:
        import requests  # type: ignore

        params: dict = {
            "auth_key": api_key,
            "text": text,
            "target_lang": target_lang.upper(),
        }
        if source_lang:
            params["source_lang"] = source_lang.upper()

        resp = requests.post(
            "https://api-free.deepl.com/v2/translate",
            data=params,
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()["translations"][0]["text"]
    except Exception as exc:
        logger.debug("DeepL translate failed: %s", exc)
        return None


def _helsinki_translate(
    text: str, src_lang: str, tgt_lang: str = "en"
) -> Optional[str]:
    """Translate using a Helsinki-NLP/opus-mt local model."""
    try:
        from transformers import MarianMTModel, MarianTokenizer  # type: ignore

        cache_key = (src_lang, tgt_lang)
        if cache_key not in _model_cache:
            model_name = f"Helsinki-NLP/opus-mt-{src_lang}-{tgt_lang}"
            tokenizer = MarianTokenizer.from_pretrained(model_name)
            model = MarianMTModel.from_pretrained(model_name)
            _model_cache[cache_key] = (tokenizer, model)

        tokenizer, model = _model_cache[cache_key]
        inputs = tokenizer([text], return_tensors="pt", padding=True, truncation=True)
        translated = model.generate(**inputs)
        return tokenizer.decode(translated[0], skip_special_tokens=True)
    except Exception as exc:
        logger.debug("Helsinki-NLP translate failed: %s", exc)
        return None


def _translate_long_text(
    text: str,
    translate_fn,
    *args,
    **kwargs,
) -> Optional[str]:
    """Split text into sentences, translate each, rejoin."""
    sentences = _split_sentences(text)
    if not sentences:
        return translate_fn(text, *args, **kwargs)

    translated_parts: list[str] = []
    for sentence in sentences:
        result = translate_fn(sentence, *args, **kwargs)
        if result is None:
            return None
        translated_parts.append(result)
    return " ".join(translated_parts)


def translate_to_english(
    text: str,
    source_lang: Optional[str] = None,
) -> Optional[str]:
    """
    Translate *text* to English.

    source_lang: ISO 639-1 code, or None to auto-detect.
    Returns None on complete failure. Never raises.
    """
    try:
        if not text:
            return None

        api_key = os.getenv("DEEPL_API_KEY", "")

        # Split long texts at sentence boundaries
        use_chunking = len(text) > 2000

        # Strategy 1: DeepL
        if api_key:
            if use_chunking:
                result = _translate_long_text(
                    text, _deepl_translate, "EN", source_lang
                )
            else:
                result = _deepl_translate(text, "EN", source_lang)
            if result is not None:
                return result

        # Strategy 2: Helsinki-NLP local model
        if source_lang:
            if use_chunking:
                result = _translate_long_text(
                    text, _helsinki_translate, source_lang, "en"
                )
            else:
                result = _helsinki_translate(text, source_lang, "en")
            if result is not None:
                return result

        return None

    except Exception as exc:
        logger.debug("translate_to_english: unexpected error (%s)", exc)
        return None


def translate_batch(
    texts: list[str],
    source_lang: Optional[str] = None,
) -> list[Optional[str]]:
    """
    Translate a list of texts to English.

    English texts are returned as-is. Returns list of same length.
    """
    try:
        from i18n.detect import detect_language
    except ImportError:
        detect_language = lambda t: None  # noqa: E731

    results: list[Optional[str]] = []
    for text in texts:
        if not text:
            results.append(text)
            continue
        detected = detect_language(text) if not source_lang else source_lang
        if detected == "en":
            results.append(text)
        else:
            results.append(translate_to_english(text, detected))
    return results


def _translate_from_english(text: str, target_lang: str) -> Optional[str]:
    """
    Translate English text to *target_lang*.

    Mirrors translate_to_english but in reverse direction.
    Used by query_expand.py.
    """
    try:
        if not text:
            return None

        api_key = os.getenv("DEEPL_API_KEY", "")

        # Strategy 1: DeepL (EN → target)
        if api_key:
            result = _deepl_translate(text, target_lang, "EN")
            if result is not None:
                return result

        # Strategy 2: Helsinki-NLP (en → target_lang)
        result = _helsinki_translate(text, "en", target_lang)
        if result is not None:
            return result

        return None

    except Exception as exc:
        logger.debug("_translate_from_english: error (%s)", exc)
        return None
