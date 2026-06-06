"""
fingerprint/stylometry.py — Writing style feature extraction and similarity.

Identifies when the same person posts under different handles on different
forums, based on HOW they write rather than WHAT they write.
"""

from __future__ import annotations

import math
import re
import string
from collections import Counter
from typing import Optional

# Top-20 English function words — nearly impossible to consciously change
_FUNCTION_WORDS = [
    "the", "a", "an", "and", "but", "or", "if", "in", "on", "at",
    "to", "for", "of", "with", "is", "are", "was", "were", "be", "have",
]

# Splits on whitespace that follows a sentence-ending punctuation mark
_SENTENCE_RE = re.compile(r"(?<=[.!?])\s+")

# Patterns for structured data to detect non-natural-language text
_BITCOIN_RE = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
_ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")
_URL_RE = re.compile(r"https?://\S+")
_ADDRESS_RE = re.compile(r"\b[a-z2-7]{56}\.onion\b", re.IGNORECASE)


def _is_natural_language(text: str) -> bool:
    """Returns True if text contains enough natural language for stylometry."""
    words = text.split()
    if len(words) < 10:
        return False
    structured_count = 0
    structured_count += len(_BITCOIN_RE.findall(text))
    structured_count += len(_ETH_RE.findall(text))
    structured_count += len(_CVE_RE.findall(text))
    structured_count += len(_URL_RE.findall(text))
    structured_count += len(_ADDRESS_RE.findall(text))
    if structured_count / len(words) > 0.5:
        return False
    return True


def _split_sentences(text: str) -> list[str]:
    parts = _SENTENCE_RE.split(text.strip())
    return [s for s in parts if s.strip()]


def _split_paragraphs(text: str) -> list[str]:
    parts = re.split(r"\n\s*\n", text.strip())
    return [p for p in parts if p.strip()]


def _get_words(text: str) -> list[str]:
    return re.findall(r"\b\w+\b", text)


def extract_style_vector(text: str) -> dict | None:
    """
    Extract a fixed set of stylometric features from *text*.

    Returns None for text shorter than 100 characters (too short to be
    meaningful) OR if text is primarily structured data (wallets, URLs, CVEs).
    Never raises.
    """
    try:
        if not text or len(text) < 100:
            return None

        if not _is_natural_language(text):
            return None

        words = _get_words(text)
        if not words:
            return None

        alpha_words = re.findall(r"\b[a-zA-Z]+\b", text)

        # avg_word_length
        avg_word_length = (
            sum(len(w) for w in alpha_words) / len(alpha_words)
            if alpha_words
            else 0.0
        )

        # avg_sentence_length (words per sentence)
        sentences = _split_sentences(text)
        if not sentences:
            sentences = [text]
        sent_word_counts = [len(_get_words(s)) for s in sentences]
        avg_sentence_length = (
            sum(sent_word_counts) / len(sent_word_counts)
            if sent_word_counts
            else 0.0
        )

        # vocabulary_richness — type-token ratio
        total_words = len(words)
        unique_words = len({w.lower() for w in words})
        vocabulary_richness = min(unique_words / total_words, 1.0) if total_words else 0.0

        # punctuation_density
        punct_count = sum(1 for c in text if c in string.punctuation)
        punctuation_density = punct_count / len(text) if text else 0.0

        # uppercase_ratio
        alpha_chars = [c for c in text if c.isalpha()]
        upper_chars = [c for c in alpha_chars if c.isupper()]
        uppercase_ratio = len(upper_chars) / len(alpha_chars) if alpha_chars else 0.0

        # digit_ratio
        digit_count = sum(1 for c in text if c.isdigit())
        digit_ratio = digit_count / len(text) if text else 0.0

        # function_word_freq — frequency of each of the 20 function words
        words_lower = [w.lower() for w in words]
        function_word_freq: dict[str, float] = {
            fw: words_lower.count(fw) / total_words if total_words else 0.0
            for fw in _FUNCTION_WORDS
        }

        # avg_paragraph_length — mean sentences per paragraph
        paragraphs = _split_paragraphs(text)
        if paragraphs:
            para_sent_counts = [
                max(len(_split_sentences(p)), 1) for p in paragraphs
            ]
            avg_paragraph_length = sum(para_sent_counts) / len(para_sent_counts)
        else:
            avg_paragraph_length = float(len(sentences))

        # exclamation_ratio and question_ratio
        num_sentences = len(sentences)
        exclamation_ratio = text.count("!") / num_sentences if num_sentences else 0.0
        question_ratio = text.count("?") / num_sentences if num_sentences else 0.0

        # char_ngram_freq — top-50 character 3-grams
        text_lower = text.lower()
        all_ngrams = [text_lower[i : i + 3] for i in range(len(text_lower) - 2)]
        ngram_counter = Counter(all_ngrams)
        total_ngrams = len(all_ngrams)
        char_ngram_freq: dict[str, float] = {
            ngram: count / total_ngrams if total_ngrams else 0.0
            for ngram, count in ngram_counter.most_common(50)
        }

        return {
            "avg_word_length": float(avg_word_length),
            "avg_sentence_length": float(avg_sentence_length),
            "vocabulary_richness": float(vocabulary_richness),
            "punctuation_density": float(punctuation_density),
            "uppercase_ratio": float(uppercase_ratio),
            "digit_ratio": float(digit_ratio),
            "function_word_freq": function_word_freq,
            "avg_paragraph_length": float(avg_paragraph_length),
            "exclamation_ratio": float(exclamation_ratio),
            "question_ratio": float(question_ratio),
            "char_ngram_freq": char_ngram_freq,
        }

    except Exception:
        return None


# ---------------------------------------------------------------------------
# Vector alignment helpers
# ---------------------------------------------------------------------------

def _aligned_flatten(
    vector_a: dict, vector_b: dict
) -> tuple[list[float], list[float]]:
    """
    Flatten two style vectors into aligned float arrays.

    For scalar keys: use the value from each vector (0.0 if missing).
    For nested-dict keys (function_word_freq, char_ngram_freq): use the
    union of subkeys, with 0.0 for any subkey missing in one vector.
    """
    flat_a: list[float] = []
    flat_b: list[float] = []

    all_keys = sorted(set(vector_a.keys()) | set(vector_b.keys()))

    for key in all_keys:
        val_a = vector_a.get(key, 0.0)
        val_b = vector_b.get(key, 0.0)

        if isinstance(val_a, dict) or isinstance(val_b, dict):
            dict_a = val_a if isinstance(val_a, dict) else {}
            dict_b = val_b if isinstance(val_b, dict) else {}
            all_subkeys = sorted(set(dict_a.keys()) | set(dict_b.keys()))
            for subkey in all_subkeys:
                flat_a.append(float(dict_a.get(subkey, 0.0)))
                flat_b.append(float(dict_b.get(subkey, 0.0)))
        else:
            flat_a.append(float(val_a) if val_a else 0.0)
            flat_b.append(float(val_b) if val_b else 0.0)

    return flat_a, flat_b


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    mag_a = math.sqrt(sum(x * x for x in a))
    mag_b = math.sqrt(sum(y * y for y in b))
    if mag_a == 0.0 or mag_b == 0.0:
        return 0.0
    return dot / (mag_a * mag_b)


def compute_similarity(vector_a: dict, vector_b: dict) -> float:
    """
    Cosine similarity between two style vectors (0.0–1.0).

    Handles nested function_word_freq and char_ngram_freq dicts by
    flattening both vectors into aligned float arrays. Returns 0.0 if
    either vector is None or malformed. Never raises.
    """
    try:
        if not vector_a or not vector_b:
            return 0.0
        if not isinstance(vector_a, dict) or not isinstance(vector_b, dict):
            return 0.0
        flat_a, flat_b = _aligned_flatten(vector_a, vector_b)
        raw = _cosine_similarity(flat_a, flat_b)
        return float(max(0.0, min(1.0, raw)))
    except Exception:
        return 0.0


def are_likely_same_author(
    vector_a: dict,
    vector_b: dict,
    threshold: float = 0.85,
) -> tuple[bool, float]:
    """
    Returns (True, similarity_score) if similarity >= threshold.

    Threshold of 0.85 is conservative — only flag high-confidence matches.
    """
    score = compute_similarity(vector_a, vector_b)
    return (score >= threshold, score)
