"""
analysis/opsec.py — Detects operational security failures in threat actor
communications that inadvertently reveal real-world identity or location.
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from typing import Optional

logger = logging.getLogger(__name__)

# Known clearnet URL regex — captures domain from http(s) URLs
_HTTP_URL_RE = re.compile(
    r"https?://([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})(?:[/?#][^\s]*)?",
    re.IGNORECASE,
)

# Structured data patterns to strip before language detection
_BITCOIN_RE = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
_ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")
_URL_RE = re.compile(r"https?://\S+")
_ONION_RE = re.compile(r"\b[a-z2-7]{56}\.onion\b", re.IGNORECASE)


def _strip_non_linguistic(text: str) -> str:
    """Remove URLs, wallet addresses, CVE IDs, and .onion addresses before language detection."""
    text = _URL_RE.sub(" ", text)
    text = _BITCOIN_RE.sub(" ", text)
    text = _ETH_RE.sub(" ", text)
    text = _CVE_RE.sub(" ", text)
    text = _ONION_RE.sub(" ", text)
    return text


def detect_timezone_leak(texts_with_timestamps: list[dict]) -> dict:
    """
    Analyze posting time distribution to infer actor timezone.

    Input: list of {"text": str, "timestamp": datetime}
    If 80%+ of posts fall within a 6-hour window: infer timezone.

    Returns:
        detected: bool
        probable_timezone_offset: str | None  (e.g. "UTC+3")
        confidence: float
        posting_hours: list[int]
        peak_window: str | None  (e.g. "09:00-15:00 UTC")
    """
    if not texts_with_timestamps:
        return {
            "detected": False,
            "probable_timezone_offset": None,
            "confidence": 0.0,
            "posting_hours": [],
            "peak_window": None,
        }

    posting_hours: list[int] = []
    for entry in texts_with_timestamps:
        ts = entry.get("timestamp")
        if ts is None:
            continue
        if hasattr(ts, "utcoffset") and ts.utcoffset() is not None:
            # Convert to UTC
            utc_ts = ts.astimezone(tz=None).replace(tzinfo=None)
            posting_hours.append(utc_ts.hour)
        else:
            posting_hours.append(ts.hour)

    if not posting_hours:
        return {
            "detected": False,
            "probable_timezone_offset": None,
            "confidence": 0.0,
            "posting_hours": [],
            "peak_window": None,
        }

    total = len(posting_hours)

    # Sliding 6-hour window to find best coverage
    best_start = 0
    best_count = 0
    for h in range(24):
        window_hours = {(h + offset) % 24 for offset in range(6)}
        count = sum(1 for hour in posting_hours if hour in window_hours)
        if count > best_count:
            best_count = count
            best_start = h

    coverage = best_count / total

    if coverage >= 0.80:
        end_hour = (best_start + 6) % 24
        peak_window = f"{best_start:02d}:00-{end_hour:02d}:00 UTC"

        # Infer timezone: assume actor is active during 09:00-17:00 local.
        # Window center → local noon assumption (midpoint at ~13:00 local)
        window_center_utc = (best_start + 3) % 24
        offset_raw = 13 - window_center_utc
        if offset_raw > 12:
            offset_raw -= 24
        elif offset_raw < -12:
            offset_raw += 24

        if offset_raw >= 0:
            tz_str = f"UTC+{offset_raw}"
        else:
            tz_str = f"UTC{offset_raw}"

        return {
            "detected": True,
            "probable_timezone_offset": tz_str,
            "confidence": round(coverage, 3),
            "posting_hours": posting_hours,
            "peak_window": peak_window,
        }

    return {
        "detected": False,
        "probable_timezone_offset": None,
        "confidence": round(coverage, 3),
        "posting_hours": posting_hours,
        "peak_window": None,
    }


def detect_language_switch(texts: list[str]) -> dict:
    """
    Detect if an actor switches between languages across posts.

    Returns:
        detected: bool
        languages_found: list[str]  (ISO 639-1 codes)
        primary_language: str | None
        switch_count: int
        switched_texts_indices: list[int]
    """
    try:
        from langdetect import detect as ld_detect
    except ImportError:
        return {"detected": False}

    if not texts:
        return {
            "detected": False,
            "languages_found": [],
            "primary_language": None,
            "switch_count": 0,
            "switched_texts_indices": [],
        }

    detected_langs: list[Optional[str]] = []
    for text in texts:
        if not text:
            detected_langs.append(None)
            continue
        clean_text = _strip_non_linguistic(text)
        if len(clean_text) < 50:
            detected_langs.append(None)
            continue
        try:
            detected_langs.append(ld_detect(clean_text))
        except Exception:
            detected_langs.append(None)

    valid_langs = [lang for lang in detected_langs if lang is not None]
    if not valid_langs:
        return {
            "detected": False,
            "languages_found": [],
            "primary_language": None,
            "switch_count": 0,
            "switched_texts_indices": [],
        }

    counter = Counter(valid_langs)
    primary_lang, _ = counter.most_common(1)[0]
    languages_found = list(counter.keys())

    switched_indices = [
        i
        for i, lang in enumerate(detected_langs)
        if lang is not None and lang != primary_lang
    ]

    detected = len(switched_indices) > 0

    return {
        "detected": detected,
        "languages_found": languages_found,
        "primary_language": primary_lang,
        "switch_count": len(switched_indices),
        "switched_texts_indices": switched_indices,
    }


def detect_clearnet_slip(texts: list[str]) -> dict:
    """
    Find clearnet URLs accidentally posted in a dark web context.

    Clearnet = any URL whose domain does not end in .onion.

    Returns:
        detected: bool
        clearnet_urls: list[str]
        platforms: list[str]  (e.g. ["youtube.com", "reddit.com"])
    """
    clearnet_urls: list[str] = []
    platforms: set[str] = set()

    for text in texts:
        if not text:
            continue
        for match in _HTTP_URL_RE.finditer(text):
            domain = match.group(1).lower()
            full_url = match.group(0)
            if not domain.endswith(".onion"):
                clearnet_urls.append(full_url)
                # Extract base domain (last two parts)
                parts = domain.rstrip(".").split(".")
                if len(parts) >= 2:
                    platforms.add(".".join(parts[-2:]))
                else:
                    platforms.add(domain)

    return {
        "detected": len(clearnet_urls) > 0,
        "clearnet_urls": clearnet_urls,
        "platforms": sorted(platforms),
    }


def detect_pgp_reuse(
    pgp_fingerprints: list[str],
    sources: Optional[list[str]] = None,
) -> dict:
    """
    Check if the same PGP fingerprint appears across multiple source domains,
    or multiple times in the fingerprint list.

    When *sources* is provided with the same length as *pgp_fingerprints*,
    reuse is detected if the same fingerprint maps to more than one source.

    When *sources* is omitted or length mismatches, reuse is detected when
    any fingerprint appears more than once in *pgp_fingerprints*.

    Returns:
        detected: bool
        reused_fingerprints: list[str]
        cross_platform_exposure: list[dict]
        forum_count: int
        fingerprint: str | None
    """
    if not pgp_fingerprints:
        return {
            "detected": False,
            "reused_fingerprints": [],
            "cross_platform_exposure": [],
            "forum_count": 0,
            "fingerprint": None,
        }

    normalized = [fp.strip() for fp in pgp_fingerprints if fp and str(fp).strip()]

    if sources is not None and len(sources) == len(pgp_fingerprints):
        fp_to_sources: dict[str, set[str]] = {}
        for fp, src in zip(normalized, sources):
            if fp not in fp_to_sources:
                fp_to_sources[fp] = set()
            fp_to_sources[fp].add(src or "")

        reused: list[str] = []
        cross_platform: list[dict] = []

        for fp, srcs in fp_to_sources.items():
            if len(srcs) > 1:
                reused.append(fp)
                cross_platform.append({"fingerprint": fp, "sources": sorted(srcs)})

        return {
            "detected": len(reused) > 0,
            "reused_fingerprints": reused,
            "cross_platform_exposure": cross_platform,
            "forum_count": max((len(s) for s in fp_to_sources.values()), default=0),
            "fingerprint": reused[0] if reused else None,
        }

    cnt = Counter(normalized)
    dupes = [fp for fp, n in cnt.items() if n > 1]
    return {
        "detected": len(dupes) > 0,
        "reused_fingerprints": dupes,
        "cross_platform_exposure": [],
        "forum_count": 2,
        "fingerprint": dupes[0] if dupes else None,
    }


def run_full_opsec_analysis(
    handle: str,
    texts_with_timestamps: list[dict],
    pgp_fingerprints: Optional[list[str]] = None,
    pgp_sources: Optional[list[str]] = None,
) -> dict:
    """
    Run all OPSEC checks for a given actor.

    Returns combined report with findings, opsec_score (100 = best), risk_level,
    and legacy keys timezone_leak / language_switch / clearnet_slips for callers.
    """
    texts = [entry.get("text", "") for entry in texts_with_timestamps]

    tz_result = detect_timezone_leak(texts_with_timestamps)
    lang_result = detect_language_switch(texts)
    clearnet_result = detect_clearnet_slip(texts)

    if tz_result.get("detected"):
        primary_language = lang_result.get("primary_language", "unknown")
        data_points = len(texts_with_timestamps)
        original_conf = float(tz_result.get("confidence", 0.5))
        tz_result["data_points"] = data_points
        tz_result["primary_language_correlation"] = primary_language
        if primary_language == "en" or data_points < 20:
            tz_result["confidence"] = round(original_conf * 0.5, 3)
            tz_result["confidence_level"] = "low"
            tz_result["note"] = (
                "Insufficient data for reliable timezone inference"
                if data_points < 20
                else "Timezone leak is LOW confidence for English content"
            )
        else:
            tz_result["confidence_level"] = "high" if original_conf >= 0.85 else "medium"

    findings: list[dict] = []
    score = 100

    if tz_result.get("detected"):
        conf = float(tz_result.get("confidence", 0.5))
        severity = tz_result.get("confidence_level", "high") if conf >= 0.4 else "low"
        findings.append(
            {
                "type": "timezone_leak",
                "severity": severity,
                "description": (
                    f"Timezone leak: probable {tz_result.get('probable_timezone_offset', 'unknown')}"
                ),
                "evidence": (
                    f"Activity window: {tz_result.get('peak_window', 'unknown')} "
                    f"(confidence {conf:.0%})"
                ),
                "first_detected": None,
            }
        )
        score -= 25

    if lang_result.get("detected"):
        langs = lang_result.get("languages_found", [])
        findings.append(
            {
                "type": "language_switch",
                "severity": "medium",
                "description": (
                    f"{lang_result.get('switch_count', 0)} language switch(es) detected"
                ),
                "evidence": (
                    f"Primary: {lang_result.get('primary_language', 'unknown')}. "
                    f"Also: {', '.join(str(l) for l in langs if l != lang_result.get('primary_language'))}"
                ),
                "first_detected": None,
            }
        )
        score -= 15

    if clearnet_result.get("detected"):
        platforms = clearnet_result.get("platforms", [])
        findings.append(
            {
                "type": "clearnet_slip",
                "severity": "high",
                "description": (
                    f"{len(clearnet_result.get('clearnet_urls', []))} clearnet URL(s) posted"
                ),
                "evidence": f"Platforms: {', '.join(str(p) for p in platforms[:5])}",
                "first_detected": None,
            }
        )
        score -= 15

    pgp_result: dict = {"detected": False}
    if pgp_fingerprints and len(pgp_fingerprints) > 1:
        pgp_result = detect_pgp_reuse(pgp_fingerprints, pgp_sources)
        if pgp_result.get("detected"):
            fp_short = (pgp_result.get("fingerprint") or "")[:16]
            findings.append(
                {
                    "type": "pgp_reuse",
                    "severity": "high",
                    "description": (
                        f"Same PGP key used across {pgp_result.get('forum_count', 2)} forums"
                    ),
                    "evidence": f"Key {fp_short}... reused",
                    "first_detected": None,
                }
            )
            score -= 20

    score = max(0, score)

    if score >= 80:
        risk_level = "LOW"
    elif score >= 60:
        risk_level = "MEDIUM"
    elif score >= 40:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    # Legacy normalized risk_score (0–1), higher = worse — for backward compatibility
    legacy_scores: list[float] = []
    if tz_result.get("detected"):
        legacy_scores.append(float(tz_result.get("confidence", 0.5)))
    else:
        legacy_scores.append(0.0)
    if lang_result.get("detected"):
        n_texts = len(texts)
        n_switched = lang_result.get("switch_count", 0)
        legacy_scores.append(min(1.0, n_switched / max(n_texts, 1)))
    else:
        legacy_scores.append(0.0)
    if clearnet_result.get("detected"):
        legacy_scores.append(1.0)
    else:
        legacy_scores.append(0.0)

    risk_score = sum(legacy_scores) / len(legacy_scores) if legacy_scores else 0.0
    if pgp_result.get("detected"):
        risk_score = min(1.0, risk_score + 0.2)

    return {
        "handle": handle,
        "timezone_leak": tz_result,
        "language_switch": lang_result,
        "clearnet_slips": clearnet_result,
        "pgp_reuse": pgp_result,
        "findings": findings,
        "opsec_score": score,
        "risk_level": risk_level,
        "risk_score": round(risk_score, 3),
    }
