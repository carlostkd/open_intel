"""
analysis/patterns.py — Pattern library for known behavioral signatures.

Heuristic rules derived from threat intelligence research for detecting
exit scams, law enforcement actions, and new actor emergence.
"""

from __future__ import annotations

import logging
from datetime import date, timedelta
from typing import Any

from analysis.temporal import (  # noqa: E402 — imported at module level for patchability
    build_activity_timeline,
    compute_activity_stats,
    detect_anomalies,
    detect_silence_breaks,
)

logger = logging.getLogger(__name__)


def check_exit_scam_pattern(timeline: list[dict]) -> dict:
    """
    Check if a marketplace/forum shows exit scam warning signs.

    Criteria: activity drops >60% over the last 14 days vs prior 14-day average.
    Returns {"risk": "high"|"medium"|"low", "confidence": float, "reason": str}.
    """
    if not timeline:
        return {"risk": "low", "confidence": 0.0, "reason": "Insufficient data"}

    sorted_entries = sorted(timeline, key=lambda x: x["date"])

    if len(sorted_entries) < 2:
        return {"risk": "low", "confidence": 0.1, "reason": "Insufficient historical data"}

    last_date = sorted_entries[-1]["date"]
    cutoff_recent = last_date - timedelta(days=14)
    cutoff_prior = cutoff_recent - timedelta(days=14)

    recent_counts = [
        e["count"] for e in sorted_entries if e["date"] > cutoff_recent
    ]
    prior_counts = [
        e["count"]
        for e in sorted_entries
        if cutoff_prior < e["date"] <= cutoff_recent
    ]

    if not prior_counts:
        return {
            "risk": "low",
            "confidence": 0.1,
            "reason": "No prior 14-day baseline available",
        }

    recent_avg = sum(recent_counts) / max(len(recent_counts), 1) if recent_counts else 0.0
    prior_avg = sum(prior_counts) / len(prior_counts)

    if prior_avg == 0.0:
        return {"risk": "low", "confidence": 0.2, "reason": "No prior activity baseline"}

    drop_ratio = 1.0 - (recent_avg / prior_avg)
    confidence = min(
        1.0,
        len(sorted_entries) / 30.0,  # more data → higher confidence
    )

    if drop_ratio > 0.60:
        return {
            "risk": "high",
            "confidence": round(confidence, 3),
            "reason": (
                f"Activity dropped {drop_ratio:.0%} over the last 14 days "
                f"(from {prior_avg:.1f} to {recent_avg:.1f} posts/day)"
            ),
        }
    elif drop_ratio > 0.30:
        return {
            "risk": "medium",
            "confidence": round(confidence * 0.7, 3),
            "reason": (
                f"Moderate activity decline of {drop_ratio:.0%} over the last 14 days"
            ),
        }
    else:
        return {
            "risk": "low",
            "confidence": round(confidence * 0.5, 3),
            "reason": "Activity levels are stable",
        }


def check_law_enforcement_pattern(timeline: list[dict]) -> dict:
    """
    Check for sudden complete silence after sustained activity.

    Criteria: zero activity for 7+ consecutive days after a period of daily activity.
    Returns {"risk": "high"|"medium"|"low", "confidence": float, "reason": str}.
    """
    if not timeline or len(timeline) < 2:
        return {"risk": "low", "confidence": 0.0, "reason": "Insufficient data"}

    sorted_entries = sorted(timeline, key=lambda x: x["date"])

    # Check for silence in the last N calendar days relative to last seen
    last_date = sorted_entries[-1]["date"]
    today = date.today()
    days_since_last = (today - last_date).days

    # Check if there was sustained prior activity (at least 5 data points)
    has_sustained = len(sorted_entries) >= 5
    confidence_base = min(1.0, len(sorted_entries) / 20.0)

    if days_since_last >= 7 and has_sustained:
        return {
            "risk": "high",
            "confidence": round(min(confidence_base + 0.3, 1.0), 3),
            "reason": (
                f"Complete silence for {days_since_last} days after sustained activity "
                f"({len(sorted_entries)} active days on record)"
            ),
        }
    elif days_since_last >= 3 and has_sustained:
        return {
            "risk": "medium",
            "confidence": round(confidence_base * 0.6, 3),
            "reason": f"Reduced activity for {days_since_last} days",
        }
    else:
        return {
            "risk": "low",
            "confidence": round(confidence_base * 0.3, 3),
            "reason": "Activity pattern appears normal",
        }


def check_new_actor_pattern(
    entity_value: str,
    entity_type: str,
) -> dict:
    """
    Check if this entity has appeared for the first time in the last 7 days.

    Returns {"is_new": bool, "first_seen": date | None, "days_active": int}.
    """
    try:
        timeline = build_activity_timeline(entity_value, entity_type)
        if not timeline:
            return {"is_new": False, "first_seen": None, "days_active": 0}

        stats = compute_activity_stats(timeline)
        first_seen = stats.get("first_seen")
        days_active = int(stats.get("active_days", 0))

        is_new = False
        if first_seen is not None:
            days_since_first = (date.today() - first_seen).days
            is_new = days_since_first < 7

        return {
            "is_new": is_new,
            "first_seen": first_seen,
            "days_active": days_active,
        }

    except Exception as exc:
        logger.debug("check_new_actor_pattern: error (%s)", exc)
        return {"is_new": False, "first_seen": None, "days_active": 0}


def run_all_patterns(
    entity_value: str,
    entity_type: str,
) -> dict:
    """
    Run all pattern checks for an entity.

    Returns combined dict with keys: exit_scam, law_enforcement, new_actor,
    anomalies, silence_breaks.
    """
    try:
        timeline = build_activity_timeline(entity_value, entity_type)

        return {
            "exit_scam": check_exit_scam_pattern(timeline),
            "law_enforcement": check_law_enforcement_pattern(timeline),
            "new_actor": check_new_actor_pattern(entity_value, entity_type),
            "anomalies": detect_anomalies(timeline),
            "silence_breaks": detect_silence_breaks(timeline),
        }
    except Exception as exc:
        logger.debug("run_all_patterns: error (%s)", exc)
        return {
            "exit_scam": {"risk": "low", "confidence": 0.0, "reason": "Error"},
            "law_enforcement": {"risk": "low", "confidence": 0.0, "reason": "Error"},
            "new_actor": {"is_new": False, "first_seen": None, "days_active": 0},
            "anomalies": [],
            "silence_breaks": [],
        }
