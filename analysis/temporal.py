"""
analysis/temporal.py — Time-series analysis of forum and actor behavior.

Detects anomalies that historically precede significant events (exit scams,
law enforcement actions, major releases).
"""

from __future__ import annotations

import logging
import math
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)


def build_activity_timeline(
    entity_value: str,
    entity_type: str,
    since: Optional[datetime] = None,
) -> list[dict]:
    """
    Query DB for all pages where this entity appeared, grouped by day.

    Returns list of {"date": date, "count": int, "page_ids": list[str]}.
    Returns [] if no data or DB unavailable. Never raises.
    """
    try:
        from db.models import Entity, Page
        from db.session import get_session

        with get_session() as session:
            entities = (
                session.query(Entity)
                .filter(
                    Entity.entity_type == entity_type,
                    Entity.value == entity_value,
                )
                .all()
            )

            if not entities:
                return []

            page_ids = list({e.page_id for e in entities if e.page_id is not None})
            if not page_ids:
                return []

            q = session.query(Page).filter(Page.id.in_(page_ids))
            if since is not None:
                q = q.filter(Page.scrape_timestamp >= since)
            pages = q.all()

            if not pages:
                return []

            by_date: dict[date, list[str]] = defaultdict(list)
            skipped_count = 0
            for page in pages:
                ts = page.posted_at
                if ts is None:
                    skipped_count += 1
                    continue
                day = ts.date() if hasattr(ts, "date") else ts
                by_date[day].append(str(page.id))
            if skipped_count > 0:
                logger.debug(
                    "build_activity_timeline: skipped %d pages due to missing posted_at",
                    skipped_count,
                )

            return [
                {"date": d, "count": len(ids), "page_ids": ids}
                for d, ids in sorted(by_date.items())
            ]

    except Exception as exc:
        logger.debug("build_activity_timeline: DB unavailable (%s)", exc)
        return []


def compute_activity_stats(timeline: list[dict]) -> dict:
    """
    Compute summary statistics for an activity timeline.

    Returns a dict with mean_daily, std_daily, peak_day, peak_count,
    total_appearances, active_days, first_seen, last_seen.
    """
    if not timeline:
        return {
            "mean_daily": 0.0,
            "std_daily": 0.0,
            "peak_day": None,
            "peak_count": 0,
            "total_appearances": 0,
            "active_days": 0,
            "first_seen": None,
            "last_seen": None,
        }

    counts = [entry["count"] for entry in timeline]
    dates = [entry["date"] for entry in timeline]

    n = len(counts)
    total = sum(counts)
    mean_daily = total / n

    variance = sum((c - mean_daily) ** 2 for c in counts) / n
    std_daily = math.sqrt(variance)

    peak_idx = counts.index(max(counts))

    return {
        "mean_daily": float(mean_daily),
        "std_daily": float(std_daily),
        "peak_day": dates[peak_idx],
        "peak_count": int(counts[peak_idx]),
        "total_appearances": int(total),
        "active_days": n,
        "first_seen": dates[0] if dates else None,
        "last_seen": dates[-1] if dates else None,
    }


Z_SCORE_THRESHOLD = 2.5
MIN_DATA_POINTS = 10
MIN_ABSOLUTE_SPIKE = 5


def detect_anomalies(
    timeline: list[dict],
    z_threshold: float = Z_SCORE_THRESHOLD,
) -> list[dict]:
    """
    Flag days where activity deviates > z_threshold standard deviations.

    Returns list of {"date": date, "count": int, "z_score": float, "type": str}.
    Returns [] for timelines with fewer than 10 data points OR fewer than 5 posts.
    """
    if len(timeline) < MIN_DATA_POINTS:
        return []

    stats = compute_activity_stats(timeline)
    mean = stats["mean_daily"]
    std = stats["std_daily"]

    if std == 0.0:
        return []

    anomalies: list[dict] = []
    for entry in timeline:
        count = entry["count"]
        z = (count - mean) / std
        if abs(z) > z_threshold:
            if z > 0 and count < MIN_ABSOLUTE_SPIKE:
                continue
            anomalies.append(
                {
                    "date": entry["date"],
                    "count": count,
                    "z_score": float(z),
                    "type": "spike" if z > 0 else "drop",
                }
            )

    return anomalies


def detect_silence_breaks(
    timeline: list[dict],
    silence_days: int = 14,
) -> list[dict]:
    """
    Find cases where the entity was inactive for silence_days or more,
    then reappeared.

    Returns list of {"silent_from": date, "silent_to": date, "gap_days": int}.
    Significant for tracking actor reappearances under new names.
    """
    if len(timeline) < 2:
        return []

    sorted_entries = sorted(timeline, key=lambda x: x["date"])
    breaks: list[dict] = []

    for i in range(1, len(sorted_entries)):
        prev_date = sorted_entries[i - 1]["date"]
        curr_date = sorted_entries[i]["date"]
        gap = (curr_date - prev_date).days
        if gap >= silence_days:
            breaks.append(
                {
                    "silent_from": prev_date,
                    "silent_to": curr_date,
                    "gap_days": gap,
                }
            )

    return breaks
