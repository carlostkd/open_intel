from datetime import datetime, timedelta, timezone
from enum import Enum


class FreshnessTag(str, Enum):
    FRESH = "fresh"
    AGING = "aging"
    STALE = "stale"
    EXPIRED = "expired"
    UNKNOWN = "unknown"


FRESHNESS_THRESHOLDS = {
    "IP_ADDRESS": {
        "fresh": 14,
        "aging": 30,
        "stale": 90,
    },
    "DOMAIN": {
        "fresh": 30,
        "aging": 90,
        "stale": 180,
    },
    "ONION_URL": {
        "fresh": 60,
        "aging": 180,
        "stale": 365,
    },
    "FILE_HASH_MD5": {
        "fresh": 365,
        "aging": 730,
        "stale": 1825,
    },
    "FILE_HASH_SHA256": {
        "fresh": 365,
        "aging": 730,
        "stale": 1825,
    },
    "CVE": {
        "fresh": 365,
        "aging": 730,
        "stale": 1825,
    },
    "BITCOIN_ADDRESS": {
        "fresh": 90,
        "aging": 180,
        "stale": 365,
    },
    "THREAT_ACTOR": {
        "fresh": 90,
        "aging": 365,
        "stale": 730,
    },
    "DEFAULT": {
        "fresh": 30,
        "aging": 90,
        "stale": 180,
    },
}


def get_freshness_tag(
    entity_type: str,
    last_seen_at: datetime | None,
    first_seen_at: datetime | None = None,
) -> FreshnessTag:
    """
    Calculate freshness tag for an entity based on its type and when it was last seen.
    """
    if not last_seen_at:
        return FreshnessTag.UNKNOWN

    thresholds = FRESHNESS_THRESHOLDS.get(
        entity_type,
        FRESHNESS_THRESHOLDS["DEFAULT"],
    )

    now = datetime.now(timezone.utc)
    # Ensure last_seen_at is tz-aware before subtracting
    if last_seen_at.tzinfo is None:
        last_seen_at = last_seen_at.replace(tzinfo=timezone.utc)
    days_since_seen = (now - last_seen_at).days

    if days_since_seen <= thresholds["fresh"]:
        return FreshnessTag.FRESH
    elif days_since_seen <= thresholds["aging"]:
        return FreshnessTag.AGING
    elif days_since_seen <= thresholds["stale"]:
        return FreshnessTag.STALE
    else:
        return FreshnessTag.EXPIRED


def get_freshness_display(tag: FreshnessTag) -> dict:
    """
    Get display config for a freshness tag.
    """
    return {
        FreshnessTag.FRESH: {
            "label": "Fresh",
            "color": "green",
            "description": "Recently observed",
        },
        FreshnessTag.AGING: {
            "label": "Aging",
            "color": "yellow",
            "description": "Observed 1-3 months ago",
        },
        FreshnessTag.STALE: {
            "label": "Stale",
            "color": "orange",
            "description": "Observed 3-6 months ago — verify before use",
        },
        FreshnessTag.EXPIRED: {
            "label": "Expired",
            "color": "red",
            "description": "Observed over 6 months ago — likely inactive",
        },
        FreshnessTag.UNKNOWN: {
            "label": "Unknown",
            "color": "gray",
            "description": "No date information available",
        },
    }.get(tag, {"label": "Unknown", "color": "gray"})