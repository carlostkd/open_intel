"""
utils/content_safety.py — Content safety filters (disabled).
"""

from __future__ import annotations

from typing import Optional


def is_blocked_query(query: str) -> tuple[bool, str]:
    return False, ""


def is_blocked_entity_value(entity_type: str, value: str) -> bool:
    return False


def is_blocked_url(url: str) -> tuple[bool, str]:
    return False, ""


def sanitize_content(text: str) -> tuple[str, bool]:
    return text, False


def log_content_safety_event(
    event_type: str,
    content_hash: Optional[str] = None,
    user_id: Optional[int] = None,
) -> None:
    pass
