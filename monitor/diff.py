"""
Content change detection using difflib (unified diff + similarity ratio).
"""

from __future__ import annotations

import difflib
import hashlib
from typing import Any


def compute_diff(old_text: str, new_text: str) -> dict[str, Any]:
    """
    Compare two text blobs. change_ratio: 0.0 identical, 1.0 completely different.
    """
    old_bytes = old_text.encode("utf-8")
    new_bytes = new_text.encode("utf-8")
    content_hash_old = hashlib.sha256(old_bytes).hexdigest()
    content_hash_new = hashlib.sha256(new_bytes).hexdigest()

    if old_text == new_text:
        return {
            "changed": False,
            "content_hash_old": content_hash_old,
            "content_hash_new": content_hash_new,
            "lines_added": 0,
            "lines_removed": 0,
            "diff_summary": "",
            "change_ratio": 0.0,
        }

    old_lines = old_text.splitlines(keepends=True)
    new_lines = new_text.splitlines(keepends=True)
    diff_lines = list(
        difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile="old",
            tofile="new",
            lineterm="",
        )
    )
    lines_added = 0
    lines_removed = 0
    for line in diff_lines:
        if line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
            continue
        if line.startswith("+"):
            lines_added += 1
        elif line.startswith("-"):
            lines_removed += 1

    matcher = difflib.SequenceMatcher(None, old_text, new_text)
    change_ratio = 1.0 - matcher.ratio()

    summary_src = "\n".join(diff_lines)
    diff_summary = summary_src[:500]

    return {
        "changed": True,
        "content_hash_old": content_hash_old,
        "content_hash_new": content_hash_new,
        "lines_added": lines_added,
        "lines_removed": lines_removed,
        "diff_summary": diff_summary,
        "change_ratio": float(change_ratio),
    }


def is_significant_change(diff: dict, threshold: float = 0.1) -> bool:
    """True when change_ratio meets or exceeds *threshold*."""
    try:
        return float(diff.get("change_ratio", 0.0)) >= threshold
    except (TypeError, ValueError):
        return False
