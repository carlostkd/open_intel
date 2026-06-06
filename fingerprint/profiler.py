"""
fingerprint/profiler.py — Builds and maintains style profiles for threat actors.

A profile is the mean style vector across all posts attributed to a handle.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from fingerprint.stylometry import compute_similarity, extract_style_vector
from vector import store as vector_store

logger = logging.getLogger(__name__)

SIMILARITY_THRESHOLD = 0.82


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _mean_vector(vectors: list[dict]) -> dict | None:
    """Compute the element-wise mean of a list of style vectors."""
    if not vectors:
        return None

    first = vectors[0]
    result: dict[str, Any] = {}

    for key in first:
        if key.startswith("_"):
            continue
        sample = first[key]
        if isinstance(sample, dict):
            all_subkeys: set[str] = set()
            for v in vectors:
                if key in v and isinstance(v[key], dict):
                    all_subkeys.update(v[key].keys())
            subdict: dict[str, float] = {}
            for subkey in all_subkeys:
                vals = [
                    v[key][subkey]
                    for v in vectors
                    if key in v and isinstance(v[key], dict) and subkey in v[key]
                ]
                subdict[subkey] = sum(vals) / len(vals) if vals else 0.0
            result[key] = subdict
        else:
            vals_scalar = [
                float(v[key])
                for v in vectors
                if key in v and isinstance(v[key], (int, float))
            ]
            result[key] = sum(vals_scalar) / len(vals_scalar) if vals_scalar else 0.0

    return result


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def build_actor_profile(texts: list[str]) -> dict | None:
    """
    Compute mean style vector across all provided texts.

    Filters out texts shorter than 100 chars. Returns None if no valid
    texts remain after filtering.
    """
    valid_vectors: list[dict] = []
    for text in texts:
        if text and len(text) >= 100:
            vec = extract_style_vector(text)
            if vec is not None:
                valid_vectors.append(vec)

    if not valid_vectors:
        return None

    profile = _mean_vector(valid_vectors)
    if profile is not None:
        profile["_sample_count"] = len(valid_vectors)
        profile["_total_chars"] = sum(len(t) for t in texts if t)
    return profile


def update_profile(existing_profile: dict, new_texts: list[str]) -> dict:
    """
    Incrementally update a profile with new text samples.

    Uses a running mean — does not require storing all historical texts.
    """
    new_vectors: list[dict] = []
    for text in new_texts:
        if text and len(text) >= 100:
            vec = extract_style_vector(text)
            if vec is not None:
                new_vectors.append(vec)

    if not new_vectors:
        return existing_profile

    n_old = int(existing_profile.get("_sample_count", 1))
    n_new = len(new_vectors)
    n_total = n_old + n_new

    new_mean = _mean_vector(new_vectors)
    if new_mean is None:
        return existing_profile

    result: dict[str, Any] = {}
    all_keys = set(existing_profile.keys()) | set(new_mean.keys())

    for key in all_keys:
        if key.startswith("_"):
            result[key] = existing_profile.get(key)
            continue

        old_val = existing_profile.get(key)
        new_val = new_mean.get(key)

        if old_val is None and new_val is None:
            continue
        elif old_val is None:
            result[key] = new_val
        elif new_val is None:
            result[key] = old_val
        elif isinstance(old_val, dict) and isinstance(new_val, dict):
            all_subkeys = set(old_val.keys()) | set(new_val.keys())
            subdict: dict[str, float] = {}
            for subkey in all_subkeys:
                ov = float(old_val.get(subkey, 0.0))
                nv = float(new_val.get(subkey, 0.0))
                subdict[subkey] = (ov * n_old + nv * n_new) / n_total
            result[key] = subdict
        elif isinstance(old_val, (int, float)) and isinstance(new_val, (int, float)):
            result[key] = (float(old_val) * n_old + float(new_val) * n_new) / n_total
        else:
            result[key] = old_val

    result["_sample_count"] = n_total
    result["_total_chars"] = existing_profile.get("_total_chars", 0) + sum(len(t) for t in new_texts if t)
    return result


def match_against_profiles(
    style_vector: dict,
    top_k: int = 10,
    threshold: float = SIMILARITY_THRESHOLD,
) -> list[dict]:
    """
    Compare a style profile against all stored actor profiles using ANN search.

    Uses ChromaDB approximate nearest neighbor search for O(log n) performance
    instead of O(n) full table scan.
    """
    return vector_store.match_actor_profiles(
        style_vector=style_vector,
        top_k=top_k,
        threshold=threshold,
    )


def save_profile_to_db(
    profile: dict,
    canonical_value: str,
    entity_type: str,
    session: Any,
) -> bool:
    """
    Store or update an actor style profile in the dedicated DB table
    and sync to ChromaDB for ANN search.
    """
    try:
        from db.models import ActorStyleProfile

        existing = (
            session.query(ActorStyleProfile)
            .filter(
                ActorStyleProfile.canonical_value == canonical_value,
                ActorStyleProfile.entity_type == entity_type,
            )
            .first()
        )

        sample_count = int(profile.get("_sample_count", 0))
        total_chars = int(profile.get("_total_chars", 0))
        
        cleaned_vector = {k: v for k, v in profile.items() if not k.startswith("_")}

        actor_id = None
        if existing:
            existing.style_vector = cleaned_vector
            existing.sample_count = sample_count
            existing.total_chars = total_chars
            existing.last_updated = datetime.now(timezone.utc)
            actor_id = existing.id
        else:
            new_profile = ActorStyleProfile(
                canonical_value=canonical_value,
                entity_type=entity_type,
                style_vector=cleaned_vector,
                sample_count=sample_count,
                total_chars=total_chars,
                last_updated=datetime.now(timezone.utc),
            )
            session.add(new_profile)
            session.flush()
            actor_id = new_profile.id
        
        vector_store.upsert_actor_profile(
            actor_id=actor_id,
            style_vector=cleaned_vector,
            username=canonical_value,
            platform=entity_type,
        )
        
        return True
    except Exception as exc:
        logger.error("save_profile_to_db failed: %s", exc)
        return False


def load_profiles_from_db(session: Any) -> dict[str, dict]:
    """
    Load all stored style profiles from the DB.
    Returns {canonical_value: style_vector}
    """
    try:
        from db.models import ActorStyleProfile
        profiles: dict[str, dict] = {}
        for row in session.query(ActorStyleProfile).all():
            profiles[row.canonical_value] = row.style_vector
        return profiles
    except Exception as exc:
        logger.error("load_profiles_from_db failed: %s", exc)
        return {}
