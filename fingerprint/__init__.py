"""
fingerprint — Writing style fingerprinting for threat actor identification.

Public interface
---------------
from fingerprint.stylometry import extract_style_vector, compute_similarity, are_likely_same_author
from fingerprint.profiler   import build_actor_profile, update_profile, match_against_profiles
from fingerprint.profiler   import load_profiles_from_db, save_profile_to_db
"""

from fingerprint.profiler import (
    build_actor_profile,
    load_profiles_from_db,
    match_against_profiles,
    save_profile_to_db,
    update_profile,
)
from fingerprint.stylometry import (
    are_likely_same_author,
    compute_similarity,
    extract_style_vector,
)

__all__ = [
    "extract_style_vector",
    "compute_similarity",
    "are_likely_same_author",
    "build_actor_profile",
    "update_profile",
    "match_against_profiles",
    "load_profiles_from_db",
    "save_profile_to_db",
]
