"""
extractor/pipeline.py — Pipeline orchestrator for entity extraction.

Single entry point that the rest of the system calls.  Runs:
    1. Regex extraction  (extractor/regex_patterns.py)
    2. NER extraction    (extractor/ner.py)
    3. LLM extraction    (extractor/llm_extract.py)  — optional
    4. Normalisation     (extractor/normalizer.py)
    5. DB persistence    (extractor/normalizer.merge_with_db)

Public interface
----------------
async extract_entities_from_page(...)   → ExtractionResult
async extract_entities_from_pages(...)  → list[ExtractionResult]

ExtractionResult is a dataclass exported through extractor/__init__.py.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Optional
import uuid

from extractor.regex_patterns import extract_all as _regex_extract_all
from extractor.ner import extract_named_entities as _ner_extract
from extractor.llm_extract import extract_with_llm as _llm_extract
from extractor.normalizer import normalize_entities as _normalize, merge_with_db as _merge_db, NormalizedEntity, resolve_entity_type_conflicts as _resolve_conflicts

logger = logging.getLogger(__name__)

PER_TYPE_CAPS = {
    "ORGANIZATION_NAME": 50,
    "PERSON_NAME": 30,
    "LOCATION": 20,
    "THREAT_ACTOR_HANDLE": 80,
}

_ENTITY_TYPE_PRIORITY = {
    1: frozenset({"CVE", "CVE_NUMBER", "IP_ADDRESS", "IPV6_ADDRESS", "FILE_HASH", "FILE_HASH_MD5", "FILE_HASH_SHA1", "FILE_HASH_SHA256", "FILE_HASH_SHA512", "ONION_URL", "DOMAIN", "DOMAIN_NAME"}),
    2: frozenset({"MALWARE_FAMILY", "RANSOMWARE_GROUP", "THREAT_ACTOR", "THREAT_ACTOR_HANDLE"}),
    3: frozenset({"BITCOIN_ADDRESS", "MONERO_ADDRESS", "ETHEREUM_ADDRESS", "WALLET"}),
    4: frozenset({"EMAIL_ADDRESS", "PGP_KEY_BLOCK"}),
    5: frozenset({"ORGANIZATION_NAME", "PERSON_NAME"}),
}


def _type_priority(entity_type: str) -> int:
    for priority, types in _ENTITY_TYPE_PRIORITY.items():
        if entity_type in types:
            return priority
    return 99

# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class ExtractionResult:
    page_url: str
    entity_count: int
    entities_by_type: dict[str, int] = field(default_factory=dict)
    entity_ids: list = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    entities: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


async def extract_entities_from_page(
    page_text: str,
    page_url: str,
    page_id: Optional[int] = None,
    investigation_id: Optional[uuid.UUID] = None,
    llm=None,
    run_llm_extraction: bool = False,
    disable_cache: Optional[bool] = None,
    persist: bool = True,
) -> ExtractionResult:
    """
    Run the full extraction pipeline for a single page.

    Each stage is wrapped in its own try/except so a failure in one stage
    never prevents later stages from running.  Non-fatal errors are collected
    in ExtractionResult.errors.

    Set persist=False to skip DB persistence (used when collecting entities
    for batch capping before write).
    """
    errors: list[str] = []

    # -----------------------------------------------------------------------
    # Stage 1 — Regex
    # -----------------------------------------------------------------------
    try:
        regex_entities = _regex_extract_all(page_text)
    except Exception as exc:
        logger.error("Regex extraction failed for %s: %s", page_url, exc)
        errors.append(f"regex: {exc}")
        regex_entities = {}

    # -----------------------------------------------------------------------
    # Stage 2 — NER
    # -----------------------------------------------------------------------
    try:
        ner_entities = _ner_extract(page_text)
    except Exception as exc:
        logger.error("NER extraction failed for %s: %s", page_url, exc)
        errors.append(f"ner: {exc}")
        ner_entities = {}

    # Merge regex + NER (regex results take precedence for shared types)
    combined: dict[str, list[str]] = dict(regex_entities)
    for entity_type, values in ner_entities.items():
        if entity_type in combined:
            combined[entity_type] = _dedup(combined[entity_type] + values)
        else:
            combined[entity_type] = list(values)

    # -----------------------------------------------------------------------
    # Stage 3 — LLM (optional)
    # -----------------------------------------------------------------------
    if run_llm_extraction and llm is not None:
        try:
            import hashlib
            page_hash = hashlib.sha256(page_text.encode()).hexdigest() if page_text else None
            combined = await _llm_extract(
                page_text, llm, combined, page_hash=page_hash, disable_cache=disable_cache
            )
        except Exception as exc:
            logger.error("LLM extraction failed for %s: %s", page_url, exc)
            errors.append(f"llm: {exc}")

    # -----------------------------------------------------------------------
    # Stage 4 — Normalise
    # -----------------------------------------------------------------------
    try:
        normalized = _normalize(combined, page_url, page_id, page_text=page_text)
    except Exception as exc:
        logger.error("Normalization failed for %s: %s", page_url, exc)
        errors.append(f"normalize: {exc}")
        normalized = []

    # -----------------------------------------------------------------------
    # Build result (no DB persist yet if persist=False)
    # -----------------------------------------------------------------------
    entities_by_type: dict[str, int] = {}
    for entity in normalized:
        entities_by_type[entity.entity_type] = (
            entities_by_type.get(entity.entity_type, 0) + 1
        )

    if not persist:
        return ExtractionResult(
            page_url=page_url,
            entity_count=len(normalized),
            entities_by_type=entities_by_type,
            entity_ids=[],
            errors=errors,
            entities=normalized,
        )

    # -----------------------------------------------------------------------
    # Stage 5 — DB persist
    # -----------------------------------------------------------------------
    try:
        entity_ids = _merge_db(normalized, investigation_id)
    except Exception as exc:
        logger.error("DB persist failed for %s: %s", page_url, exc)
        errors.append(f"db: {exc}")
        entity_ids = []

    return ExtractionResult(
        page_url=page_url,
        entity_count=len(normalized),
        entities_by_type=entities_by_type,
        entity_ids=entity_ids,
        errors=errors,
    )


async def extract_entities_from_pages(
    pages: list[dict],
    investigation_id: Optional[uuid.UUID] = None,
    llm=None,
    run_llm_extraction: bool = False,
    max_concurrent: int = 5,
    disable_cache: Optional[bool] = None,
    entity_cap: int = 400,
) -> list[ExtractionResult]:
    """
    Run extraction concurrently across a list of pages.

    Each page dict must have at least a "url" key.  Content is read from
    "text", "content", or "cleaned_text" keys (first found wins).

    A semaphore limits concurrency to *max_concurrent* simultaneous pages.
    One page failing never blocks others — failures are captured in each
    page's ExtractionResult.errors.

    Before DB persistence, applies entity cap (default 400) ranked by:
    confidence (primary), entity type priority (secondary), occurrence count (tertiary).
    """
    semaphore = asyncio.Semaphore(max_concurrent)

    async def _process(page: dict) -> ExtractionResult:
        async with semaphore:
            url = page.get("url", "")
            text = (
                page.get("text")
                or page.get("content")
                or page.get("cleaned_text")
                or ""
            )
            try:
                return await extract_entities_from_page(
                    page_text=text,
                    page_url=url,
                    page_id=page.get("page_id"),
                    investigation_id=investigation_id,
                    llm=llm,
                    run_llm_extraction=run_llm_extraction,
                    disable_cache=disable_cache,
                    persist=False,
                )
            except Exception as exc:
                logger.error("Page processing failed for %s: %s", url, exc)
                return ExtractionResult(
                    page_url=url,
                    entity_count=0,
                    entities_by_type={},
                    entity_ids=[],
                    errors=[str(exc)],
                )

    results = list(await asyncio.gather(*[_process(p) for p in pages]))

    all_normalized: list[NormalizedEntity] = []
    for result in results:
        all_normalized.extend(result.entities)

    if not all_normalized:
        return results

    all_normalized = _resolve_conflicts(all_normalized)

    # -----------------------------------------------------------------------
    # Content safety: drop prohibited entity values before capping/storing.
    # Only text-based types are checked; technical IOCs are never filtered.
    # The actual value is never logged — only type and count.
    # -----------------------------------------------------------------------
    from utils.content_safety import is_blocked_entity_value as _is_blocked_entity_value
    clean_entities: list[NormalizedEntity] = []
    blocked_entity_count = 0
    for _ent in all_normalized:
        if _is_blocked_entity_value(_ent.entity_type, _ent.value):
            blocked_entity_count += 1
            logger.debug(
                "Entity value blocked — prohibited content: type=%s",
                _ent.entity_type,
            )
        else:
            clean_entities.append(_ent)
    if blocked_entity_count > 0:
        logger.info(
            "Blocked %d entities for prohibited content",
            blocked_entity_count,
        )
    all_normalized = clean_entities

    capped_entities, original_count = apply_entity_cap(
        all_normalized, cap=entity_cap, investigation_id=investigation_id
    )

    if capped_entities:
        try:
            entity_id_map = _merge_db(capped_entities, investigation_id)
            url_to_ids: dict[str, list] = {}
            for ent, eid in zip(capped_entities, entity_id_map):
                if ent.source_url not in url_to_ids:
                    url_to_ids[ent.source_url] = []
                url_to_ids[ent.source_url].append(eid)

            for result in results:
                result.entity_ids = url_to_ids.get(result.page_url, [])
                result.entities = [e for e in capped_entities if e.source_url == result.page_url]
        except Exception as exc:
            logger.error("Batch entity persist failed: %s", exc)

    return results


# ---------------------------------------------------------------------------
# Entity cap logic
# ---------------------------------------------------------------------------

def _occurrence_count(entity: NormalizedEntity, all_entities: list[NormalizedEntity]) -> int:
    """Count how many times this entity value appears across all pages."""
    count = 0
    for other in all_entities:
        if other.entity_type == entity.entity_type and other.value == entity.value:
            count += 1
    return count


def _apply_per_type_caps(
    entities: list[NormalizedEntity],
    caps: dict = PER_TYPE_CAPS,
) -> list[NormalizedEntity]:
    """
    Apply per-type sub-caps before the global cap.

    This prevents high-volume low-specificity entity types (e.g., ORGANIZATION_NAME)
    from crowding out high-value IOCs (FILE_HASH, CVE, MITRE_TECHNIQUE).
    """
    type_counts: dict[str, int] = {}
    result: list[NormalizedEntity] = []

    for entity in entities:
        etype = entity.entity_type
        cap = caps.get(etype, float("inf"))
        count = type_counts.get(etype, 0)
        if count < cap:
            result.append(entity)
            type_counts[etype] = count + 1
        else:
            logger.debug(f"Per-type cap: {etype} capped at {cap}")

    return result


def apply_entity_cap(
    entities: list[NormalizedEntity],
    cap: int = 400,
    investigation_id: Optional[uuid.UUID] = None,
) -> tuple[list[NormalizedEntity], int]:
    """
    Apply quality-based entity filtering and hard cap.

    Steps:
    a) Remove any entity where confidence < 0.80
    b) Apply per-type sub-caps (see _apply_per_type_caps)
    c) Apply per-investigation hard cap of *cap* entities, ranked by:
       - confidence score (primary, descending)
       - entity type priority (secondary, ascending - lower number = higher priority)
       - occurrence count across pages (tertiary, descending)
    d) Log a warning when cap is applied

    Returns: (capped_entities, original_count)
    """
    original_count = len(entities)

    # Step a: confidence filter
    filtered = [e for e in entities if e.confidence >= 0.80]
    removed_confidence = original_count - len(filtered)
    if removed_confidence:
        logger.warning(f"Entity confidence filter removed {removed_confidence} low-confidence entities")

    # Count occurrences per entity (by type+value)
    for ent in filtered:
        ent._occurrence = _occurrence_count(ent, filtered)

    # Step b: per-type sub-caps
    filtered = _apply_per_type_caps(filtered)

    # Step c: sort and cap
    if len(filtered) > cap:
        filtered.sort(key=lambda e: (-e.confidence, _type_priority(e.entity_type), -e._occurrence))
        filtered = filtered[:cap]
        logger.warning(
            f"Entity cap applied: {original_count} entities reduced to {len(filtered)} "
            f"for investigation {investigation_id}"
        )

    # Clean up temporary attribute
    for ent in filtered:
        if hasattr(ent, "_occurrence"):
            del ent._occurrence

    return filtered, original_count


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------


def _dedup(values) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for v in values:
        if v not in seen:
            seen.add(v)
            result.append(v)
    return result
