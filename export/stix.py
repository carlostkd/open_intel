"""
export/stix.py — Converts Open_Intel entities and investigations into STIX 2.1 bundles.

Uses the stix2 Python library throughout; no manual JSON construction.

Public interface
----------------
entity_to_stix_indicator(entity)                                    → stix2.Indicator | None
entity_to_stix_malware(entity)                                      → stix2.Malware | None
entity_to_stix_threat_actor(entity)                                 → stix2.ThreatActor | None
investigation_to_stix_bundle(investigation_id, include_relationships) → stix2.Bundle
bundle_to_json(bundle)                                              → str
bundle_to_dict(bundle)                                              → dict
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Optional, Union
import uuid

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Graceful import of stix2
# ---------------------------------------------------------------------------

try:
    import stix2  # type: ignore
    _STIX2_AVAILABLE = True
except ImportError:
    stix2 = None  # type: ignore
    _STIX2_AVAILABLE = False
    logger.warning(
        "stix2 not installed — export/stix.py functions will return None / empty Bundle"
    )


# ---------------------------------------------------------------------------
# STIX pattern templates per entity type
# ---------------------------------------------------------------------------

_STIX_PATTERNS: dict[str, str] = {
    "BITCOIN_ADDRESS":   "[cryptocurrency-wallet:address = '{value}']",
    "ETHEREUM_ADDRESS":  "[cryptocurrency-wallet:address = '{value}']",
    "MONERO_ADDRESS":    "[cryptocurrency-wallet:address = '{value}']",
    "EMAIL_ADDRESS":     "[email-message:from_ref.value = '{value}']",
    "ONION_URL":         "[url:value = '{value}']",
    "IP_ADDRESS":        "[ipv4-addr:value = '{value}']",
    "CVE_NUMBER":        "[vulnerability:name = '{value}']",
    "MALWARE_FAMILY":    "[malware:name = '{value}']",
    "RANSOMWARE_GROUP":  "[malware:name = '{value}']",
}

# Entity types that map to STIX Malware objects
_MALWARE_TYPES = frozenset({"MALWARE_FAMILY", "RANSOMWARE_GROUP"})

# ---------------------------------------------------------------------------
# Confidence mapping: Open_Intel float → STIX integer (0-100)
# ---------------------------------------------------------------------------


def _to_stix_confidence(confidence: float) -> int:
    return min(100, max(0, int(round(confidence * 100))))


# ---------------------------------------------------------------------------
# Public conversion functions
# ---------------------------------------------------------------------------


def entity_to_stix_indicator(entity: Any) -> Optional[Any]:
    """
    Convert a single NormalizedEntity to a STIX 2.1 Indicator object.

    Returns None for entity types without a clear STIX pattern mapping,
    and returns None (with a warning) if stix2 is not installed.
    """
    if not _STIX2_AVAILABLE:
        return None

    pattern_template = _STIX_PATTERNS.get(entity.entity_type)
    if pattern_template is None:
        return None

    safe_value = entity.value.replace("'", "\\'")
    pattern = pattern_template.format(value=safe_value)

    # Determine indicator_types from entity_type
    indicator_types = ["unknown"]
    etype = entity.entity_type
    if etype in ("MALWARE_FAMILY", "RANSOMWARE_GROUP"):
        indicator_types = ["malicious-activity"]
    elif etype in ("BITCOIN_ADDRESS", "ETHEREUM_ADDRESS", "MONERO_ADDRESS"):
        indicator_types = ["malicious-activity"]
    elif etype in ("IP_ADDRESS", "ONION_URL"):
        indicator_types = ["malicious-activity"]
    elif etype == "CVE_NUMBER":
        indicator_types = ["compromised"]

    try:
        indicator = stix2.Indicator(
            name=f"{entity.entity_type}: {entity.value[:80]}",
            pattern=pattern,
            pattern_type="stix",
            indicator_types=indicator_types,
            confidence=_to_stix_confidence(entity.confidence),
            external_references=(
                [{"source_name": "Open_Intel", "url": entity.source_url}]
                if entity.source_url
                else []
            ),
        )
        return indicator
    except Exception as exc:
        logger.warning("entity_to_stix_indicator failed for %r: %s", entity.value, exc)
        return None


def entity_to_stix_malware(entity: Any) -> Optional[Any]:
    """
    Convert a MALWARE_FAMILY or RANSOMWARE_GROUP entity to a STIX 2.1 Malware object.

    Returns None for all other entity types.
    """
    if not _STIX2_AVAILABLE:
        return None

    if entity.entity_type not in _MALWARE_TYPES:
        return None

    try:
        malware = stix2.Malware(
            name=entity.value,
            is_family=True,
            confidence=_to_stix_confidence(entity.confidence),
            external_references=(
                [{"source_name": "Open_Intel", "url": entity.source_url}]
                if entity.source_url
                else []
            ),
        )
        return malware
    except Exception as exc:
        logger.warning("entity_to_stix_malware failed for %r: %s", entity.value, exc)
        return None


def entity_to_stix_threat_actor(entity: Any) -> Optional[Any]:
    """
    Convert a THREAT_ACTOR_HANDLE entity to a STIX 2.1 ThreatActor object.

    Returns None for all other entity types.
    """
    if not _STIX2_AVAILABLE:
        return None

    if entity.entity_type != "THREAT_ACTOR_HANDLE":
        return None

    try:
        threat_actor = stix2.ThreatActor(
            name=entity.value,
            aliases=[entity.value],
            confidence=_to_stix_confidence(entity.confidence),
            external_references=(
                [{"source_name": "Open_Intel", "url": entity.source_url}]
                if entity.source_url
                else []
            ),
        )
        return threat_actor
    except Exception as exc:
        logger.warning(
            "entity_to_stix_threat_actor failed for %r: %s", entity.value, exc
        )
        return None


def investigation_to_stix_bundle(
    investigation_id: Any,
    include_relationships: bool = True,
    entity_ids: Optional[list[str]] = None,
) -> Any:
    """
    Load all entities for an investigation and return a STIX 2.1 Bundle.

    If include_relationships=True, adds STIX Relationship objects for entity pairs
    that have edges in the graph (loaded via graph.build_graph_from_db).

    Returns an empty Bundle if:
    - stix2 is not installed
    - DATABASE_URL is not set
    - investigation not found
    """
    if not _STIX2_AVAILABLE:
        return _empty_bundle()

    filter_uuids: Optional[list[uuid.UUID]] = None
    if entity_ids:
        filter_uuids = []
        for raw in entity_ids:
            try:
                filter_uuids.append(uuid.UUID(str(raw)))
            except (ValueError, AttributeError):
                continue
        if not filter_uuids:
            return _empty_bundle()

    entities = _load_entities_for_investigation(investigation_id, entity_ids=filter_uuids)
    if not entities:
        return _empty_bundle()

    stix_objects: list[Any] = []
    stix_id_map: dict[str, str] = {}  # entity.value → stix_object.id

    for entity in entities:
        indicator = entity_to_stix_indicator(entity)
        if indicator:
            stix_objects.append(indicator)
            stix_id_map[entity.value] = indicator.id

        malware = entity_to_stix_malware(entity)
        if malware:
            stix_objects.append(malware)
            stix_id_map.setdefault(entity.value, malware.id)

        actor = entity_to_stix_threat_actor(entity)
        if actor:
            stix_objects.append(actor)
            stix_id_map.setdefault(entity.value, actor.id)

    if include_relationships and stix_objects:
        stix_objects.extend(_build_stix_relationships(investigation_id, stix_id_map))

    try:
        return stix2.Bundle(*stix_objects, allow_custom=True)
    except Exception as exc:
        logger.warning("investigation_to_stix_bundle: Bundle construction failed: %s", exc)
        return _empty_bundle()


def bundle_to_json(bundle: Any) -> str:
    """Return JSON string of a STIX bundle (pretty-printed, 2-space indent)."""
    if not _STIX2_AVAILABLE or bundle is None:
        return "{}"
    try:
        return bundle.serialize(pretty=True, indent=2)
    except Exception as exc:
        logger.warning("bundle_to_json failed: %s", exc)
        return "{}"


def bundle_to_dict(bundle: Any) -> dict:
    """Return a plain Python dict representation of the bundle (no stix2 objects)."""
    if not _STIX2_AVAILABLE or bundle is None:
        return {}
    try:
        raw = bundle_to_json(bundle)
        return json.loads(raw)
    except Exception as exc:
        logger.warning("bundle_to_dict failed: %s", exc)
        return {}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _empty_bundle() -> Any:
    """Return an empty STIX Bundle, or a plain dict sentinel if stix2 absent."""
    if not _STIX2_AVAILABLE:
        return None
    try:
        return stix2.Bundle(allow_custom=True)
    except Exception:
        return stix2.Bundle()


def _load_entities_for_investigation(
    investigation_id: Any,
    entity_ids: Optional[list[uuid.UUID]] = None,
) -> list[Any]:
    """
    Load entities from DB for the given investigation_id.

    Includes entities owned directly by the investigation AND entities linked
    via InvestigationEntityLink (canonical dedup junction table).

    Returns [] if DATABASE_URL is not set, investigation not found, or any error.
    """
    if not os.getenv("DATABASE_URL"):
        return []

    try:
        from db.session import get_session  # noqa: PLC0415
        from db.queries import get_investigation_by_id_or_run  # noqa: PLC0415
        from db.models import Entity, InvestigationEntityLink  # noqa: PLC0415
        from extractor.normalizer import NormalizedEntity  # noqa: PLC0415

        inv_uuid = _coerce_uuid(investigation_id)
        if inv_uuid is None:
            return []

        with get_session() as session:
            inv = get_investigation_by_id_or_run(session, inv_uuid)
            if inv is None:
                return []

            linked_ids_subq = (
                session.query(InvestigationEntityLink.entity_id)
                .filter(InvestigationEntityLink.investigation_id == inv.id)
                .subquery()
            )
            q = session.query(Entity).filter(
                (Entity.investigation_id == inv.id)
                | Entity.id.in_(linked_ids_subq)
            )
            db_entities = q.all()

            if entity_ids is not None:
                want = frozenset(entity_ids)
                db_entities = [e for e in db_entities if e.id in want]

            result: list[NormalizedEntity] = []
            for e in db_entities:
                source_url = ""
                try:
                    if e.page:
                        source_url = e.page.url or ""
                except Exception:
                    pass
                ne = NormalizedEntity(
                    entity_type=e.entity_type,
                    value=e.canonical_value or e.value,
                    confidence=e.confidence,
                    source_url=source_url,
                    page_id=e.page_id,
                    context_snippet=e.context_snippet or "",
                    extraction_method="db",
                )
                result.append(ne)
        return result

    except Exception as exc:
        logger.warning("_load_entities_for_investigation failed: %s", exc)
        return []


def _build_stix_relationships(
    investigation_id: Any,
    stix_id_map: dict[str, str],
) -> list[Any]:
    """
    Build STIX Relationship objects from graph edges for the investigation.

    Returns [] on any error.
    """
    if not _STIX2_AVAILABLE:
        return []
    try:
        from graph.builder import build_graph_from_db  # noqa: PLC0415

        inv_uuid = _coerce_uuid(investigation_id)
        graph = build_graph_from_db(investigation_id=inv_uuid)

        relationships: list[Any] = []
        for source_node, target_node, data in graph.edges(data=True):
            src_stix_id = stix_id_map.get(source_node)
            tgt_stix_id = stix_id_map.get(target_node)
            if not src_stix_id or not tgt_stix_id:
                continue
            edge_type = data.get("edge_type", "related-to")
            # Map Open_Intel edge types to STIX relationship types
            rel_type = _edge_type_to_stix(edge_type)
            try:
                rel = stix2.Relationship(
                    relationship_type=rel_type,
                    source_ref=src_stix_id,
                    target_ref=tgt_stix_id,
                )
                relationships.append(rel)
            except Exception:
                continue
        return relationships
    except Exception as exc:
        logger.warning("_build_stix_relationships failed: %s", exc)
        return []


def _edge_type_to_stix(edge_type: str) -> str:
    """Map Open_Intel graph edge types to STIX relationship type strings."""
    mapping = {
        "CO_APPEARED_ON": "related-to",
        "POSTED_BY": "attributed-to",
        "LINKED_TO": "related-to",
        "PAID_TO": "related-to",
        "MEMBER_OF": "member-of",
        "USED": "uses",
        "CLAIMED": "attributed-to",
        "LIKELY_SAME_ACTOR": "related-to",
        "CONFIRMED_SAME_ACTOR": "related-to",
        "FUNDED_BY": "related-to",
    }
    return mapping.get(edge_type, "related-to")


def _coerce_uuid(value: Any) -> Optional[uuid.UUID]:
    """Try to coerce an arbitrary value to uuid.UUID. Returns None on failure."""
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError):
        return None
