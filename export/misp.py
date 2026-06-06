"""
export/misp.py — Generates MISP event JSON from a Open_Intel investigation.

MISP format is constructed directly as a dict — no MISP library required.
The format follows the MISP standard event structure as documented at
https://www.misp-standard.org/rfc/misp-core-format.html

Public interface
----------------
investigation_to_misp_event(investigation_id) → dict
misp_event_to_json(event)                     → str
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Entity type → MISP attribute mapping
# ---------------------------------------------------------------------------

_MISP_ATTR_MAP: dict[str, dict] = {
    "BITCOIN_ADDRESS": {
        "type": "btc",
        "category": "Financial fraud",
        "to_ids": True,
    },
    "ETHEREUM_ADDRESS": {
        "type": "other",
        "category": "Financial fraud",
        "to_ids": True,
    },
    "MONERO_ADDRESS": {
        "type": "other",
        "category": "Financial fraud",
        "to_ids": True,
    },
    "EMAIL_ADDRESS": {
        "type": "email-src",
        "category": "Network activity",
        "to_ids": False,
    },
    "ONION_URL": {
        "type": "url",
        "category": "Network activity",
        "to_ids": True,
    },
    "IP_ADDRESS": {
        "type": "ip-dst",
        "category": "Network activity",
        "to_ids": True,
    },
    "CVE_NUMBER": {
        "type": "vulnerability",
        "category": "External analysis",
        "to_ids": False,
    },
    "MALWARE_FAMILY": {
        "type": "malware-type",
        "category": "Antivirus detection",
        "to_ids": False,
    },
    "RANSOMWARE_GROUP": {
        "type": "malware-type",
        "category": "Antivirus detection",
        "to_ids": False,
    },
    "THREAT_ACTOR_HANDLE": {
        "type": "threat-actor",
        "category": "Attribution",
        "to_ids": False,
    },
}


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def investigation_to_misp_event(
    investigation_id: Any,
    entity_ids: Optional[list[str]] = None,
) -> dict:
    """
    Build a MISP-compatible event dict for the given investigation.

    Returns a valid (but empty-attribute) event if the investigation is not found.
    Never raises.
    """
    investigation, entities = _load_investigation_and_entities(
        investigation_id, entity_ids=entity_ids
    )

    if investigation is None:
        return {
            "Event": {
                "info": "Not found",
                "Attribute": [],
            }
        }

    date_str = _utc_date_str(investigation.created_at)
    query = getattr(investigation, "query", "") or ""

    attributes: list[dict] = []
    for entity in entities:
        mapping = _MISP_ATTR_MAP.get(entity.entity_type)
        if mapping is None:
            continue
        attr = {
            "type": mapping["type"],
            "category": mapping["category"],
            "value": entity.value,
            "comment": f"Source: {entity.source_url}" if entity.source_url else "Source: unknown",
            "to_ids": mapping["to_ids"],
        }
        attributes.append(attr)

    return {
        "Event": {
            "info": f"Open_Intel Investigation: {query}",
            "date": date_str,
            "threat_level_id": "2",   # Medium
            "analysis": "2",           # Completed
            "distribution": "0",       # Your organisation only
            "Attribute": attributes,
        }
    }


def misp_event_to_json(event: dict) -> str:
    """
    Return JSON string of a MISP event dict (pretty-printed, 2-space indent).
    """
    try:
        return json.dumps(event, indent=2, default=str)
    except Exception as exc:
        logger.warning("misp_event_to_json failed: %s", exc)
        return json.dumps({"Event": {"info": "Not found", "Attribute": []}}, indent=2)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _load_investigation_and_entities(
    investigation_id: Any,
    entity_ids: Optional[list[str]] = None,
):
    """
    Load the investigation record and its entities from DB.

    Includes entities owned directly by the investigation AND entities linked
    via InvestigationEntityLink (canonical dedup junction table).

    Returns (investigation, entities) or (None, []) on error / not found.
    """
    import uuid as _uuid

    if not os.getenv("DATABASE_URL"):
        return None, []

    try:
        from db.session import get_session  # noqa: PLC0415
        from db.queries import get_investigation_by_id_or_run  # noqa: PLC0415
        from db.models import Entity, InvestigationEntityLink  # noqa: PLC0415
        from extractor.normalizer import NormalizedEntity  # noqa: PLC0415

        inv_uuid = _coerce_uuid(investigation_id)
        if inv_uuid is None:
            return None, []

        filter_uuids: Optional[list[_uuid.UUID]] = None
        if entity_ids:
            filter_uuids = []
            for raw in entity_ids:
                try:
                    filter_uuids.append(_uuid.UUID(str(raw)))
                except (ValueError, AttributeError):
                    continue

        with get_session() as session:
            investigation = get_investigation_by_id_or_run(session, inv_uuid)
            if investigation is None:
                return None, []

            linked_ids_subq = (
                session.query(InvestigationEntityLink.entity_id)
                .filter(InvestigationEntityLink.investigation_id == investigation.id)
                .subquery()
            )
            db_entities = (
                session.query(Entity)
                .filter(
                    (Entity.investigation_id == investigation.id)
                    | Entity.id.in_(linked_ids_subq)
                )
                .all()
            )

            if filter_uuids is not None:
                want = frozenset(filter_uuids)
                db_entities = [e for e in db_entities if e.id in want]

            normalized: list[NormalizedEntity] = []
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
                )
                normalized.append(ne)

            session.expunge_all()
            return investigation, normalized

    except Exception as exc:
        logger.warning("_load_investigation_and_entities failed: %s", exc)
        return None, []


def _coerce_uuid(value: Any):
    """Coerce value to uuid.UUID. Returns None on failure."""
    import uuid as _uuid
    if isinstance(value, _uuid.UUID):
        return value
    try:
        return _uuid.UUID(str(value))
    except (ValueError, AttributeError):
        return None


def _utc_date_str(dt: Optional[Any]) -> str:
    """Format a datetime as YYYY-MM-DD string. Defaults to today on None."""
    if dt is None:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")
    try:
        return dt.strftime("%Y-%m-%d")
    except Exception:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")
