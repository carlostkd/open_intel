"""
cli/adapters/sqlite.py — SQLite persistence layer for the CLI.

Reuses the existing SQLAlchemy ORM (db.models) and engine factory
(db.session) by setting DATABASE_URL=sqlite:///~/.open_intel/investigations.db
before any Open_Intel module is imported (cli.config.apply_env).

This adapter wraps that infrastructure with CLI-friendly helpers:
init_db()              — create tables on first run (no Alembic)
save_investigation()   — create an Investigation row
update_investigation() — patch fields on an existing row
list_investigations()  — recent runs
get_investigation()    — single row by id
get_entities()         — entities for an investigation, optionally filtered
get_relationships()    — edges for an investigation
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Optional, Union

from sqlalchemy import text


def init_db() -> None:
    """Create all tables on the SQLite file if missing. Idempotent."""
    from db.models import Base
    from db.session import get_engine
    engine = get_engine()
    Base.metadata.create_all(engine)

    # Create page_extraction_cache table if missing
    with engine.connect() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS page_extraction_cache (
                page_hash TEXT PRIMARY KEY,
                entities_json TEXT NOT NULL,
                extracted_at TIMESTAMP NOT NULL,
                expires_at TIMESTAMP NOT NULL
            )
        """))
        conn.commit()


def _serialize_dt(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _coerce_expires_at(expires_at: Union[str, datetime]) -> datetime:
    """SQLite returns TIMESTAMP columns as strings; normalize for comparisons."""
    if isinstance(expires_at, str):
        expires_at = datetime.fromisoformat(expires_at)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at


def get_page_extraction_cache(page_hash: str) -> Optional[dict[str, list[str]]]:
    """Load cached LLM extraction results when present and not expired."""
    try:
        from db.session import get_session
    except Exception:
        return None

    try:
        with get_session() as session:
            row = session.execute(
                text(
                    """
                    SELECT entities_json, expires_at
                    FROM page_extraction_cache
                    WHERE page_hash = :page_hash
                    """
                ),
                {"page_hash": page_hash},
            ).fetchone()

        if row is None:
            return None

        entities_json, expires_at = row[0], row[1]
        expires_at = _coerce_expires_at(expires_at)
        if expires_at < datetime.now(timezone.utc):
            return None

        return json.loads(entities_json)
    except Exception:
        return None


def save_investigation(
    query: str,
    refined_query: Optional[str] = None,
    model_used: Optional[str] = None,
    status: str = "running",
) -> str:
    """Insert a new Investigation row, return its id (string UUID)."""
    from db.models import Investigation
    from db.session import get_session

    inv_id = uuid.uuid4()
    run_id = uuid.uuid4()
    with get_session() as session:
        inv = Investigation(
            id=inv_id,
            run_id=run_id,
            query=query,
            refined_query=refined_query,
            model_used=model_used,
            status=status,
            user_id=None,
        )
        session.add(inv)
    return str(inv_id)


def update_investigation(investigation_id: str, updates: dict[str, Any]) -> None:
    from db.models import Investigation
    from db.session import get_session

    inv_uuid = uuid.UUID(investigation_id)
    allowed = {
        "status",
        "refined_query",
        "model_used",
        "preset",
        "summary",
        "graph_status",
        "current_step",
        "current_step_label",
        "entity_count",
        "page_count",
    }
    patch = {k: v for k, v in updates.items() if k in allowed}
    if not patch:
        return
    with get_session() as session:
        session.query(Investigation).filter_by(id=inv_uuid).update(patch)


def resolve_investigation_id(prefix_or_full: str) -> Optional[str]:
    """Accept a full UUID or a unique prefix; return the full UUID string."""
    from db.models import Investigation
    from db.session import get_session

    try:
        u = uuid.UUID(prefix_or_full)
        return str(u)
    except (ValueError, AttributeError):
        pass

    p = prefix_or_full.strip().lower()
    if not p:
        return None
    with get_session() as session:
        rows = session.query(Investigation).all()
        matches = [str(r.id) for r in rows if str(r.id).startswith(p)]
    if len(matches) == 1:
        return matches[0]
    return None


def get_investigation(investigation_id: str) -> Optional[dict[str, Any]]:
    from db.models import Investigation
    from db.session import get_session

    full = resolve_investigation_id(investigation_id) or investigation_id
    try:
        inv_uuid = uuid.UUID(full)
    except (ValueError, AttributeError):
        return None
    with get_session() as session:
        inv = session.query(Investigation).filter_by(id=inv_uuid).one_or_none()
        if inv is None:
            return None
        return _investigation_row(inv)


def list_investigations(limit: int = 50) -> list[dict[str, Any]]:
    from db.models import Investigation
    from db.session import get_session

    with get_session() as session:
        rows = (
            session.query(Investigation)
            .order_by(Investigation.created_at.desc())
            .limit(limit)
            .all()
        )
        return [_investigation_row(r) for r in rows]


def _investigation_row(inv) -> dict[str, Any]:
    return {
        "id": str(inv.id),
        "query": inv.query,
        "refined_query": inv.refined_query,
        "status": inv.status,
        "model_used": inv.model_used,
        "summary": inv.summary,
        "entity_count": inv.entity_count,
        "page_count": inv.page_count,
        "created_at": _serialize_dt(inv.created_at),
        "current_step": inv.current_step,
        "current_step_label": inv.current_step_label,
    }


def get_entities(
    investigation_id: str,
    entity_types: Optional[list[str]] = None,
    limit: int = 1000,
) -> list[dict[str, Any]]:
    from db.models import Entity
    from db.session import get_session

    full = resolve_investigation_id(investigation_id) or investigation_id
    inv_uuid = uuid.UUID(full)
    with get_session() as session:
        q = session.query(Entity).filter(Entity.investigation_id == inv_uuid)
        if entity_types:
            q = q.filter(Entity.entity_type.in_(entity_types))
        rows = q.limit(limit).all()
        return [_entity_row(r) for r in rows]


def _entity_row(e) -> dict[str, Any]:
    return {
        "id": str(e.id),
        "entity_type": e.entity_type,
        "value": e.value,
        "canonical_value": e.canonical_value,
        "confidence": float(e.confidence) if e.confidence is not None else None,
        "context_snippet": e.context_snippet,
        "extraction_method": e.extraction_method,
        "source_count": e.source_count,
        "corroborating_sources": e.corroborating_sources,
        "first_seen": _serialize_dt(e.first_seen),
        "last_seen": _serialize_dt(e.last_seen),
    }


def get_relationships(investigation_id: str, limit: int = 5000) -> list[dict[str, Any]]:
    from db.models import EntityRelationship
    from db.session import get_session

    full = resolve_investigation_id(investigation_id) or investigation_id
    inv_uuid = uuid.UUID(full)
    with get_session() as session:
        rows = (
            session.query(EntityRelationship)
            .filter(EntityRelationship.investigation_id == inv_uuid)
            .limit(limit)
            .all()
        )
        return [
            {
                "id": str(r.id),
                "entity_a_id": str(r.entity_a_id),
                "entity_b_id": str(r.entity_b_id),
                "relationship_type": r.relationship_type,
                "confidence": float(r.confidence) if r.confidence is not None else None,
            }
            for r in rows
        ]


def save_relationships(investigation_id: str, edges: list[dict[str, Any]]) -> int:
    """Bulk-insert co-occurrence edges; ignores duplicate (a,b,type) triples."""
    from db.models import EntityRelationship
    from db.session import get_session

    inv_uuid = uuid.UUID(investigation_id)
    written = 0
    if not edges:
        return 0
    with get_session() as session:
        existing = {
            (str(r.entity_a_id), str(r.entity_b_id), r.relationship_type)
            for r in session.query(EntityRelationship)
            .filter(EntityRelationship.investigation_id == inv_uuid)
            .all()
        }
        for edge in edges:
            key = (edge.get("entity_a_id"), edge.get("entity_b_id"), edge.get("relationship_type"))
            if not all(key) or key in existing:
                continue
            try:
                row = EntityRelationship(
                    entity_a_id=uuid.UUID(edge["entity_a_id"]),
                    entity_b_id=uuid.UUID(edge["entity_b_id"]),
                    relationship_type=edge["relationship_type"],
                    confidence=float(edge.get("confidence", 1.0)),
                    investigation_id=inv_uuid,
                )
                session.add(row)
                existing.add(key)
                written += 1
            except Exception:
                continue
    return written


def investigation_to_export_dict(investigation_id: str) -> dict[str, Any]:
    """Full export dict: investigation + entities + relationships."""
    full = resolve_investigation_id(investigation_id) or investigation_id
    inv = get_investigation(full)
    if inv is None:
        return {}
    entities = get_entities(full)
    relationships = get_relationships(full)
    return {
        "investigation": inv,
        "entities": entities,
        "relationships": relationships,
    }


def write_json_export(investigation_id: str, path) -> None:
    data = investigation_to_export_dict(investigation_id)
    from pathlib import Path
    Path(path).write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
