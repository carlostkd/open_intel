"""
api/routes/search.py — Semantic and full-text search endpoints.

POST /search/semantic   — vector similarity search against scraped pages
POST /search/entities   — full-text search across entity values in DB
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from api.auth import CurrentUser, get_current_user

logger = logging.getLogger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class SemanticSearchRequest(BaseModel):
    query: str
    n_results: int = 10
    offset: int = 0


class EntitySearchRequest(BaseModel):
    query: str
    entity_types: Optional[list[str]] = None
    offset: int = 0
    limit: int = 50


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/semantic")
async def semantic_search(
    body: SemanticSearchRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    """
    Return semantically similar pages from the vector store.
    Uses ChromaDB + sentence-transformers embeddings.
    Supports pagination via offset/n_results.
    """
    try:
        from vector.search import find_related_pages
        from vector.store import count_pages

        results = find_related_pages(body.query, n_results=body.n_results)
        total = count_pages()
        
        if not isinstance(results, list):
            results = []

        user_inv_ids: set[str] = set()
        if os.getenv("DATABASE_URL"):
            try:
                from db.session import get_session  # noqa: PLC0415
                from db.models import Investigation  # noqa: PLC0415

                with get_session() as session:
                    rows = (
                        session.query(Investigation.id)
                        .filter(Investigation.user_id == current_user.user.id)
                        .all()
                    )
                    user_inv_ids = {str(r[0]) for r in rows}
            except Exception as exc:
                logger.warning("semantic_search: failed to load user inv IDs: %s", exc)

        results = [
            r for r in results
            if str(r.get("metadata", {}).get("investigation_id", "")) in user_inv_ids
        ]

        return {
            "items": results,
            "total": total,
            "offset": body.offset,
            "n_results": body.n_results,
        }
    except Exception as exc:
        logger.warning("semantic_search failed: %s", exc)
        return {"items": [], "total": 0, "offset": 0, "n_results": 10}


@router.post("/entities")
async def search_entities(
    body: EntitySearchRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> list[dict]:
    """
    Full-text search across entity values in DB.
    Optionally filter by entity_types list.
    Supports pagination via offset/limit.
    """
    if not os.getenv("DATABASE_URL"):
        return []
    try:
        from db.session import get_session  # noqa: PLC0415
        from db.models import Entity, Investigation, InvestigationEntityLink  # noqa: PLC0415
        import sqlalchemy as sa  # noqa: PLC0415

        limit = max(1, min(body.limit, 200))
        offset = max(0, body.offset)

        with get_session() as session:
            user_inv_ids = (
                session.query(Investigation.id)
                .filter(Investigation.user_id == current_user.user.id)
                .subquery()
            )
            linked_entity_ids = (
                session.query(InvestigationEntityLink.entity_id)
                .filter(InvestigationEntityLink.investigation_id.in_(user_inv_ids))
                .subquery()
            )
            q = session.query(Entity).filter(
                sa.or_(
                    Entity.investigation_id.in_(user_inv_ids),
                    Entity.id.in_(linked_entity_ids),
                ),
                Entity.value.contains(body.query),
            )
            if body.entity_types:
                q = q.filter(Entity.entity_type.in_(body.entity_types))
            total = q.count()
            entities = q.order_by(Entity.created_at.desc()).offset(offset).limit(limit).all()
            return {
                "items": [
                    {
                        "id": str(e.id),
                        "entity_type": e.entity_type,
                        "value": e.value,
                        "confidence": e.confidence,
                        "investigation_id": str(e.investigation_id) if e.investigation_id else None,
                        "created_at": e.created_at.isoformat() if e.created_at else None,
                    }
                    for e in entities
                ],
                "total": total,
                "offset": offset,
                "limit": limit,
            }
    except Exception as exc:
        logger.warning("search_entities failed: %s", exc)
        return {"items": [], "total": 0, "offset": 0, "limit": 50}
