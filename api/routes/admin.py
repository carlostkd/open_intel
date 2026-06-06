"""
Admin routes for Open_Intel API.

Provides administrative endpoints for monitoring and managing the system.
"""

import asyncio
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from api.auth import get_current_user
from search.search import SEARCH_ENGINES
from search.circuit_breaker import get_all_states, record_success, is_open, _engine_failures, _engine_last_success
from sources.seed_manager import get_seed_manager

logger = logging.getLogger(__name__)

router = APIRouter(tags=["admin"])

# In-memory registry of seed-validation jobs.  Persistence isn't required —
# validation is best-effort and ephemeral.
_seed_validation_jobs: dict[str, dict] = {}


@router.get("/circuit-breakers")
async def get_circuit_breakers(current_user=Depends(get_current_user)) -> dict:
    """
    Get the current state of all search engine circuit breakers.
    Returns state, failure count, and last success timestamp for each engine.
    """
    engines = {}
    for engine in SEARCH_ENGINES:
        name = engine["name"]
        failures = _engine_failures.get(name, 0)
        open_state = await is_open(name)
        engines[name] = {
            "state": "open" if open_state else "closed",
            "failure_count": failures,
            "url": engine.get("url", "").split("{")[0]  # strip query param
        }
    return {"engines": engines}


@router.post("/circuit-breakers/{engine_name}/reset", dependencies=[Depends(get_current_user)])
async def reset_circuit_breaker(engine_name: str) -> dict:
    """Reset a circuit breaker to closed state manually."""
    await record_success(engine_name)
    return {"engine": engine_name, "state": "closed", "message": "Circuit breaker reset"}


@router.post("/circuit-breakers/reset-all", dependencies=[Depends(get_current_user)])
async def reset_all_circuit_breakers() -> dict:
    """Reset all circuit breakers to closed state."""
    from search.search import SEARCH_ENGINES
    for engine in SEARCH_ENGINES:
        await record_success(engine["name"])
    return {"reset_count": len(SEARCH_ENGINES), "state": "all closed"}


@router.get("/content-safety/events", dependencies=[Depends(get_current_user)])
async def get_content_safety_events() -> dict:
    """
    Return content safety block event counts for operator review.
    Returns counts only — never the blocked content itself.
    """
    try:
        import os
        if not os.getenv("DATABASE_URL"):
            return {
                "last_24h": {"query_blocked": 0, "url_blocked": 0, "content_blocked": 0},
                "total": {"query_blocked": 0, "url_blocked": 0, "content_blocked": 0},
            }

        from db.session import get_session
        from db.models import ContentSafetyEvent
        from sqlalchemy import func

        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

        event_types = ["query_blocked", "url_blocked", "content_blocked"]

        with get_session() as session:
            last_24h: dict[str, int] = {}
            total: dict[str, int] = {}
            for et in event_types:
                last_24h[et] = int(
                    session.query(func.count(ContentSafetyEvent.id))
                    .filter(
                        ContentSafetyEvent.event_type == et,
                        ContentSafetyEvent.timestamp >= cutoff,
                    )
                    .scalar()
                    or 0
                )
                total[et] = int(
                    session.query(func.count(ContentSafetyEvent.id))
                    .filter(ContentSafetyEvent.event_type == et)
                    .scalar()
                    or 0
                )

        return {"last_24h": last_24h, "total": total}

    except Exception as exc:
        return {
            "error": str(exc)[:200],
            "last_24h": {"query_blocked": 0, "url_blocked": 0, "content_blocked": 0},
            "total": {"query_blocked": 0, "url_blocked": 0, "content_blocked": 0},
        }


# ---------------------------------------------------------------------------
# Seed list management
# ---------------------------------------------------------------------------


class AddSeedBody(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    url: str = Field(..., min_length=8, max_length=500)
    category: str = Field(default="discovered", max_length=80)
    tags: list[str] = Field(default_factory=list)


async def _run_seed_validation_job(job_id: str) -> None:
    """Background coroutine: validate all seeds and record the result."""
    job = _seed_validation_jobs.setdefault(job_id, {})
    job["status"] = "running"
    job["started_at"] = datetime.now(timezone.utc).isoformat()
    try:
        seed_manager = get_seed_manager()
        results = await seed_manager.validate_seeds(concurrency=3)
        job["status"] = "completed"
        job["results"] = results
    except Exception as exc:
        logger.warning("Seed validation job %s failed: %s", job_id, exc)
        job["status"] = "failed"
        job["error"] = str(exc)[:300]
    finally:
        job["finished_at"] = datetime.now(timezone.utc).isoformat()


@router.get("/seeds", dependencies=[Depends(get_current_user)])
async def get_seeds_summary() -> dict:
    """Return a summary of the seed list: counts by category and status."""
    try:
        seed_manager = get_seed_manager()
        return seed_manager.summary()
    except Exception as exc:
        logger.warning("get_seeds_summary failed: %s", exc)
        return {"total": 0, "by_category": {}, "by_status": {}, "last_validated": None}


@router.get("/seeds/list", dependencies=[Depends(get_current_user)])
async def list_all_seeds() -> dict:
    """Return the full seed list (admin only)."""
    try:
        seed_manager = get_seed_manager()
        return {"seeds": seed_manager.list_seeds()}
    except Exception as exc:
        logger.warning("list_all_seeds failed: %s", exc)
        return {"seeds": []}


@router.post("/seeds/validate", dependencies=[Depends(get_current_user)])
async def trigger_seed_validation() -> dict:
    """
    Trigger a background validation of every seed over Tor.
    Returns a job_id so callers can poll status.
    """
    seed_manager = get_seed_manager()
    seed_count = len(seed_manager.list_seeds())
    job_id = str(uuid.uuid4())
    _seed_validation_jobs[job_id] = {
        "status": "queued",
        "queued_at": datetime.now(timezone.utc).isoformat(),
        "seed_count": seed_count,
    }
    asyncio.create_task(_run_seed_validation_job(job_id))
    return {
        "job_id": job_id,
        "message": f"Validation started for {seed_count} seeds",
    }


@router.get("/seeds/validate/{job_id}", dependencies=[Depends(get_current_user)])
async def get_seed_validation_status(job_id: str) -> dict:
    """Poll the status of a seed-validation job."""
    job = _seed_validation_jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Validation job not found")
    return {"job_id": job_id, **job}


@router.post("/seeds/add", dependencies=[Depends(get_current_user)])
async def add_seed(body: AddSeedBody) -> dict:
    """Manually add a seed URL to the catalogue."""
    seed_manager = get_seed_manager()
    added = seed_manager.add_discovered_seed(
        url=body.url,
        name=body.name,
        tags=body.tags,
        category=body.category,
    )
    if not added:
        raise HTTPException(
            status_code=400,
            detail="Seed not added (duplicate URL or blocked by content safety)",
        )
    return {"added": True, "url": body.url, "category": body.category}