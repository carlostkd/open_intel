"""
api/routes/investigations.py — Investigation management endpoints.

POST /investigations          — trigger an investigation (background task)
GET  /investigations          — list recent investigations
GET  /investigations/{id}     — get single investigation
GET  /investigations/{id}/entities — list entities for investigation
GET  /investigations/{id}/graph    — graph JSON for investigation
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import csv
import hashlib
import io
import logging
import os
import uuid
from typing import Any, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, validator
from sqlalchemy import select as sa_select
from crawler import crawl
from sources.seeds import get_seeds
from sources.seed_manager import get_seed_manager
from sources.paste_scraper import scrape_paste_sites
from sources.github_scraper import scrape_github
from sources.gitlab_scraper import scrape_gitlab
from sources.rss_scraper import scrape_rss_feeds

# Paste-site hostnames used for counting paste-sourced pages in responses.
PASTE_SITE_HOSTNAMES = (
    "pastebin.com",
    "rentry.co",
    "dpaste.org",
    "paste.ee",
)

# Opt-out toggle for the parallel paste site scraper (read at task time so
# tests can monkey-patch the env var without re-importing this module).
def _paste_scraping_enabled() -> bool:
    return os.getenv("PASTE_SCRAPING_ENABLED", "true").lower() == "true"


def _github_scraping_enabled() -> bool:
    return os.getenv("GITHUB_SCRAPING_ENABLED", "true").lower() == "true"


def _gitlab_scraping_enabled() -> bool:
    return os.getenv("GITLAB_SCRAPING_ENABLED", "true").lower() == "true"


def _rss_scraping_enabled() -> bool:
    return os.getenv("RSS_FEEDS_ENABLED", "true").lower() == "true"
from api.auth import CurrentUser, get_current_user, require_password_not_reset_pending
import json

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
router = APIRouter()

# In-process cache: investigation_id (str) → infrastructure clusters list.
# Populated during the pipeline run; read by the GET detail endpoint.
_infra_cluster_cache: dict[str, list] = {}

# In-process cache: investigation_id (str) → sources_used status dict.
# Populated during the pipeline run; read by the GET detail endpoint.
_sources_used_cache: dict[str, dict] = {}

# Cooperative cancellation flags: investigation_id (str) → True when cancel requested.
# Checked at pipeline checkpoints; cleared once the pipeline honours the request.
# Falls back cleanly in multi-process deployments (each worker has its own dict;
# cancellation works as long as the pipeline task runs in the same process as the
# cancel HTTP request, which is true for single-worker FastAPI/uvicorn).
_cancel_flags: dict[str, bool] = {}


def _is_cancelled(investigation_id: str) -> bool:
    return _cancel_flags.get(investigation_id, False)


def _set_cancelled(investigation_id: str) -> None:
    _cancel_flags[investigation_id] = True


def _clear_cancel_flag(investigation_id: str) -> None:
    _cancel_flags.pop(investigation_id, None)


async def _check_cancelled(inv_uuid: uuid.UUID, investigation_id: str) -> bool:
    """Return True and mark investigation cancelled in DB if cancellation was requested."""
    if not _is_cancelled(investigation_id):
        return False
    _clear_cancel_flag(investigation_id)
    logger.info("[%s] Cancellation flag detected — stopping pipeline cleanly", inv_uuid)
    from db.models import Investigation
    from db.session import get_session
    with get_session() as session:
        session.query(Investigation).filter_by(id=inv_uuid).update({"status": "cancelled"})
        session.commit()
    return True

# ---------------------------------------------------------------------------
# Rate limiting (shared key_func with api/main.py; enforcement via app.state.limiter)
# ---------------------------------------------------------------------------

_DISABLE_RATE_LIMIT = os.getenv("DISABLE_RATE_LIMIT", "false").lower() == "true"

if not _DISABLE_RATE_LIMIT:
    try:
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        _limiter: "Limiter | None" = Limiter(key_func=get_remote_address)
    except ImportError:
        _limiter = None
else:
    _limiter = None


def _rate_limit(limit_string: str):
    """Return a slowapi rate-limit decorator, or a pass-through when disabled."""
    if _limiter is None:
        return lambda f: f
    return _limiter.limit(limit_string)


STEP_LABELS = {
    1: "Refining query",
    2: "Searching dark web",
    3: "Filtering results",
    4: "Scraping pages",
    5: "Extracting entities",
    6: "Enriching intelligence",
    7: "Building graph",
    8: "Generating summary",
    9: "Finalizing results",
}


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------


class InvestigationRequest(BaseModel):
    query: str = Field(..., min_length=3, max_length=500, description="Search query (3-500 chars)")
    model: str = Field(default="openrouter/deepseek/deepseek-chat", description="LLM model ID to use")
    run_crawler: bool = False

    @validator("query")
    def query_not_whitespace(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Query cannot be empty or whitespace")
        if len(v.strip()) < 3:
            raise ValueError("Query must be at least 3 characters")
        return v.strip()


# ---------------------------------------------------------------------------
# Helper: load investigation from DB
# ---------------------------------------------------------------------------


def _count_paste_pages_for_investigation(session, internal_id) -> tuple[int, list[str]]:
    """
    Count distinct paste-site pages observed for *internal_id* and return the
    list of paste sources that contributed at least one page.

    Implementation: paste pages are persisted as rows in the `pages` table
    with their paste-site URL, and entities extracted from those pages are
    linked back to the investigation via Entity.investigation_id.  We join
    Entity → Page and filter by hostname instead of adding a DB column.
    """
    try:
        from db.models import Entity, Page

        rows = (
            session.query(Page.url)
            .join(Entity, Entity.page_id == Page.id)
            .filter(Entity.investigation_id == internal_id)
            .distinct()
            .all()
        )
    except Exception as exc:
        logger.debug("paste-page count failed: %s", exc)
        return 0, []

    paste_urls: set[str] = set()
    sources_used: set[str] = set()
    for (url,) in rows:
        if not url:
            continue
        url_lower = url.lower()
        for host in PASTE_SITE_HOSTNAMES:
            if host in url_lower:
                paste_urls.add(url)
                sources_used.add({
                    "pastebin.com": "Pastebin",
                    "rentry.co": "Rentry",
                    "dpaste.org": "dpaste",
                    "paste.ee": "paste.ee",
                }[host])
                break
    return len(paste_urls), sorted(sources_used)


def _get_db_investigation(investigation_id: str) -> Any:
    """Return investigation dict or raise HTTPException 404."""
    if not os.getenv("DATABASE_URL"):
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        from db.session import get_session  # noqa: PLC0415
        from db.queries import (  # noqa: PLC0415
            count_distinct_pages_for_investigation,
            get_investigation_by_id_or_run,
        )

        from sqlalchemy import func  # noqa: PLC0415
        from db.models import Entity, EntityRelationship, InvestigationEntityLink  # noqa: PLC0415

        inv_uuid = uuid.UUID(investigation_id)
        with get_session() as session:
            inv = get_investigation_by_id_or_run(session, inv_uuid)
            if inv is None:
                raise HTTPException(status_code=404, detail="Investigation not found")
            pages_crawled = count_distinct_pages_for_investigation(session, inv.id)
            paste_pages_found, paste_sources_used = _count_paste_pages_for_investigation(
                session, inv.id
            )

            # Entity IDs for this investigation = own entities + junction-table links
            linked_ids_subq = (
                session.query(InvestigationEntityLink.entity_id)
                .filter(InvestigationEntityLink.investigation_id == inv.id)
                .subquery()
            )
            entity_subq = (
                session.query(Entity.id)
                .filter(
                    (Entity.investigation_id == inv.id)
                    | Entity.id.in_(linked_ids_subq)
                )
                .subquery()
            )
            entity_count = int(
                session.query(func.count()).select_from(entity_subq).scalar() or 0
            )
            relationship_count = int(
                session.query(func.count(EntityRelationship.id))
                .filter(
                    (EntityRelationship.entity_a_id.in_(entity_subq))
                    | (EntityRelationship.entity_b_id.in_(entity_subq))
                )
                .scalar()
                or 0
            )
            return {
                "id": str(inv.id),
                "run_id": str(inv.run_id),
                "query": inv.query,
                "refined_query": inv.refined_query,
                "model_used": inv.model_used,
                "preset": inv.preset,
                "summary": inv.summary,
                "status": inv.status,
                "graph_status": getattr(inv, "graph_status", "pending"),
                "created_at": inv.created_at.isoformat() if inv.created_at else None,
                "current_step": inv.current_step or 0,
                "total_steps": 13,
                "current_step_label": inv.current_step_label or "",
                "entity_count": entity_count,
                "relationship_count": relationship_count,
                "page_count": pages_crawled,
                "pages_crawled": pages_crawled,  # keep for compat
                "paste_pages_found": paste_pages_found,
                "paste_sources_used": paste_sources_used,
                "infrastructure_clusters": _infra_cluster_cache.get(investigation_id, _infra_cluster_cache.get(str(inv.id), [])),
                "sources_used": _sources_used_cache.get(str(inv.id), _sources_used_cache.get(investigation_id, {})),
            }
    except HTTPException:
        raise
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid investigation ID format")
    except Exception as exc:
        logger.exception("_get_db_investigation failed: %s", exc)
        raise HTTPException(
            status_code=500,
            detail=f"Internal error: {exc!s}"[:500],
        )


async def _update_investigation_status(
    investigation_id: uuid.UUID,
    status: str,
    model_used: Optional[str] = None,
    summary: Optional[str] = None,
) -> None:
    """Update investigation status in a short-lived session."""
    from db.session import get_session
    from db.models import Investigation

    with get_session() as session:
        updates: dict[str, Any] = {"status": status}
        if model_used is not None:
            updates["model_used"] = model_used
        if summary is not None:
            updates["summary"] = summary
        session.query(Investigation).filter_by(id=investigation_id).update(updates)
        session.commit()


async def _update_progress(
    investigation_id: uuid.UUID,
    step: Optional[int] = None,
    entity_count: Optional[int] = None,
    scraped_pages: Optional[dict] = None,
    label: Optional[str] = None,
) -> None:
    """Fire-and-forget progress field update. Failures are non-critical."""
    try:
        from db.session import get_session
        from db.models import Investigation

        with get_session() as session:
            inv = session.query(Investigation).filter_by(id=investigation_id).first()
            if inv is None:
                return
            if step is not None:
                inv.current_step = step
                inv.current_step_label = label if label is not None else STEP_LABELS.get(step, "Processing")
            elif label is not None:
                inv.current_step_label = label
            if entity_count is not None:
                inv.entity_count = entity_count
            if scraped_pages is not None:
                inv.page_count = len(scraped_pages)
            session.commit()
    except Exception as e:
        logger.warning("[%s] _update_progress failed (non-critical): %s", investigation_id, e)


async def _get_investigation_model_choice(model: Optional[str]) -> tuple[str, Any]:
    """Get model choices and selected model in a short-lived session."""
    from db.session import get_session
    from open_intel.llm_utils import get_model_choices
    import config as config_module

    with get_session() as session:
        model_choices = get_model_choices()
        if not model_choices:
            raise RuntimeError("No LLM models available")
        selected_model = (
            model
            or config_module.DEFAULT_MODEL
            or "openrouter/deepseek/deepseek-chat"
        )
        return selected_model, model_choices


# ---------------------------------------------------------------------------
# Background task: run investigation pipeline
# ---------------------------------------------------------------------------


def _parse_rate_limit_reset(exc: Exception) -> float:
    """Extract reset timestamp from a 429 error and return seconds to wait."""
    import time, re
    exc_str = str(exc)
    # OpenRouter returns X-RateLimit-Reset as epoch milliseconds in metadata
    match = re.search(r"'X-RateLimit-Reset':\s*'?(\d{13})'?", exc_str)
    if match:
        reset_ms = int(match.group(1))
        wait = (reset_ms / 1000.0) - time.time() + 1.0  # +1s buffer
        return max(wait, 5.0)
    # Fallback: 65s to outlast a 60s/1-min rate-limit window
    return 65.0


async def _llm_with_backoff(fn, *args, max_retries: int = 4, investigation_id: "uuid.UUID | None" = None, **kwargs):
    """Run a synchronous LLM function in a thread, retrying on 429 rate-limit errors."""
    for attempt in range(max_retries):
        try:
            return await asyncio.to_thread(fn, *args, **kwargs)
        except Exception as exc:
            if "429" in str(exc) and attempt < max_retries - 1:
                wait_secs = _parse_rate_limit_reset(exc)
                logger.info(
                    "[LLM] Rate limit hit — waiting %.0fs before retry (attempt %d/%d)",
                    wait_secs, attempt + 1, max_retries,
                )
                if investigation_id is not None:
                    await _update_progress(investigation_id, label=f"Rate limited — retrying in {wait_secs:.0f}s...")
                await asyncio.sleep(wait_secs)
            else:
                raise
    raise RuntimeError("LLM max retries exceeded")


async def _run_investigation_task(
    investigation_id: str, run_id: str, query: str, model: str, run_crawler: bool
) -> None:
    """
    Background task that runs the investigation pipeline.

    The investigation DB record already exists (created by the HTTP handler) with
    status "pending".  This task updates status → processing → completed/failed.

    CRITICAL: Each DB operation uses its own short-lived session that commits
    and closes immediately. No session is held open across asyncio.to_thread()
    calls, which prevents SQLAlchemy session state corruption and connection
    pool exhaustion.

    Errors are logged — never propagated to the caller.
    """
    try:
        if not os.getenv("DATABASE_URL"):
            logger.warning("Background investigation: DATABASE_URL not set, skipping persist")
            return

        from db.models import Investigation
        from db.session import get_session, get_async_session
        from db.queries import update_investigation_summary
        from open_intel.llm import filter_results, generate_summary, get_llm, refine_query
        from open_intel.llm_utils import get_model_choices
        from search.search import _search_async as _search_engines_async, _dedupe_links as _search_dedupe, ENGINE_WEIGHTS as _engine_weights
        from scraper.scrape import scrape_multiple, validate_urls_for_scraping
        from extractor import extract_entities_from_pages

        inv_uuid = uuid.UUID(investigation_id)

        async with get_async_session() as session:
            result = await session.execute(
                sa_select(Investigation).where(Investigation.id == inv_uuid)
            )
            inv_record = result.scalar_one_or_none()
            inv_user_id = inv_record.user_id if inv_record else None

        resolved_keys = {}
        if inv_user_id is not None:
            async with get_async_session() as session:
                from utils.user_keys import resolve_api_key
                for key_name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY",
                                "OPENROUTER_API_KEY", "GROQ_API_KEY", "OTX_API_KEY", "VT_API_KEY"):
                    resolved_keys[key_name] = await resolve_api_key(inv_user_id, key_name, session)

        # ===== STEP 0: Get model choice and mark as processing =====
        selected_model, _ = await _get_investigation_model_choice(model)
        logger.info(
            "Investigation %s: using model '%s'",
            inv_uuid,
            selected_model,
        )
        await _update_investigation_status(inv_uuid, "processing", model_used=selected_model)
        await _update_progress(inv_uuid, 0)
        logger.info("[%s] Starting investigation: %s", inv_uuid, query)

        # ===== STEP 1: Query refinement (no session held) =====
        logger.info("[%s] STEP 1: Refining query...", inv_uuid)
        llm_client = None
        refined_query = query
        try:
            llm_client = get_llm(selected_model, api_keys=resolved_keys)
            refined_query = await _llm_with_backoff(refine_query, llm_client, query, investigation_id=inv_uuid)
            logger.info("[%s] Refined query: %s", inv_uuid, refined_query)
        except Exception as exc:
            logger.exception("[%s] Query refinement failed, using original query: %s", inv_uuid, exc)
            refined_query = query

        def _persist_refined_query():
            with get_session() as session:
                inv = session.query(Investigation).filter_by(id=inv_uuid).first()
                if inv:
                    inv.refined_query = refined_query
                    session.commit()

        await asyncio.to_thread(_persist_refined_query)
        await _update_progress(inv_uuid, 1)
        if await _check_cancelled(inv_uuid, investigation_id):
            return

        # ===== STEP 1.5: Multilingual Query Expansion (no session held) =====
        logger.info("[%s] STEP 1.5: Expanding query to multiple languages...", inv_uuid)
        expanded_queries: dict[str, str] = {"en": refined_query}
        try:
            from i18n.query_expand import expand_query

            expansion = expand_query(refined_query)

            if expansion and isinstance(expansion, dict) and len(expansion) > 1:
                expanded_queries = expansion
                lang_count = len(expanded_queries)
                logger.info(
                    "[%s] Query expanded to %d languages: %s",
                    inv_uuid,
                    lang_count,
                    list(expanded_queries.keys()),
                )
            else:
                logger.info("[%s] Query expansion returned no results, using English only", inv_uuid)

        except ImportError:
            logger.info("[%s] i18n module not available, using English only", inv_uuid)
        except Exception as e:
            logger.info("[%s] Query expansion failed (non-fatal): %s", inv_uuid, e)

        # ===== SEED URL INJECTION (runs before search engine fan-out) =====
        # Curated, known-active .onion intelligence sources are checked first
        # so we always visit relevant leak sites/forums even if search engines
        # don't surface them.  These bypass the LLM filter.
        relevant_seeds: list[dict] = []
        try:
            seed_manager = get_seed_manager()
            relevant_seeds = seed_manager.get_relevant_seeds(
                query=query,
                refined_query=refined_query or "",
                max_seeds=10,
            )
        except Exception as exc:
            logger.info("[%s] Seed manager unavailable (non-fatal): %s", inv_uuid, exc)
            relevant_seeds = []

        seed_urls: list[dict] = []
        if relevant_seeds:
            for s in relevant_seeds:
                url = s.get("url") or ""
                if not url:
                    continue
                seed_urls.append({
                    "link": url,
                    "title": s.get("name", "Seed source"),
                    "source": "seed",
                    "source_type": "seed",
                    "seed_category": s.get("category", "unknown"),
                    "seed_tags": s.get("tags", []),
                })
            categories = sorted({s.get("category", "unknown") for s in relevant_seeds})
            logger.info(
                "[%s] Injecting %d seed URLs into scrape queue (categories: %s)",
                inv_uuid,
                len(seed_urls),
                categories,
            )
            await _update_progress(
                inv_uuid,
                step=2,
                label=f"Checking {len(seed_urls)} known intelligence sources + searching Tor engines",
            )
        else:
            logger.info("[%s] No relevant seeds for query", inv_uuid)

        # ===== STEP 2, 3.5, 4: Parallel Pipeline =====
        logger.info("[%s] STEP 2/3.5/4: Launching Search, Enrichment, and Crawler concurrently...", inv_uuid)

        async def run_search_and_filter() -> list:
            logger.info("[%s] STEP 2: Searching dark web...", inv_uuid)
            
            async def search_single_language(lang_code: str, q: str) -> list[dict]:
                search_query = q.replace(" ", "+")
                logger.info("[%s] Searching [%s]: %s...", inv_uuid, lang_code, search_query[:60])
                try:
                    engine_results = await _search_engines_async(search_query)
                    all_links: list[dict] = []
                    for er in engine_results:
                        weight = 0.5
                        for known in _engine_weights:
                            if known in er.name.lower():
                                weight = _engine_weights[known]
                                break
                        for link in er.links:
                            link["source_engine"] = er.name
                            link["source_weight"] = weight
                            all_links.append(link)
                    lang_results = _search_dedupe(all_links)
                    lang_results.sort(key=lambda r: r.get("source_weight", 0.5), reverse=True)
                    for result in lang_results:
                        result["search_language"] = lang_code
                    return lang_results
                except Exception as e:
                    logger.info("[%s] [%s] search failed: %s", inv_uuid, lang_code, e)
                    return []

            search_tasks = [
                search_single_language(lang, q)
                for lang, q in expanded_queries.items()
            ]
            try:
                results_by_language = await asyncio.wait_for(
                    asyncio.gather(*search_tasks, return_exceptions=True),
                    timeout=180,
                )
            except asyncio.TimeoutError:
                logger.warning("[%s] Multilingual search timed out after 180s, using partial results", inv_uuid)
                results_by_language = []

            all_search_results = []
            seen_urls = set()
            for lang_results in results_by_language:
                if isinstance(lang_results, Exception):
                    continue
                for result in lang_results:
                    url = result.get("link", "")
                    normalized = url.lower().rstrip("/").replace("https://", "http://")
                    if normalized and normalized not in seen_urls:
                        seen_urls.add(normalized)
                        all_search_results.append(result)

            search_results = all_search_results
            logger.info("[%s] Total search results: %d (from %d languages)", inv_uuid, len(search_results), len(expanded_queries))

            if not search_results:
                logger.info("[%s] WARNING: No search results from any language", inv_uuid)

            logger.info("[%s] STEP 3: Filtering results...", inv_uuid)
            if llm_client is None:
                filtered_results = list(search_results[:100])
                logger.info("[%s] LLM unavailable; fallback to top %s search results", inv_uuid, len(filtered_results))
            else:
                try:
                    filtered_results = await _llm_with_backoff(filter_results, llm_client, refined_query, search_results, investigation_id=inv_uuid)
                except Exception as exc:
                    logger.exception("[%s] Filter step failed, falling back: %s", inv_uuid, exc)
                    filtered_results = list(search_results[:100])
            logger.info("[%s] Filtered to %s results", inv_uuid, len(filtered_results))
            
            _urls_to_scrape = list(filtered_results)
            if len(_urls_to_scrape) < 100:
                current_links = {res.get("link") for res in _urls_to_scrape if res.get("link")}
                for res in search_results:
                    if res.get("link") not in current_links:
                        _urls_to_scrape.append(res)
                        current_links.add(res.get("link"))
                    if len(_urls_to_scrape) >= 150:
                        break
            return _urls_to_scrape

        async def run_enrichment() -> list:
            logger.info("[%s] STEP 3.5: Running threat intel enrichment...", inv_uuid)
            try:
                from sources.enrichment import enrich_investigation

                queries_to_enrich = [query]
                if refined_query and refined_query.strip().lower() != query.strip().lower():
                    queries_to_enrich.append(refined_query)

                all_pages: list = []
                seen_urls: set = set()
                for eq in queries_to_enrich:
                    try:
                        # Hard 60s cap per enrichment query — individual requests already have 30s timeouts
                        batch = await asyncio.wait_for(
                            enrich_investigation(
                                query=eq,
                                otx_api_key=resolved_keys.get("OTX_API_KEY") or "",
                            ),
                            timeout=60,
                        )
                        for p in batch:
                            u = p.get("url") or p.get("link") or ""
                            if u not in seen_urls:
                                seen_urls.add(u)
                                all_pages.append(p)
                    except asyncio.TimeoutError:
                        logger.warning("[%s] Enrichment query '%s' timed out after 60s", inv_uuid, eq)
                    except Exception as exc:
                        logger.info("[%s] Enrichment batch failed for '%s': %s", inv_uuid, eq, exc)

                logger.info("[%s] Enrichment: %s pages (tried %s queries)", inv_uuid, len(all_pages), len(queries_to_enrich))
                return all_pages
            except Exception as exc:
                logger.info("[%s] Enrichment failed (non-fatal): %s", inv_uuid, exc)
                return []

        async def run_crawler_task() -> list:
            if not run_crawler:
                logger.info("[%s] STEP 4: Crawler disabled", inv_uuid)
                return []
            try:
                logger.info("[%s] STEP 4: Running recursive crawler...", inv_uuid)
                seeds = await asyncio.to_thread(get_seeds, category="index", query=refined_query)
                seed_urls = [seed["url"] for seed in seeds if seed.get("url")]
                # max_depth=1 and max_pages=20 keep the crawler bounded;
                # 120s hard cap prevents dead Tor circuits from stalling the pipeline
                crawler_result = await asyncio.wait_for(
                    crawl(seed_urls=seed_urls, query=refined_query, max_depth=1, max_pages=20),
                    timeout=120,
                )
                logger.info("[%s] Crawler: %s pages, %s failed", inv_uuid, crawler_result.pages_crawled, crawler_result.pages_failed)
                return [{"link": item.get("url", ""), "title": "Crawler discovery"}
                        for item in crawler_result.results if isinstance(item, dict) and item.get("url")]
            except asyncio.TimeoutError:
                logger.warning("[%s] Crawler timed out after 120s, continuing without crawler results", inv_uuid)
                return []
            except Exception as exc:
                logger.exception("[%s] Crawler failed: %s", inv_uuid, str(exc))
                return []

        async def run_paste_scraping_task() -> list:
            # Clearnet paste-site sweep (Pastebin, dpaste, paste.ee, Rentry).
            # Opt-out via PASTE_SCRAPING_ENABLED=false.
            if not _paste_scraping_enabled():
                logger.info("[%s] Paste sites: disabled via env var", inv_uuid)
                return []
            try:
                paste_max = int(os.getenv("PASTE_MAX_RESULTS", "15") or 15)
            except ValueError:
                paste_max = 15
            try:
                pages = await asyncio.wait_for(
                    scrape_paste_sites(
                        query=query,
                        refined_query=refined_query or "",
                        max_results=paste_max,
                    ),
                    timeout=120,
                )
                logger.info(
                    "[%s] Paste sites: %d pastes found",
                    inv_uuid,
                    len(pages),
                )
                return pages
            except asyncio.TimeoutError:
                logger.warning("[%s] Paste scraping timed out after 120s", inv_uuid)
                return []
            except Exception as exc:
                logger.info("[%s] Paste scraping failed (non-fatal): %s", inv_uuid, exc)
                return []

        async def run_github_scraping_task() -> list:
            # Clearnet GitHub sweep — code search + repo READMEs.
            # Opt-out via GITHUB_SCRAPING_ENABLED=false.
            if not _github_scraping_enabled():
                logger.info("[%s] GitHub: disabled via env var", inv_uuid)
                return []
            try:
                github_max = int(os.getenv("GITHUB_MAX_RESULTS", "15") or 15)
            except ValueError:
                github_max = 15
            try:
                pages = await asyncio.wait_for(
                    scrape_github(
                        query=query,
                        refined_query=refined_query or "",
                        max_results=github_max,
                    ),
                    timeout=180,
                )
                logger.info(
                    "[%s] GitHub: %d files found",
                    inv_uuid,
                    len(pages),
                )
                return pages
            except asyncio.TimeoutError:
                logger.warning("[%s] GitHub scraping timed out after 180s", inv_uuid)
                return []
            except Exception as exc:
                logger.info("[%s] GitHub scraping failed (non-fatal): %s", inv_uuid, exc)
                return []

        async def run_gitlab_scraping_task() -> list:
            # Clearnet GitLab sweep — code search + project READMEs.
            # Opt-out via GITLAB_SCRAPING_ENABLED=false.
            if not _gitlab_scraping_enabled():
                logger.info("[%s] GitLab: disabled via env var", inv_uuid)
                return []
            try:
                gitlab_max = int(os.getenv("GITLAB_MAX_RESULTS", "15") or 15)
            except ValueError:
                gitlab_max = 15
            try:
                pages = await asyncio.wait_for(
                    scrape_gitlab(
                        query=query,
                        refined_query=refined_query or "",
                        max_results=gitlab_max,
                    ),
                    timeout=180,
                )
                logger.info(
                    "[%s] GitLab: %d results found",
                    inv_uuid,
                    len(pages),
                )
                return pages
            except asyncio.TimeoutError:
                logger.warning("[%s] GitLab scraping timed out after 180s", inv_uuid)
                return []
            except Exception as exc:
                logger.info("[%s] GitLab scraping failed (non-fatal): %s", inv_uuid, exc)
                return []

        async def run_rss_scraping_task() -> list:
            if not _rss_scraping_enabled():
                logger.info("[%s] RSS feeds: disabled via env var", inv_uuid)
                return []
            try:
                rss_max = int(os.getenv("RSS_MAX_ARTICLES", "20") or 20)
            except ValueError:
                rss_max = 20
            try:
                pages = await asyncio.wait_for(
                    scrape_rss_feeds(
                        query=query,
                        refined_query=refined_query or "",
                        max_results=rss_max,
                    ),
                    timeout=120,
                )
                logger.info("[%s] RSS feeds: %d articles found", inv_uuid, len(pages))
                return pages
            except asyncio.TimeoutError:
                logger.warning("[%s] RSS scraping timed out after 120s", inv_uuid)
                return []
            except Exception as exc:
                logger.info("[%s] RSS scraping failed (non-fatal): %s", inv_uuid, exc)
                return []

        # Hard 5-minute cap on the entire parallel phase (search + enrichment +
        # crawler + paste scraping + github scraping + gitlab scraping + RSS
        # feeds).  Each inner function also has its own timeout so partial
        # results are preserved even if only one hangs.
        # return_exceptions=True ensures one failing task never cancels the others.
        try:
            _gr = await asyncio.wait_for(
                asyncio.gather(
                    run_search_and_filter(),
                    run_enrichment(),
                    run_crawler_task(),
                    run_paste_scraping_task(),
                    run_github_scraping_task(),
                    run_gitlab_scraping_task(),
                    run_rss_scraping_task(),
                    return_exceptions=True,
                ),
                timeout=300,
            )
        except asyncio.TimeoutError:
            logger.warning("[%s] Parallel phase hit 300s hard cap — using empty results", inv_uuid)
            _gr = [[], [], [], [], [], [], []]

        _source_errors: set[str] = set()

        if isinstance(_gr[0], Exception):
            logger.warning("[%s] Search+filter task raised: %s", inv_uuid, _gr[0])
            _source_errors.add("tor_search")
            search_urls = []
        else:
            search_urls = _gr[0]

        if isinstance(_gr[1], Exception):
            logger.warning("[%s] Enrichment task raised: %s", inv_uuid, _gr[1])
            _source_errors.add("enrichment")
            enrichment_pages = []
        else:
            enrichment_pages = _gr[1]

        if isinstance(_gr[2], Exception):
            logger.warning("[%s] Crawler task raised: %s", inv_uuid, _gr[2])
            crawler_urls = []
        else:
            crawler_urls = _gr[2]

        if isinstance(_gr[3], Exception):
            logger.warning("[%s] Paste scraping task raised: %s", inv_uuid, _gr[3])
            _source_errors.add("paste_sites")
            paste_pages = []
        else:
            paste_pages = _gr[3]

        if isinstance(_gr[4], Exception):
            logger.warning("[%s] GitHub scraping task raised: %s", inv_uuid, _gr[4])
            _source_errors.add("github")
            github_pages = []
        else:
            github_pages = _gr[4]

        if isinstance(_gr[5], Exception):
            logger.warning("[%s] GitLab scraping task raised: %s", inv_uuid, _gr[5])
            _source_errors.add("gitlab")
            gitlab_pages = []
        else:
            gitlab_pages = _gr[5]

        if isinstance(_gr[6], Exception):
            logger.warning("[%s] RSS scraping task raised: %s", inv_uuid, _gr[6])
            _source_errors.add("rss_feeds")
            rss_pages = []
        else:
            rss_pages = _gr[6]

        await _update_progress(inv_uuid, 2)
        if await _check_cancelled(inv_uuid, investigation_id):
            return

        if paste_pages:
            paste_sources_used = sorted({
                p.get("source_name") for p in paste_pages
                if p.get("source_name")
            })
            await _update_progress(
                inv_uuid,
                label=(
                    f"Found {len(paste_pages)} paste site results "
                    f"({', '.join(paste_sources_used)})"
                ),
            )

        # ── sources_used: record which sources ran and what they returned ──────
        _otx_key = (resolved_keys.get("OTX_API_KEY") or "").strip()
        _vt_key = os.getenv("VT_API_KEY", "").strip()
        _st_key = os.getenv("SECURITYTRAILS_API_KEY", "").strip()

        def _src_status(count: int, error_key: str | None = None) -> str:
            if error_key and error_key in _source_errors:
                return "error"
            return f"ok_{count}_results" if count > 0 else "ok_0_results"

        sources_used: dict[str, str] = {}

        # Keyed sources — show "skipped_no_key" when the key is absent
        if not _otx_key:
            sources_used["otx"] = "skipped_no_key"
        else:
            n = sum(1 for p in enrichment_pages if p.get("source") == "alienvault_otx")
            sources_used["otx"] = _src_status(n, "enrichment")

        if not _vt_key:
            sources_used["virustotal"] = "skipped_no_key"
        else:
            n = sum(1 for p in enrichment_pages if p.get("source") == "virustotal")
            sources_used["virustotal"] = _src_status(n, "enrichment")

        sources_used["securitytrails"] = "skipped_no_key" if not _st_key else "skipped_not_implemented"

        # Free enrichment sources
        for _skey, _psrc in [
            ("malwarebazaar", "malwarebazaar"),
            ("threatfox", "threatfox"),
            ("urlhaus", "urlhaus"),
        ]:
            n = sum(1 for p in enrichment_pages if p.get("source") == _psrc)
            sources_used[_skey] = _src_status(n, "enrichment")

        _rl_n = sum(
            1 for p in enrichment_pages
            if p.get("source") == "ransomware_live" and not p.get("_scrape_seed")
        )
        sources_used["ransomware_live"] = _src_status(_rl_n, "enrichment")

        _cisa_n = sum(1 for p in enrichment_pages if p.get("source") in ("cisa_kev", "cisa_advisory"))
        sources_used["cisa"] = _src_status(_cisa_n, "enrichment")

        _shodan_n = sum(1 for p in enrichment_pages if p.get("source") == "shodan_internetdb")
        sources_used["shodan"] = _src_status(_shodan_n, "enrichment")

        # Tor search
        if "tor_search" in _source_errors:
            sources_used["tor_search"] = "error"
        else:
            n = len(search_urls)
            sources_used["tor_search"] = f"ok_{n}_pages" if n > 0 else "ok_0_pages"

        # Clearnet scrapers
        if not _github_scraping_enabled():
            sources_used["github"] = "skipped_disabled"
        elif "github" in _source_errors:
            sources_used["github"] = "error"
        else:
            sources_used["github"] = _src_status(len(github_pages))

        if not _gitlab_scraping_enabled():
            sources_used["gitlab"] = "skipped_disabled"
        elif "gitlab" in _source_errors:
            sources_used["gitlab"] = "error"
        else:
            sources_used["gitlab"] = _src_status(len(gitlab_pages))

        if not _paste_scraping_enabled():
            sources_used["paste_sites"] = "skipped_disabled"
        elif "paste_sites" in _source_errors:
            sources_used["paste_sites"] = "error"
        else:
            sources_used["paste_sites"] = _src_status(len(paste_pages))

        if not _rss_scraping_enabled():
            sources_used["rss_feeds"] = "skipped_disabled"
        elif "rss_feeds" in _source_errors:
            sources_used["rss_feeds"] = "error"
        else:
            sources_used["rss_feeds"] = _src_status(len(rss_pages))

        # DNS, domain, hash, and email reputation placeholders — updated after those steps complete
        sources_used["circl_pdns"] = "pending"
        sources_used["domain_reputation"] = "pending"
        sources_used["hash_reputation"] = "pending"
        sources_used["email_reputation"] = "pending"
        _sources_used_cache[investigation_id] = sources_used
        # ── end sources_used ──────────────────────────────────────────────────

        if len(search_urls) < 2:
            logger.warning(
                "[%s] Filtered results too small (%s INTELLIGENCE pages). "
                "Query may have returned only directory/index pages. "
                "Try a more specific query.",
                inv_uuid,
                len(search_urls),
            )
            no_result_summary = (
                f"Investigation for '{refined_query}' completed but found insufficient "
                f"intelligence content. Only {len(search_urls)} qualifying page(s) remained "
                f"after filtering out directory/index pages. This suggests the query "
                f"returned primarily link aggregators or marketplace indexes rather than "
                f"actual threat intelligence content. Try a more specific, targeted query "
                f"(e.g., specific malware names, actor handles, or infrastructure indicators) "
                f"instead of broad topic searches."
            )
            with get_session() as session:
                session.query(Investigation).filter_by(id=inv_uuid).update(
                    {"status": "completed_no_results", "summary": no_result_summary, "graph_status": "no_data"}
                )
                session.commit()
            logger.info("[%s] Investigation COMPLETED_NO_RESULTS (run_id=%s)", inv_uuid, run_id)
            return

        # Seed .onion leak-site URLs discovered by enrichment (e.g. ransomware.live)
        # into the scrape queue so they get visited even if search engines didn't find them
        enrichment_onion_seeds = [
            {"link": p.get("link") or p.get("url"), "title": p.get("title", "Enrichment seed")}
            for p in enrichment_pages
            if p.get("_scrape_seed") and ".onion" in (p.get("link") or p.get("url") or "")
        ]
        if enrichment_onion_seeds:
            logger.info(
                "[%s] Adding %d .onion seeds from enrichment to scrape queue",
                inv_uuid, len(enrichment_onion_seeds),
            )

        # Seed URLs go first — they're known intelligence sources and skip the LLM filter
        all_urls_to_scrape = seed_urls + search_urls + crawler_urls + enrichment_onion_seeds
        logger.info(
            "[%s] Total URLs to scrape: %s (%s seeds + %s search + %s crawler + %s enrichment)",
            inv_uuid,
            len(all_urls_to_scrape),
            len(seed_urls),
            len(search_urls),
            len(crawler_urls),
            len(enrichment_onion_seeds),
        )

        if enrichment_pages:
            try:
                from vector.store import store_page
                for ep in enrichment_pages:
                    u = ep.get("url") or ep.get("link") or ""
                    t = ep.get("text") or ep.get("content") or ""
                    if u and t:
                        store_page(url=u, content=t, metadata={"source": ep.get("source", "enrichment")})
            except Exception:
                pass

        # ===== STEP 4.5: Vector Cache Lookup (no session held) =====
        logger.info(
            "[%s] STEP 4.5: Checking vector cache for %d URLs...",
            inv_uuid,
            len(all_urls_to_scrape),
        )
        cached_dict: dict = {}
        uncached_url_dicts = list(all_urls_to_scrape)
        try:
            from vector.store import bulk_check_cache

            url_strings = [
                u.get("link", u) if isinstance(u, dict) else str(u)
                for u in all_urls_to_scrape
            ]
            cached_pages_list, urls_needing_scrape = bulk_check_cache(
                url_strings, max_age_hours=24
            )
            cached_dict = {p["link"]: p["content"] for p in cached_pages_list}
            uncached_set = set(urls_needing_scrape)
            uncached_url_dicts = [
                u for u in all_urls_to_scrape
                if (u.get("link", u) if isinstance(u, dict) else str(u))
                in uncached_set
            ]
            logger.info(
                "[%s] Cache: %d hits, %d misses (need Tor)",
                inv_uuid,
                len(cached_dict),
                len(uncached_url_dicts),
            )
        except Exception as exc:
            logger.info("[%s] Cache check failed (non-fatal): %s", inv_uuid, exc)
            cached_dict = {}
            uncached_url_dicts = list(all_urls_to_scrape)

        # ===== STEP 5: Scraping (no session held) =====
        uncached_url_dicts, ssrf_blocked = validate_urls_for_scraping(uncached_url_dicts)
        if ssrf_blocked:
            logger.info(
                "[%s] SSRF: blocked %d unsafe URLs",
                inv_uuid,
                len(ssrf_blocked),
            )
        logger.info(
            "[%s] STEP 5: Scraping %d URLs (skipped %d cached)...",
            inv_uuid,
            len(uncached_url_dicts),
            len(cached_dict),
        )
        freshly_scraped = await scrape_multiple(uncached_url_dicts, max_workers=12)
        await _update_progress(inv_uuid, 4, scraped_pages=freshly_scraped)
        if await _check_cancelled(inv_uuid, investigation_id):
            return

        # ===== STEP 5.5: Store new pages in vector cache (no session held) =====
        try:
            from vector.store import store_page

            stored_count = 0
            for page_url, page_text in freshly_scraped.items():
                if page_text and len(page_text) > 100:
                    if store_page(url=page_url, content=page_text, metadata={"source": "scraper"}):
                        stored_count += 1
            logger.info("[%s] Stored %d new pages in vector cache", inv_uuid, stored_count)
        except Exception as exc:
            logger.info("[%s] Cache store failed (non-fatal): %s", inv_uuid, exc)

        scraped_pages = {**cached_dict, **freshly_scraped}

        # ===== STEP 5.75: Content safety scan (Layer 4) =====
        from utils.content_safety import sanitize_content, log_content_safety_event
        clean_pages: dict[str, str] = {}
        blocked_count = 0
        for page_url, page_text in scraped_pages.items():
            clean_text, was_flagged = sanitize_content(page_text)
            if was_flagged:
                blocked_count += 1
                url_hash = hashlib.sha256(page_url.encode()).hexdigest()[:16]
                logger.warning(
                    "[%s] Page content blocked — prohibited content. Page hash: %s",
                    inv_uuid,
                    url_hash,
                )
                log_content_safety_event(
                    event_type="content_blocked",
                    content_hash=url_hash,
                    user_id=inv_user_id,
                )
            else:
                clean_pages[page_url] = clean_text
        if blocked_count > 0:
            logger.warning(
                "[%s] Blocked %d pages for prohibited content",
                inv_uuid,
                blocked_count,
            )
        scraped_pages = clean_pages

        scraped_count = len(scraped_pages)
        logger.info(
            "[%s] Total for extraction: %d pages (%d cached + %d fresh, %d blocked)",
            inv_uuid,
            scraped_count,
            len(cached_dict),
            len(freshly_scraped),
            blocked_count,
        )

        page_records = [
            {"url": page_url, "text": page_text, "content": page_text}
            for page_url, page_text in scraped_pages.items()
        ]

        if enrichment_pages:
            enrichment_count = 0
            for ep in enrichment_pages:
                u = ep.get("url") or ep.get("link") or ""
                t = ep.get("text") or ep.get("content") or ""
                if u and (t or "").strip():
                    page_records.append({"url": u, "text": t, "content": t})
                    enrichment_count += 1

            logger.info(
                "[%s] Total pages for extraction: %s (%s scraped + %s enrichment)",
                inv_uuid,
                len(page_records),
                scraped_count,
                enrichment_count,
            )
        else:
            logger.info(
                "[%s] Total pages for extraction: %s (%s scraped + 0 enrichment)",
                inv_uuid,
                len(page_records),
                scraped_count,
            )

        # Paste-site pages already have fetched text — bypass scraping and
        # add them directly to the extraction pool, marked with their source.
        if paste_pages:
            paste_added = 0
            for pp in paste_pages:
                u = pp.get("url") or ""
                t = pp.get("text_content") or ""
                if u and t.strip():
                    page_records.append({
                        "url": u,
                        "text": t,
                        "content": t,
                        "source_type": "paste_site",
                        "source_name": pp.get("source_name"),
                    })
                    paste_added += 1
            logger.info(
                "[%s] Added %d paste-site pages to extraction pool",
                inv_uuid,
                paste_added,
            )

        # GitHub pages already have fetched text — bypass scraping and add
        # them directly to the extraction pool, marked source_type="github".
        if github_pages:
            github_added = 0
            for gp in github_pages:
                u = gp.get("url") or ""
                t = gp.get("text_content") or ""
                if u and t.strip():
                    page_records.append({
                        "url": u,
                        "text": t,
                        "content": t,
                        "source_type": "github",
                        "source_name": gp.get("source_name", "GitHub"),
                    })
                    github_added += 1
            logger.info(
                "[%s] Added %d GitHub pages to extraction pool",
                inv_uuid,
                github_added,
            )
        else:
            logger.info("[%s] GitHub: no results", inv_uuid)

        # GitLab pages already have fetched text — bypass scraping and add
        # them directly to the extraction pool, marked source_type="gitlab".
        if gitlab_pages:
            gitlab_added = 0
            for glp in gitlab_pages:
                u = glp.get("url") or ""
                t = glp.get("text_content") or ""
                if u and t.strip():
                    page_records.append({
                        "url": u,
                        "text": t,
                        "content": t,
                        "source_type": "gitlab",
                        "source_name": glp.get("source_name", "GitLab"),
                    })
                    gitlab_added += 1
            logger.info(
                "[%s] Added %d GitLab pages to extraction pool",
                inv_uuid,
                gitlab_added,
            )
        else:
            logger.info("[%s] GitLab: no results", inv_uuid)

        # RSS feed articles are pre-fetched — bypass scraping, add directly
        # to the extraction pool marked source_type="rss_feed".
        if rss_pages:
            rss_added = 0
            for rp in rss_pages:
                u = rp.get("url") or ""
                t = rp.get("text_content") or ""
                if u and t.strip():
                    page_records.append({
                        "url": u,
                        "text": t,
                        "content": t,
                        "source_type": "rss_feed",
                        "source_name": rp.get("source_name", "RSS Feed"),
                        "title": rp.get("title", ""),
                        "published_at": rp.get("published_at", ""),
                    })
                    rss_added += 1
            contributing_feeds = sorted({
                rp.get("source_name", "unknown") for rp in rss_pages
                if rp.get("source_name")
            })
            logger.info(
                "[%s] Added %d RSS articles to extraction pool (feeds: %s)",
                inv_uuid,
                rss_added,
                contributing_feeds,
            )
        else:
            logger.info("[%s] RSS feeds: no relevant articles", inv_uuid)

        non_empty_records = [r for r in page_records if len((r.get("text") or "").strip()) > 100]
        logger.info("[%s] Non-empty pages (>100 chars): %s", inv_uuid, len(non_empty_records))
        if not non_empty_records:
            first_length = len(page_records[0].get("text", "")) if page_records else 0
            logger.info("[%s] WARNING: All scraped pages are empty/short", inv_uuid)
            logger.info("[%s] First page content length: %s", inv_uuid, first_length)

        # ===== STEP 5.7: Detect content languages (no session held) =====
        try:
            from i18n.detect import detect_language

            lang_distribution: dict[str, int] = {}
            for page in page_records:
                text = page.get("content") or page.get("text") or ""
                if len(text) >= 50:
                    lang = detect_language(text[:500])
                    if lang:
                        lang_distribution[lang] = lang_distribution.get(lang, 0) + 1

            if lang_distribution:
                total_pages = sum(lang_distribution.values())
                non_english = {k: v for k, v in lang_distribution.items() if k != "en"}
                logger.info(
                    "[%s] Content languages: %s (%d/%d non-English pages)",
                    inv_uuid,
                    lang_distribution,
                    sum(non_english.values()),
                    total_pages,
                )
        except Exception as e:
            logger.info("[%s] Language detection failed (non-fatal): %s", inv_uuid, e)

        # ===== STEP 6: Entity extraction (no session held) =====
        logger.info("[%s] STEP 6: Extracting entities...", inv_uuid)
        extraction_input = non_empty_records if non_empty_records else page_records
        try:
            extraction_results = await extract_entities_from_pages(
                extraction_input,
                investigation_id=inv_uuid,
                llm=llm_client,
                run_llm_extraction=True,
            )
            total_entities = sum(r.entity_count for r in extraction_results)
            logger.info("[%s] Extracted %s entities", inv_uuid, total_entities)
            if total_entities == 0:
                logger.info("[%s] WARNING: No entities extracted", inv_uuid)
                logger.info(
                    "[%s] Pages passed to extractor: %s",
                    inv_uuid,
                    len(extraction_input),
                )
        except Exception as exc:
            logger.exception("[%s] Extraction failed: %s", inv_uuid, str(exc))
            extraction_results = []
            total_entities = 0

        await _update_progress(inv_uuid, 5, entity_count=total_entities)
        if await _check_cancelled(inv_uuid, investigation_id):
            return

        # ===== STEP 6.1: IP Reputation Enrichment =====
        # Runs after entities are in DB but before the entity cap is applied.
        # Suppresses GreyNoise-benign IPs and boosts confidence for confirmed C2s.
        logger.info("[%s] STEP 6.1: Running IP reputation enrichment...", inv_uuid)
        try:
            from sources.ip_reputation import enrich_ip_entities as _enrich_ips

            extraction_results, _ip_stats = await asyncio.wait_for(
                _enrich_ips(extraction_results, inv_uuid),
                timeout=60,
            )
            total_entities = sum(r.entity_count for r in extraction_results)
            sources_used["ip_reputation"] = _ip_stats.get("ip_reputation", "ok_0_ips")
            _sources_used_cache[investigation_id] = sources_used
            logger.info(
                "[%s] IP reputation: %d checked, %d suppressed, %d C2 confirmed, %d abuse",
                inv_uuid,
                _ip_stats.get("checked", 0),
                _ip_stats.get("suppressed", 0),
                _ip_stats.get("c2_confirmed", 0),
                _ip_stats.get("abuse_confirmed", 0),
            )
        except asyncio.TimeoutError:
            logger.warning("[%s] IP reputation enrichment timed out after 60s", inv_uuid)
            sources_used["ip_reputation"] = "error_timeout"
            _sources_used_cache[investigation_id] = sources_used
        except Exception as _ip_exc:
            logger.info("[%s] IP reputation enrichment failed (non-fatal): %s", inv_uuid, _ip_exc)
            sources_used["ip_reputation"] = "error"
            _sources_used_cache[investigation_id] = sources_used

        # ===== STEP 6.5: Cross-reference against seed data (short-lived session) =====
        logger.info("[%s] STEP 6.5: Cross-referencing with historical data...", inv_uuid)
        try:
            from db.queries import cross_reference_with_seeds

            with get_session() as session:
                seed_matches = cross_reference_with_seeds(session, inv_uuid)
                logger.info("[%s] Found %s historical matches", inv_uuid, seed_matches)
        except Exception as e:
            logger.info("[%s] Cross-reference failed (non-fatal): %s", inv_uuid, e)

        # ===== STEP 6.6: Build Stylometry Profiles (wrapped in to_thread with own session) =====
        logger.info(f"[{inv_uuid}] STEP 6.6: Building actor style profiles...")
        try:
            profiles_built = await asyncio.to_thread(
                _build_investigation_profiles,
                inv_uuid,
            )
            logger.info(f"[{inv_uuid}] Built {profiles_built} actor profiles")
        except Exception as e:
            logger.info(f"[{inv_uuid}] Profile building failed (non-fatal): {e}")

        # ===== STEP 6.7: Blockchain Wallet Enrichment (wrapped in to_thread with own session) =====
        logger.info(f"[{inv_uuid}] STEP 6.7: Enriching wallet entities...")
        try:
            from sources.blockchain import enrich_wallets_for_investigation
            from config import BLOCKCYPHER_TOKEN, ETHERSCAN_API_KEY

            blockchain_stats = await asyncio.to_thread(
                _enrich_wallets_sync,
                inv_uuid,
                BLOCKCYPHER_TOKEN,
                ETHERSCAN_API_KEY,
            )

            logger.info(
                f"[{inv_uuid}] Blockchain enrichment: "
                f"{blockchain_stats['successful_lookups']}/{blockchain_stats['wallets_looked_up']} lookups successful, "
                f"{blockchain_stats['edges_created']} PAID_TO edges created, "
                f"{blockchain_stats['connected_wallets_found']} connected wallets found"
            )
        except Exception as e:
            logger.info(f"[{inv_uuid}] Blockchain enrichment failed (non-fatal): {e}")

        await _update_progress(inv_uuid, 6)

        # ===== STEP 6.8: DNS/WHOIS Enrichment (no session held) =====
        logger.info("[%s] STEP 6.8: Running DNS/WHOIS enrichment...", inv_uuid)
        try:
            from sources.enrichment import run_dns_enrichment

            # Build a flat list of entity dicts from extraction results for DNS lookup.
            # NormalizedEntity dataclasses are converted to the dict format expected by
            # enrich_with_dns (entity_type + canonical_value/value).
            extracted_entities_for_dns: list[dict] = []
            for _r in extraction_results:
                for _e in getattr(_r, "entities", []):
                    if hasattr(_e, "entity_type"):
                        extracted_entities_for_dns.append({
                            "entity_type": _e.entity_type,
                            "canonical_value": _e.value,
                            "value": _e.value,
                            "confidence": _e.confidence,
                        })
                    elif isinstance(_e, dict):
                        extracted_entities_for_dns.append(_e)

            dns_results = await asyncio.wait_for(
                run_dns_enrichment(extracted_entities_for_dns),
                timeout=120,
            )

            new_dns_entities = dns_results.get("new_entities", [])
            if new_dns_entities:
                logger.info(
                    "[%s] DNS enrichment: %d new entities discovered",
                    inv_uuid,
                    len(new_dns_entities),
                )

            clusters = dns_results.get("infrastructure_clusters", [])
            if clusters:
                logger.info(
                    "[%s] Infrastructure clusters found: %d",
                    inv_uuid,
                    len(clusters),
                )
                for cluster in clusters:
                    logger.info("[%s]   %s", inv_uuid, cluster["description"])
                _infra_cluster_cache[investigation_id] = clusters

            _dns_ent_count = len(new_dns_entities)
            sources_used["circl_pdns"] = (
                f"ok_{_dns_ent_count}_enrichments" if _dns_ent_count > 0 else "ok_0_enrichments"
            )
            _sources_used_cache[investigation_id] = sources_used

        except asyncio.TimeoutError:
            logger.warning("[%s] DNS enrichment timed out after 120s", inv_uuid)
            sources_used["circl_pdns"] = "error"
            _sources_used_cache[investigation_id] = sources_used
        except Exception as _dns_exc:
            logger.info("[%s] DNS enrichment failed (non-fatal): %s", inv_uuid, _dns_exc)
            sources_used["circl_pdns"] = "error"
            _sources_used_cache[investigation_id] = sources_used

        # ===== STEP 6.2: Domain Reputation Enrichment =====
        # Runs after DNS enrichment. Enriches DOMAIN entities with:
        #   crt.sh (subdomain enumeration via certificate transparency)
        #   URLScan.io (live scan data, malicious indicators, communicating IPs)
        #   Wayback Machine (historical snapshots for taken-down domains)
        # Non-fatal: if all three sources fail for a domain, entity is unchanged.
        logger.info("[%s] STEP 6.2: Running domain reputation enrichment...", inv_uuid)
        try:
            from sources.domain_reputation import enrich_domain_entities as _enrich_domains

            extraction_results, _dom_stats = await asyncio.wait_for(
                _enrich_domains(extraction_results, inv_uuid),
                timeout=120,
            )
            sources_used["domain_reputation"] = _dom_stats.get(
                "domain_reputation", "ok_0_domains"
            )
            _sources_used_cache[investigation_id] = sources_used
            logger.info(
                "[%s] Domain reputation: %d domains, %d CT records, %d malicious, %d archived",
                inv_uuid,
                _dom_stats.get("domains_checked", 0),
                _dom_stats.get("ct_records", 0),
                _dom_stats.get("urlscan_malicious", 0),
                _dom_stats.get("wayback_archived", 0),
            )
        except asyncio.TimeoutError:
            logger.warning("[%s] Domain reputation enrichment timed out after 120s", inv_uuid)
            sources_used["domain_reputation"] = "error_timeout"
            _sources_used_cache[investigation_id] = sources_used
        except Exception as _dom_exc:
            logger.info("[%s] Domain reputation enrichment failed (non-fatal): %s", inv_uuid, _dom_exc)
            sources_used["domain_reputation"] = "error"
            _sources_used_cache[investigation_id] = sources_used

        # ===== STEP 6.3: Hash Reputation Enrichment =====
        # Runs after domain reputation. Enriches FILE_HASH_* entities with:
        #   Hybrid Analysis (behavioral sandbox — requires HYBRID_ANALYSIS_API_KEY)
        #   MalwareBazaar (family classification — free, no auth)
        #   ThreatFox (IOC database — free, no auth)
        #   VirusTotal extended (AV detections + sandbox IOCs — requires VT_API_KEY)
        # Hashes are never suppressed. Non-fatal: 90s timeout.
        logger.info("[%s] STEP 6.3: Running hash reputation enrichment...", inv_uuid)
        try:
            from sources.hash_reputation import enrich_hash_entities as _enrich_hashes

            extraction_results, _hash_stats = await asyncio.wait_for(
                _enrich_hashes(extraction_results, inv_uuid),
                timeout=90,
            )
            sources_used["hash_reputation"] = _hash_stats.get("hash_reputation", "ok_0_hashes")
            _sources_used_cache[investigation_id] = sources_used
            logger.info(
                "[%s] Hash reputation: %d checked, %d malicious, %d suspicious, "
                "%d families, %d new entities",
                inv_uuid,
                _hash_stats.get("hashes_checked", 0),
                _hash_stats.get("malicious", 0),
                _hash_stats.get("suspicious", 0),
                _hash_stats.get("malware_families_found", 0),
                _hash_stats.get("new_entities_discovered", 0),
            )
        except asyncio.TimeoutError:
            logger.warning("[%s] Hash reputation enrichment timed out after 90s", inv_uuid)
            sources_used["hash_reputation"] = "error_timeout"
            _sources_used_cache[investigation_id] = sources_used
        except Exception as _hash_exc:
            logger.info("[%s] Hash reputation enrichment failed (non-fatal): %s", inv_uuid, _hash_exc)
            sources_used["hash_reputation"] = "error"
            _sources_used_cache[investigation_id] = sources_used

        # ===== STEP 6.4: Email Reputation Enrichment =====
        # Runs after hash reputation. Enriches EMAIL_ADDRESS entities with:
        #   HIBP (breach history — requires HIBP_API_KEY, paid $3.50/mo)
        #   EmailRep.io (reputation scoring — works without key)
        #   Disposable domain blocklist (local check, no auth)
        #   Domain cross-reference (custom email domains added as DOMAIN entities)
        # Non-fatal: 60s timeout.
        logger.info("[%s] STEP 6.4: Running email reputation enrichment...", inv_uuid)
        try:
            from sources.email_reputation import enrich_email_entities as _enrich_emails

            extraction_results, _email_stats = await asyncio.wait_for(
                _enrich_emails(extraction_results, inv_uuid),
                timeout=60,
            )
            sources_used["email_reputation"] = _email_stats.get(
                "email_reputation", "ok_0_emails"
            )
            _sources_used_cache[investigation_id] = sources_used
            logger.info(
                "[%s] Email reputation: %d checked, %d breached, %d passwords exposed, "
                "%d disposable, %d malicious",
                inv_uuid,
                _email_stats.get("emails_checked", 0),
                _email_stats.get("breached", 0),
                _email_stats.get("password_exposed", 0),
                _email_stats.get("disposable", 0),
                _email_stats.get("malicious", 0),
            )
        except asyncio.TimeoutError:
            logger.warning("[%s] Email reputation enrichment timed out after 60s", inv_uuid)
            sources_used["email_reputation"] = "error_timeout"
            _sources_used_cache[investigation_id] = sources_used
        except Exception as _email_exc:
            logger.info(
                "[%s] Email reputation enrichment failed (non-fatal): %s", inv_uuid, _email_exc
            )
            sources_used["email_reputation"] = "error"
            _sources_used_cache[investigation_id] = sources_used

        # ===== STEP 7: Graph building (wrapped in to_thread with own session) =====
        logger.info("[%s] STEP 7: Building graph...", inv_uuid)
        try:
            from graph.builder import build_graph_from_db, persist_graph_edges

            graph_obj = await asyncio.to_thread(build_graph_from_db, investigation_id=inv_uuid)
            node_count = len(graph_obj.nodes())
            edge_count = len(graph_obj.edges())
            logger.info(
                "[%s] Graph: %s nodes, %s edges",
                inv_uuid,
                node_count,
                edge_count,
            )

            try:
                persist_result = await asyncio.to_thread(
                    _persist_graph_edges_sync,
                    graph_obj,
                    inv_uuid,
                )
                graph_status = persist_result.get("status", "written")
                edges_written = persist_result.get("edges_written", 0)
                logger.info(
                    "[%s] Graph edges persisted: %s (%s)",
                    inv_uuid,
                    edges_written,
                    graph_status,
                )

                new_graph_status = "skipped_overflow" if graph_status == "skipped_overflow" else "built"
                with get_session() as session:
                    session.query(Investigation).filter_by(id=inv_uuid).update(
                        {"graph_status": new_graph_status}
                    )
                    session.commit()
            except Exception as e:
                logger.info("[%s] Edge persistence failed (non-fatal): %s", inv_uuid, e)

        except Exception as exc:
            logger.exception("[%s] Graph building failed: %s", inv_uuid, str(exc))

        await _update_progress(inv_uuid, 7)

        # ===== STEP 8: Summary (no session held) =====
        logger.info("[%s] STEP 8: Generating summary (%d pages available)...", inv_uuid, len(page_records))
        if llm_client is None:
            summary = (
                f"Investigation completed without LLM summary. "
                f"Scraped {scraped_count} pages; extracted {total_entities} entities."
            )
        else:
            try:
                summary_entities = []
                if extraction_results:
                    for result in extraction_results:
                        summary_entities.extend(result.entities)

                summary = await _llm_with_backoff(
                    generate_summary,
                    llm=llm_client,
                    query=refined_query,
                    content=page_records,
                    entities=summary_entities if summary_entities else None,
                    investigation_id=inv_uuid,
                )
                logger.info("[%s] Summary generated (%d chars)", inv_uuid, len(summary or ""))
            except Exception as exc:
                logger.exception("[%s] Summary generation failed, using fallback summary: %s", inv_uuid, exc)
                summary = (
                    f"Investigation complete for '{refined_query}'. "
                    f"Analysis pipeline completed successfully, but summary generation failed: {exc}."
                )

        logger.info("[%s] Summary preview: %s", inv_uuid, (summary or "")[:100])

        await _update_progress(inv_uuid, 8)

        # ===== Final: Update summary and mark completed (short-lived session) =====
        with get_session() as session:
            update_investigation_summary(session, inv_uuid, summary)
            session.query(Investigation).filter_by(id=inv_uuid).update(
                {"status": "completed"}
            )
            session.commit()
        await _update_progress(inv_uuid, 9)
        logger.info("[%s] Investigation COMPLETED (run_id=%s)", inv_uuid, run_id)

    except Exception as exc:
        logger.exception("[%s] Investigation FAILED with exception: %s", investigation_id, exc)
        try:
            from db.models import Investigation
            from db.session import get_session

            with get_session() as session:
                session.query(Investigation).filter_by(id=uuid.UUID(investigation_id)).update(
                    {"status": "failed", "summary": f"Investigation failed: {exc!s}"[:500]}
                )
                session.commit()
        except Exception as update_exc:
            logger.warning("Failed to persist investigation failure status: %s", update_exc)


def _enrich_wallets_sync(investigation_id, blockcypher_token, etherscan_key):
    """Sync wrapper for blockchain enrichment - creates its own session."""
    from sources.blockchain import enrich_wallets_for_investigation
    from db.session import get_session

    with get_session() as session:
        return enrich_wallets_for_investigation(
            investigation_id=investigation_id,
            session=session,
            blockcypher_token=blockcypher_token,
            etherscan_key=etherscan_key,
            max_wallets=10,
        )


def _persist_graph_edges_sync(graph_obj, investigation_id):
    """Sync wrapper for graph edge persistence - creates its own session."""
    from graph.builder import persist_graph_edges
    from db.session import get_session

    with get_session() as session:
        return persist_graph_edges(
            graph_obj,
            investigation_id,
            session,
        )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("")
@_rate_limit("3/minute")
async def create_investigation(
    request: Request,
    body: InvestigationRequest,
    background_tasks: BackgroundTasks,
    current_user: CurrentUser = Depends(require_password_not_reset_pending),
) -> dict:
    """Trigger an investigation asynchronously.

    Creates the investigation row in the DB synchronously before returning so
    that GET /investigations/{run_id} returns a valid record immediately while
    the background pipeline runs.
    """
    from utils.content_safety import is_blocked_query, log_content_safety_event

    blocked, reason = is_blocked_query(body.query)
    if blocked:
        logger.warning(
            "Investigation blocked — prohibited content detected. User: %s",
            current_user.user.id,
        )
        log_content_safety_event(
            event_type="query_blocked",
            content_hash=hashlib.sha256(body.query.encode()).hexdigest()[:16],
            user_id=current_user.user.id,
        )
        raise HTTPException(
            status_code=400,
            detail={
                "error": "prohibited_content",
                "message": (
                    "This query cannot be processed. Open_Intel is intended "
                    "for legitimate security research only."
                ),
                "code": "CONTENT_BLOCKED",
            },
        )

    run_id = str(uuid.uuid4())

    if os.getenv("DATABASE_URL"):
        try:
            from db.session import get_session
            from db.queries import create_investigation as db_create

            with get_session() as session:
                inv = db_create(session, query=body.query, user_id=current_user.user.id)
                inv.run_id = uuid.UUID(run_id)
                inv.status = "pending"
                session.commit()
                investigation_id = str(inv.id)
        except Exception as exc:
            logger.exception("Failed to create investigation record: %s", exc)
            raise HTTPException(
                status_code=500,
                detail=f"Could not persist investigation: {exc!s}"[:300],
            )
    else:
        investigation_id = str(uuid.uuid4())

    background_tasks.add_task(
        _run_investigation_task,
        investigation_id=investigation_id,
        run_id=run_id,
        query=body.query,
        model=body.model,
        run_crawler=body.run_crawler,
    )
    return {"run_id": run_id, "status": "pending", "query": body.query}


@router.get("")
async def list_investigations(
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    current_user: "CurrentUser" = Depends(get_current_user),
) -> list[dict]:
    """Return a paginated list of investigation summaries."""
    if not os.getenv("DATABASE_URL"):
        return []
    try:
        from db.session import get_session
        from db.models import Investigation

        with get_session() as session:
            invs = (
                session.query(Investigation)
                .filter(Investigation.is_seed == False)
                .filter(Investigation.user_id == current_user.id)
                .order_by(Investigation.created_at.desc())
                .offset(offset)
                .limit(limit)
                .all()
            )
            return [
                {
                    "id": str(inv.id),
                    "run_id": str(inv.run_id),
                    "query": inv.query,
                    "status": inv.status,
                    "model_used": inv.model_used,
                    "created_at": inv.created_at.isoformat() if inv.created_at else None,
                    "entity_count": inv.entity_count or 0,
                    "page_count": inv.page_count or 0,
                }
                for inv in invs
            ]
    except Exception as exc:
        logger.exception("list_investigations failed: %s", exc)
        return []


@router.post("/{investigation_id}/cancel")
async def cancel_investigation(
    investigation_id: str,
    current_user: "CurrentUser" = Depends(require_password_not_reset_pending),
) -> dict:
    """Request cooperative cancellation of a running investigation.

    Sets a cancellation flag that the pipeline checks at each checkpoint.
    Returns 200 immediately — the pipeline may still be running; poll the
    investigation status to confirm it reaches 'cancelled'.
    Returns 409 if the investigation is already in a terminal state.
    """
    if not os.getenv("DATABASE_URL"):
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        inv_uuid = uuid.UUID(investigation_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid investigation ID format")

    from db.session import get_session
    from db.models import Investigation
    from db.queries import get_investigation_by_id_or_run

    try:
        with get_session() as session:
            inv = get_investigation_by_id_or_run(session, inv_uuid)
            if inv is None:
                raise HTTPException(status_code=404, detail="Investigation not found")
            if str(inv.user_id) != str(current_user.user.id):
                raise HTTPException(status_code=403, detail="Forbidden")
            terminal = {"completed", "failed", "cancelled", "completed_no_results"}
            if inv.status in terminal:
                raise HTTPException(
                    status_code=409,
                    detail=f"Investigation cannot be cancelled (current status: {inv.status})",
                )
            # Set flag by both run_id and inv.id — the pipeline task uses inv.id
            _set_cancelled(investigation_id)
            _set_cancelled(str(inv.id))
            logger.info(
                "[%s] Cancellation requested by user %s",
                inv_uuid,
                current_user.user.id,
            )
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("cancel_investigation failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Internal error: {exc!s}"[:300])

    return _get_db_investigation(investigation_id)


@router.get("/{investigation_id}/progress")
async def investigation_progress(
    investigation_id: str,
    current_user: "CurrentUser" = Depends(get_current_user),
) -> StreamingResponse:
    """
    SSE stream of investigation pipeline progress.
    Emits step updates every 5 seconds until a terminal state is reached.
    """
    from db.session import get_async_session
    from db.models import Investigation

    try:
        inv_uuid = uuid.UUID(investigation_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid investigation ID format")

    # Verify existence and ownership before opening the stream
    async with get_async_session() as session:
        result = await session.execute(sa_select(Investigation).where(Investigation.id == inv_uuid))
        inv_check = result.scalar_one_or_none()
    if inv_check is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    if str(inv_check.user_id) != str(current_user.user.id):
        raise HTTPException(status_code=403, detail="Forbidden")

    async def event_stream():
        last_step = None
        last_status = None
        timeout_count = 0
        max_timeout = 360
        data: dict = {}

        while timeout_count < max_timeout:
            try:
                async with get_async_session() as session:
                    result = await session.execute(
                        sa_select(Investigation).where(Investigation.id == inv_uuid)
                    )
                    inv = result.scalar_one_or_none()
            except Exception:
                break

            if inv is None:
                yield f"data: {json.dumps({'error': 'not_found'})}\n\n"
                break

            step = inv.current_step or 0
            label = inv.current_step_label or ""
            status = inv.status

            if step != last_step or status != last_status:
                data = {
                    "step": step,
                    "total_steps": 13,
                    "label": label,
                    "progress": int((step / 13) * 100),
                    "status": status,
                    "entity_count": inv.entity_count or 0,
                    "page_count": inv.page_count or 0,
                }
                yield f"data: {json.dumps(data)}\n\n"
                last_step = step
                last_status = status

            if status in ("completed", "failed", "completed_no_results", "cancelled"):
                yield f"data: {json.dumps({**data, 'done': True})}\n\n"
                break

            timeout_count += 1
            await asyncio.sleep(5)

        yield ": stream closed\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/{investigation_id}/analysis/temporal")
async def get_temporal_analysis(investigation_id: str) -> dict:
    """
    Run temporal analysis on pages from this investigation.

    Returns activity patterns by hour/day, anomalies, and silence breaks.
    Returns {"error": "insufficient_data"} (not 500) when there is not enough data.
    """
    try:
        inv_uuid = uuid.UUID(investigation_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid investigation ID format")

    if not os.getenv("DATABASE_URL"):
        raise HTTPException(status_code=503, detail="Database not configured")

    try:
        from db.session import get_session
        from db.models import Entity, Page
        from db.queries import get_investigation_by_id_or_run
        from collections import defaultdict
        from analysis.temporal import detect_anomalies, detect_silence_breaks, Z_SCORE_THRESHOLD

        with get_session() as session:
            inv = get_investigation_by_id_or_run(session, inv_uuid)
            if inv is None:
                raise HTTPException(status_code=404, detail="Investigation not found")

            entities = session.query(Entity).filter(
                Entity.investigation_id == inv.id
            ).all()

            if not entities:
                return {
                    "investigation_id": investigation_id,
                    "error": "insufficient_data",
                    "message": "No entities found for this investigation",
                }

            page_ids = list({e.page_id for e in entities if e.page_id is not None})
            if not page_ids:
                return {
                    "investigation_id": investigation_id,
                    "error": "insufficient_data",
                    "message": "No page timestamps available",
                }

            pages = session.query(Page).filter(Page.id.in_(page_ids)).all()
            real_post_ts = sum(1 for p in pages if p.posted_at is not None)
            skipped_no_posted_at = len(pages) - real_post_ts
            if skipped_no_posted_at > 0:
                logger.debug(
                    "Temporal analysis: skipped %d pages due to missing posted_at (using content timestamp, not scrape time)",
                    skipped_no_posted_at,
                )
            timestamps = []
            for p in pages:
                if p.posted_at is not None:
                    timestamps.append(p.posted_at)

            if len(timestamps) < 3:
                return {
                    "investigation_id": investigation_id,
                    "error": "insufficient_data",
                    "message": f"Only {len(timestamps)} timestamps available (minimum 3)",
                    "data_points": len(timestamps),
                }

            by_hour: dict[int, int] = defaultdict(int)
            for ts in timestamps:
                by_hour[ts.hour] += 1
            activity_by_hour = {str(h): int(by_hour.get(h, 0)) for h in range(24)}

            day_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
            by_day: dict[int, int] = defaultdict(int)
            for ts in timestamps:
                by_day[ts.weekday()] += 1
            activity_by_day = {day_names[d]: int(by_day.get(d, 0)) for d in range(7)}

            peak_hour_key = max(activity_by_hour, key=lambda h: activity_by_hour[h], default=None)
            peak_day_key = max(activity_by_day, key=lambda d: activity_by_day[d], default=None)

            daily_counts: dict = defaultdict(int)
            for ts in timestamps:
                daily_counts[ts.date()] += 1
            timeline = [
                {"date": d, "count": c} for d, c in sorted(daily_counts.items())
            ]

            anomalies_raw = detect_anomalies(timeline, z_threshold=Z_SCORE_THRESHOLD)
            anomalies = [
                {
                    "date": str(a["date"]),
                    "count": a["count"],
                    "z_score": round(a["z_score"], 2),
                    "type": a["type"],
                    "description": (
                        f"Activity {'spike' if a['z_score'] > 0 else 'drop'}: "
                        f"z-score {a['z_score']:.1f}"
                    ),
                }
                for a in anomalies_raw
            ]

            silence_raw = detect_silence_breaks(timeline, silence_days=7)
            silence_breaks = [
                {
                    "before": str(s["silent_from"]),
                    "after": str(s["silent_to"]),
                    "gap_days": s["gap_days"],
                    "significance": "high" if s["gap_days"] >= 14 else "medium",
                }
                for s in silence_raw
            ]

            all_dates = sorted(daily_counts.keys())
            timespan_days = (
                (all_dates[-1] - all_dates[0]).days if len(all_dates) >= 2 else 0
            )

            return {
                "investigation_id": investigation_id,
                "activity_by_hour": activity_by_hour,
                "activity_by_day": activity_by_day,
                "anomalies": anomalies,
                "silence_breaks": silence_breaks,
                "peak_hour": int(peak_hour_key) if peak_hour_key is not None else None,
                "peak_day": peak_day_key,
                "total_timespan_days": timespan_days,
                "data_points": len(timestamps),
            }
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("get_temporal_analysis failed: %s", exc)
        return {"error": "analysis_failed", "message": str(exc)[:300]}


@router.get("/{investigation_id}")
async def get_investigation(
    investigation_id: str,
    current_user: "CurrentUser" = Depends(get_current_user),
) -> dict:
    """Return full investigation record including entity count. 404 if not found."""
    if os.getenv("DATABASE_URL"):
        try:
            from db.session import get_session
            from db.queries import get_investigation_by_id_or_run
            inv_uuid = uuid.UUID(investigation_id)
            with get_session() as session:
                inv = get_investigation_by_id_or_run(session, inv_uuid)
                if inv is None:
                    raise HTTPException(status_code=404, detail="Investigation not found")
                if str(inv.user_id) != str(current_user.user.id):
                    raise HTTPException(status_code=403, detail="Forbidden")
        except HTTPException:
            raise
        except ValueError:
            raise HTTPException(status_code=422, detail="Invalid investigation ID format")
    return _get_db_investigation(investigation_id)


@router.get("/{investigation_id}/entities")
async def get_investigation_entities(
    investigation_id: str,
    entity_type: Optional[str] = Query(default=None),
    min_confidence: float = Query(default=0.75, ge=0.0, le=1.0),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    defang: bool = Query(default=True),
    freshness_exclude: Optional[str] = Query(default=None),
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    """Return paginated entities for an investigation, optionally filtered by type and confidence."""
    if not os.getenv("DATABASE_URL"):
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        from db.session import get_session
        from db.models import Entity, InvestigationEntityLink
        from db.queries import get_investigation_by_id_or_run
        from graph.builder import _make_node_id
        from sqlalchemy import func
        from utils.ioc_freshness import get_freshness_tag, get_freshness_display
        from utils.defang import defang_value, defang_text

        inv_uuid = uuid.UUID(investigation_id)
        with get_session() as session:
            inv = get_investigation_by_id_or_run(session, inv_uuid)
            if inv is None:
                raise HTTPException(status_code=404, detail="Investigation not found")
            if str(inv.user_id) != str(current_user.user.id):
                raise HTTPException(status_code=403, detail="Forbidden")

            linked_ids_subq = (
                session.query(InvestigationEntityLink.entity_id)
                .filter(InvestigationEntityLink.investigation_id == inv.id)
                .subquery()
            )
            query = session.query(Entity).filter(
                (Entity.investigation_id == inv.id)
                | Entity.id.in_(linked_ids_subq)
            )
            if entity_type:
                query = query.filter(Entity.entity_type == entity_type)
            if min_confidence > 0.0:
                query = query.filter(Entity.confidence >= min_confidence)

            total = query.count()
            entities = (
                query.order_by(Entity.created_at.desc())
                .offset(offset)
                .limit(limit)
                .all()
            )

            # Safety net: filter prohibited entity values from the response.
            # Catches values that may have been stored before FIX 2 was deployed.
            from utils.content_safety import is_blocked_entity_value as _is_blocked_ev
            entities = [
                e for e in entities
                if not _is_blocked_ev(e.entity_type, e.value)
            ]

            out: list[dict] = []
            for e in entities:
                source_url = ""
                try:
                    if e.page:
                        source_url = e.page.url or ""
                except Exception:
                    pass

                freshness_tag = get_freshness_tag(
                    e.entity_type,
                    e.last_seen_at,
                    e.first_seen_at,
                )

                if freshness_exclude == "expired" and freshness_tag.value == "expired":
                    continue

                graph_node_id = _make_node_id(e.entity_type, e.value, source_url)

                display_value = e.value
                display_context = e.context
                if defang:
                    display_value = defang_value(e.entity_type, e.value or "")
                    if e.context:
                        display_context = defang_text(e.context)

                freshness_display = get_freshness_display(freshness_tag)

                out.append(
                    {
                        "id": str(e.id),
                        "entity_type": e.entity_type,
                        "canonical_value": e.canonical_value,
                        "value": display_value,
                        "confidence": e.confidence,
                        "context_snippet": e.context_snippet,
                        "context": display_context,
                        "created_at": e.created_at.isoformat() if e.created_at else None,
                        "first_seen": e.first_seen.isoformat() if e.first_seen else None,
                        "last_seen": e.last_seen.isoformat() if e.last_seen else None,
                        "first_seen_at": e.first_seen_at.isoformat() if e.first_seen_at else None,
                        "last_seen_at": e.last_seen_at.isoformat() if e.last_seen_at else None,
                        "freshness_tag": freshness_tag.value,
                        "freshness_label": freshness_display["label"],
                        "freshness_color": freshness_display["color"],
                        "source_count": e.source_count or 1,
                        "corroborating_sources": json.loads(e.corroborating_sources or '["dark_web_scrape"]'),
                        "cross_referenced": (e.source_count or 1) > 1,
                        "graph_node_id": graph_node_id,
                        "defanged": defang,
                    }
                )
            return {"items": out, "total": total, "skip": offset, "limit": limit}
    except HTTPException:
        raise
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid investigation ID format")
    except Exception as exc:
        logger.exception("get_investigation_entities failed: %s", exc)
        raise HTTPException(
            status_code=500,
            detail=f"Internal error: {exc!s}"[:500],
        )


@router.get("/{investigation_id}/entities/export/csv")
async def export_investigation_entities_csv(
    investigation_id: str,
    current_user: CurrentUser = Depends(get_current_user),
) -> Response:
    """
    Export entities for an investigation as a CSV file download.

    Returns CSV with columns: entity_type, canonical_value, confidence,
    occurrence_count, first_seen_page, context_snippet
    """
    if not os.getenv("DATABASE_URL"):
        raise HTTPException(status_code=503, detail="Database not configured")

    try:
        inv_uuid = uuid.UUID(investigation_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid investigation ID format")

    try:
        from db.session import get_session
        from db.models import Entity, InvestigationEntityLink
        from db.queries import get_investigation_by_id_or_run
        from sqlalchemy import func

        with get_session() as session:
            inv = get_investigation_by_id_or_run(session, inv_uuid)
            if inv is None:
                raise HTTPException(status_code=404, detail="Investigation not found")
            if str(inv.user_id) != str(current_user.user.id):
                raise HTTPException(status_code=403, detail="Forbidden")

            linked_ids_subq = (
                session.query(InvestigationEntityLink.entity_id)
                .filter(InvestigationEntityLink.investigation_id == inv.id)
                .subquery()
            )
            entities = (
                session.query(Entity)
                .filter(
                    (Entity.investigation_id == inv.id)
                    | Entity.id.in_(linked_ids_subq)
                )
                .all()
            )

            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow([
                "entity_type",
                "canonical_value",
                "confidence",
                "occurrence_count",
                "first_seen_page",
                "context_snippet",
            ])

            for e in entities:
                source_url = ""
                try:
                    if e.page:
                        source_url = e.page.url or ""
                except Exception:
                    pass
                context = (e.context_snippet or "").replace(
                    "\n", " "
                ).replace(
                    "\r", " "
                ).strip()
                writer.writerow([
                    e.entity_type,
                    e.canonical_value or e.value,
                    e.confidence,
                    1,
                    source_url,
                    context[:500],
                ])

            csv_content = output.getvalue()

        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename=open_intel_{investigation_id}_entities.csv"
            },
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("export_investigation_entities_csv failed: %s", exc)
        raise HTTPException(
            status_code=500,
            detail=f"Internal error: {exc!s}"[:500],
        )


MAX_GRAPH_NODES = 500


@router.get("/{investigation_id}/graph")
async def get_investigation_graph(
    investigation_id: str,
    force_rebuild: bool = False,
    max_nodes: int = Query(default=MAX_GRAPH_NODES, ge=1, le=MAX_GRAPH_NODES),
    min_confidence: float = Query(default=0.75, ge=0.0, le=1.0),
) -> dict:
    """
    Return graph JSON for the investigation.

    Requires investigation_id (now enforced - no more global graph).
    Uses persisted edges from the DB with O(1) lookup.

    Use ?force_rebuild=true to recompute from scratch.
    Use ?max_nodes=N to limit node count (default 500, max 500).
    Use ?min_confidence=N to filter nodes/edges by confidence (default 0.75).
    Returns 400 if node count exceeds max_nodes - filter by entity type first.
    Returns 200 with {"graph_status": "skipped_overflow", ...} if graph was skipped due to size.
    """
    try:
        inv_uuid = uuid.UUID(investigation_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid investigation ID format")

    try:
        from db.session import get_session
        from db.queries import get_investigation_by_id_or_run
        from graph.builder import build_graph_from_db, build_graph_from_db_cached
        from graph.export import to_json
        from db.models import EntityRelationship, Entity
        from sqlalchemy import func

        with get_session() as session:
            inv = get_investigation_by_id_or_run(session, inv_uuid)
            if inv is None:
                raise HTTPException(status_code=404, detail="Investigation not found")
            internal_id = inv.id
            graph_status = getattr(inv, "graph_status", "pending")

            if graph_status == "skipped_overflow":
                entity_count = (
                    session.query(func.count(Entity.id))
                    .filter(Entity.investigation_id == internal_id)
                    .scalar() or 0
                )
                return {
                    "graph_status": "skipped_overflow",
                    "message": "Graph too large to render. Use the entity list or download the CSV export instead.",
                    "total_entities": entity_count,
                    "nodes": [],
                    "edges": [],
                }

            persisted_edge_count = (
                session.query(func.count(EntityRelationship.id))
                .filter(EntityRelationship.investigation_id == internal_id)
                .scalar() or 0
            )

            total_entity_count = (
                session.query(func.count(Entity.id))
                .filter(Entity.investigation_id == internal_id)
                .scalar() or 0
            )

        if persisted_edge_count > 0 and not force_rebuild:
            logger.debug(
                "Graph cache hit: %s edges from DB for investigation %s",
                persisted_edge_count,
                investigation_id,
            )
            graph = build_graph_from_db_cached(investigation_id=internal_id)
        else:
            graph = build_graph_from_db(investigation_id=internal_id)

        node_count = len(graph.nodes)
        if node_count > max_nodes:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Graph has {node_count} nodes, exceeds max_nodes={max_nodes}. "
                    "Filter by entity type first using the /entities endpoint "
                    "with entity_type filter, then rebuild the graph."
                ),
            )

        graph_data = to_json(graph)

        nodes_to_keep = set()
        total_entities = len(graph_data["nodes"])
        for node in graph_data["nodes"]:
            node_confidence = node.get("confidence", 0.0)
            if node_confidence >= min_confidence:
                nodes_to_keep.add(node["id"])

        filtered_nodes = [n for n in graph_data["nodes"] if n["id"] in nodes_to_keep]
        filtered_edges = [
            e for e in graph_data["edges"]
            if e["source"] in nodes_to_keep and e["target"] in nodes_to_keep
        ]

        return {
            "graph_status": graph_status,
            "total_entities": total_entities,
            "filtered_entities": len(filtered_nodes),
            "min_confidence": min_confidence,
            "nodes": filtered_nodes,
            "edges": filtered_edges,
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("get_investigation_graph failed: %s", exc)
        return {"nodes": [], "edges": []}


def _build_investigation_profiles(investigation_id) -> int:
    """
    For each THREAT_ACTOR entity in this investigation,
    build/update their style profile from available text.

    Uses context_snippets collected across all appearances
    of the same canonical entity.

    NOTE: This function creates its own session - never pass a session
    across thread boundaries.
    """
    from db.models import Entity
    from db.session import get_session
    from fingerprint.profiler import build_actor_profile, save_profile_to_db
    from sqlalchemy import func

    count = 0
    with get_session() as session:
        actors = (
            session.query(Entity.canonical_value, Entity.entity_type)
            .filter(
                Entity.investigation_id == investigation_id,
                Entity.entity_type.in_(["THREAT_ACTOR", "THREAT_ACTOR_HANDLE", "MALWARE_FAMILY", "RANSOMWARE_GROUP"]),
                Entity.canonical_value.isnot(None),
            )
            .distinct()
            .all()
        )

        for canonical_value, entity_type in actors:
            texts = (
                session.query(Entity.context_snippet)
                .filter(
                    Entity.entity_type == entity_type,
                    Entity.canonical_value == canonical_value,
                    Entity.context_snippet.isnot(None),
                    func.length(Entity.context_snippet) >= 50,
                )
                .all()
            )

            text_list = [t[0] for t in texts if t[0]]
            total_chars = sum(len(t) for t in text_list)

            if len(text_list) < 2 or total_chars < 200:
                continue

            try:
                profile = build_actor_profile(text_list)
                if profile:
                    save_profile_to_db(
                        profile=profile,
                        canonical_value=canonical_value,
                        entity_type=entity_type,
                        session=session,
                    )
                    count += 1
            except Exception as e:
                logger.debug(f"Profile build failed for {canonical_value}: {e}")
                continue

        session.commit()

    return count
