"""
cli/commands/investigate.py — open_intel investigate "<query>"

Orchestrates the existing pipeline modules (search, sources, scraper,
extractor, llm) from a fresh async entry point. Re-implements the
sequencing that api.routes.investigations._run_investigation_task did
under FastAPI — minus auth, SSE, rate limiting, Postgres.

Outputs
    ~/.open_intel/results/<slug>-<YYYYMMDD-HHMMSS>.json
    ~/.open_intel/results/<slug>-<YYYYMMDD-HHMMSS>.md
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import typer
from rich.console import Console

# Import reputation enrichment sources (used in Step 6.2–6.4)
from sources.domain_reputation import enrich_domain_entities
from sources.email_reputation import enrich_email_entities
from sources.hash_reputation import enrich_hash_entities

console = Console()
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Typer entry point
# ---------------------------------------------------------------------------


def run(
    query: str = typer.Argument(..., help="Investigation query (e.g. 'LockBit ransomware')"),
    output: Optional[Path] = typer.Option(None, "--output", help="Override output directory"),
    model: Optional[str] = typer.Option(None, "--model", help="Override LLM model"),
    no_tor: bool = typer.Option(False, "--no-tor", help="Clearnet-only mode (skip Tor)"),
    no_refine: bool = typer.Option(False, "--no-refine", help="Skip query refinement, keep LLM for filtering and summary"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Skip LLM (query refinement, filtering, summary)"),
    depth: str = typer.Option("normal", "--depth", help="shallow | normal | deep"),
    fmt: str = typer.Option("both", "--format", help="json | md | both"),
    quiet: bool = typer.Option(False, "--quiet", help="No live display; print final summary only"),
) -> None:
    """Run an investigation: query → search → scrape → extract → enrich → report."""
    from open_intel_cli import config as cli_config

    cli_config.apply_env()

    try:
        import spacy
        spacy.load("en_core_web_sm")
    except Exception:
        import subprocess, sys
        from rich.console import Console
        Console().print(
            "  [dim]→[/dim] Installing spaCy NER model (one-time)..."
        )
        subprocess.run(
            [sys.executable, "-m", "spacy",
             "download", "en_core_web_sm"],
            capture_output=True
        )

    if quiet:
        logging.getLogger().setLevel(logging.ERROR)

    from utils.content_safety import is_blocked_query
    blocked, reason = is_blocked_query(query)
    if blocked:
        console.print(f"[red]Query blocked:[/red] {reason}")
        raise typer.Exit(code=1)

    if not cli_config.is_configured() and not no_llm:
        console.print("[yellow]No LLM configured — LLM features (refinement, filtering, summary) will be skipped.[/yellow]")
        console.print("  Run [bold]open_intel configure[/bold] to set one up, or pass [bold]--no-llm[/bold] to silence this message.")

    if depth not in ("shallow", "normal", "deep"):
        console.print(f"[red]Invalid depth:[/red] {depth}")
        raise typer.Exit(code=2)
    if fmt not in ("json", "md", "both"):
        console.print(f"[red]Invalid format:[/red] {fmt}")
        raise typer.Exit(code=2)

    out_dir = Path(output).expanduser() if output else cli_config.get_output_dir()
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        asyncio.run(
            _run_investigation(
                query=query,
                out_dir=out_dir,
                model=model,
                no_tor=no_tor,
                no_refine=no_refine,
                no_llm=no_llm,
                depth=depth,
                fmt=fmt,
                quiet=quiet,
            )
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
        raise typer.Exit(code=130)


# ---------------------------------------------------------------------------
# Pipeline orchestrator
# ---------------------------------------------------------------------------


DEPTH_PRESETS = {
    "shallow": {"top_n": 10, "max_workers": 3, "extract_concurrency": 3},
    "normal":  {"top_n": 20, "max_workers": 5, "extract_concurrency": 5},
    "deep":    {"top_n": 40, "max_workers": 8, "extract_concurrency": 6},
}

# Pages kept after LLM relevance filter (must match open_intel.llm.filter_results cap).
LLM_FILTER_TOP_N = 15

INVESTIGATION_STEPS = [
    "Refining query",
    "Searching dark web",
    "Filtering results",
    "Scraping pages",
    "Extracting entities",
    "Enriching intelligence",
    "Enriching domains",
    "Enriching hashes",
    "Enriching emails",
    "Building graph",
    "Generating summary",
    "Finalizing results",
]


async def _run_investigation(
    query: str,
    out_dir: Path,
    model: Optional[str],
    no_tor: bool,
    no_refine: bool,
    no_llm: bool,
    depth: str,
    fmt: str,
    quiet: bool,
) -> None:
    from open_intel_cli import config as cli_config
    from open_intel_cli.adapters import sqlite as sqlite_adapter
    from open_intel_cli.display import InvestigationDisplay
    from open_intel_cli.tor_detect import detect_tor, tor_unavailable_message

    cfg = cli_config.load_config()
    preset = DEPTH_PRESETS[depth]
    display = InvestigationDisplay(quiet=quiet)
    display.start(query, steps=INVESTIGATION_STEPS)

    # --- DB init ----------------------------------------------------------
    sqlite_adapter.init_db()
    _patch_llm_extraction_cache(sqlite_adapter)

    # --- Tor preflight ----------------------------------------------------
    tor_proxy: Optional[str] = None
    if not no_tor:
        status = detect_tor()
        if status.proxy_url:
            tor_proxy = status.proxy_url
            os.environ["TOR_PROXY_HOST"] = status.host or "127.0.0.1"
            os.environ["TOR_PROXY_PORT"] = str(status.port or 9050)
        else:
            display.error(tor_unavailable_message())
            return

    # --- LLM instance -----------------------------------------------------
    llm = None
    chosen_model = model or cli_config.get_llm_model(cfg)
    if not no_llm:
        try:
            from open_intel.llm import get_llm
            llm = get_llm(chosen_model)
        except Exception as exc:
            display.update_step("Refining query", "fail", f"LLM init failed: {exc}")
            llm = None

    # --- Create investigation row -----------------------------------------
    investigation_id = sqlite_adapter.save_investigation(
        query=query,
        model_used=chosen_model if llm is not None else None,
        status="running",
    )
    inv_uuid = uuid.UUID(investigation_id)

    sources_used: dict[str, dict[str, Any]] = {}
    page_count_by_url: dict[str, dict[str, Any]] = {}

    # --- Step 1 — refine query -------------------------------------------
    display.update_step("Refining query", "active")
    refined = query
    if no_refine:
        display.update_step("Refining query", "skip", "--no-refine")
    elif llm is not None:
        try:
            from open_intel.llm import refine_query
            refined = await asyncio.to_thread(refine_query, llm, query) or query
        except Exception as exc:
            display.update_step("Refining query", "fail", str(exc))
            refined = query
        else:
            display.update_step("Refining query", "ok", f"→ {refined!r}")
    else:
        display.update_step("Refining query", "skip", "--no-llm")
    sqlite_adapter.update_investigation(investigation_id, {"refined_query": refined})

    # --- Step 2 — search fan-out -----------------------------------------
    display.update_step("Searching dark web", "active")
    search_links: list[dict] = []
    paste_pages: list[dict] = []
    github_pages: list[dict] = []
    gitlab_pages: list[dict] = []
    rss_pages: list[dict] = []
    intelx_pages: list[dict] = []

    if not no_tor:
        try:
            from search import get_search_results_async
            display.update_substep("Searching dark web", "Tor engines", "active")
            search_links = await asyncio.to_thread(get_search_results_async, refined)
            display.update_substep("Searching dark web", "Tor engines", "ok")
            sources_used["tor_search"] = {"status": "ok", "count": len(search_links)}
        except Exception as exc:
            display.update_substep("Searching dark web", "Tor engines", "fail")
            sources_used["tor_search"] = {"status": "fail", "error": str(exc)}
    else:
        display.update_substep("Searching dark web", "Tor engines", "skip")
        sources_used["tor_search"] = {"status": "skipped"}

    # Parallel clearnet sources
    async def _safe(coro_factory, label, key):
        display.update_substep("Searching dark web", label, "active")
        try:
            res = await coro_factory()
            display.update_substep("Searching dark web", label, "ok")
            sources_used[key] = {"status": "ok", "count": len(res) if res else 0}
            return res or []
        except Exception as exc:
            display.update_substep("Searching dark web", label, "fail")
            sources_used[key] = {"status": "fail", "error": str(exc)}
            return []

    side_tasks = await asyncio.gather(
        _safe(lambda: _scrape_pastes(refined), "Paste sites", "paste_sites"),
        _safe(lambda: _scrape_github(refined), "GitHub", "github"),
        _safe(lambda: _scrape_gitlab(refined), "GitLab", "gitlab"),
        _safe(lambda: _scrape_rss(refined), "RSS feeds", "rss"),
        _safe(lambda: _scrape_intelx(refined), "IntelX", "intelx"),
    )
    paste_pages, github_pages, gitlab_pages, rss_pages, intelx_pages = side_tasks

    display.update_step("Searching dark web", "ok", f"{len(search_links)} links + side sources")

    # --- Step 3 — filter results ------------------------------------------
    display.update_step("Filtering results", "active")
    filter_top_n = LLM_FILTER_TOP_N
    filtered_links = search_links[: filter_top_n * 2] if search_links else []
    if llm is not None and search_links:
        try:
            from open_intel.llm import filter_results
            filtered_links = await asyncio.to_thread(filter_results, llm, refined, search_links) or search_links
            filtered_links = filtered_links[:filter_top_n]
            display.update_step("Filtering results", "ok", f"top {len(filtered_links)}")
        except Exception as exc:
            display.update_step("Filtering results", "fail", str(exc))
            filtered_links = search_links[:filter_top_n]
    else:
        filtered_links = (search_links or [])[:filter_top_n]
        display.update_step("Filtering results", "skip" if no_llm else "ok", f"{len(filtered_links)} kept")

    # --- Step 4 — scrape pages -------------------------------------------
    display.update_step("Scraping pages", "active")
    scraped_pages: list[dict] = []
    if filtered_links:
        try:
            from scraper.scrape import scrape_multiple

            async def _scrape_with_progress():
                # scrape_multiple does its own batching; we surface current URL
                # by intercepting via a side ticker since the underlying API
                # doesn't expose per-URL callbacks. Best effort: just show the
                # first URL while the gather runs.
                display.update_current_url(
                    (filtered_links[0].get("link") if filtered_links else "") or ""
                )
                return await scrape_multiple(filtered_links, max_workers=preset["max_workers"])

            results = await _scrape_with_progress()
            display.update_current_url("")
            for url, text in results.items():
                if text:
                    scraped_pages.append({"url": url, "text": text, "source": "tor_search"})
            display.update_step("Scraping pages", "ok", f"{len(scraped_pages)} pages")
        except Exception as exc:
            display.update_step("Scraping pages", "fail", str(exc))
    else:
        display.update_step("Scraping pages", "skip", "no links")

    # Merge in clearnet pages (paste/github/gitlab/rss/intelx)
    for extra in (paste_pages, github_pages, gitlab_pages, rss_pages, intelx_pages):
        for page in extra:
            url = page.get("url") or page.get("link")
            text = page.get("text") or page.get("content") or page.get("cleaned_text") or page.get("text_content") or ""
            if not url or not text:
                continue
            scraped_pages.append({"url": url, "text": text, "source": page.get("source", "clearnet")})

    # Resolve page_ids from DB (scrape_multiple persisted .onion pages)
    page_ids = await asyncio.to_thread(_lookup_page_ids, [p["url"] for p in scraped_pages])
    for page in scraped_pages:
        pid = page_ids.get(page["url"])
        if pid is not None:
            page["page_id"] = pid

    page_count_by_url = {p["url"]: p for p in scraped_pages}

    # --- Step 5 — extract entities ---------------------------------------
    display.update_step("Extracting entities", "active")
    extraction_results = []
    try:
        from extractor.pipeline import extract_entities_from_pages
        extraction_results = await extract_entities_from_pages(
            pages=scraped_pages,
            investigation_id=inv_uuid,
            llm=llm,
            run_llm_extraction=llm is not None,
            max_concurrent=preset["extract_concurrency"],
        )
        total_entities = sum(len(r.entity_ids) for r in extraction_results)
        display.update_step("Extracting entities", "ok", f"{total_entities} entities")
    except Exception as exc:
        display.update_step("Extracting entities", "fail", str(exc))

    # --- Step 6 — enrich intelligence (OTX + IP) ---------------------------
    display.update_step("Enriching intelligence", "active")
    enrichment_pages: list[dict] = []
    try:
        from sources.enrichment import enrich_investigation as _enrich_inv
        otx_key = os.getenv("OTX_API_KEY", "") or ""
        entity_dicts = sqlite_adapter.get_entities(investigation_id)
        enrichment_pages = await _enrich_inv(refined, otx_api_key=otx_key, entities=entity_dicts)
        sources_used["enrichment"] = {"status": "ok", "count": len(enrichment_pages)}
        display.update_step("Enriching intelligence", "ok", f"{len(enrichment_pages)} pages added")
    except Exception as exc:
        sources_used["enrichment"] = {"status": "fail", "error": str(exc)}
        display.update_step("Enriching intelligence", "fail", str(exc))

    try:
        from sources.ip_reputation import enrich_ip_entities
        await enrich_ip_entities(extraction_results, investigation_id=inv_uuid)
    except Exception as ip_exc:
        logger.debug("ip_reputation skipped: %s", ip_exc)

    # --- Step 6.2–6.4 — domain / hash / email (before graph) -------------
    display.update_step("Enriching domains", "active")
    try:
        extraction_results = await enrich_domain_entities(extraction_results, inv_uuid)
        domain_count = sum(
            1
            for e in sqlite_adapter.get_entities(investigation_id)
            if (e.get("entity_type") or "").upper() == "DOMAIN"
        )
        detail = f"{domain_count} domains enriched" if domain_count else ""
        display.update_step("Enriching domains", "ok", detail)
    except Exception as exc:
        logger.debug("Domain enrichment: %s", exc)
        display.update_step("Enriching domains", "fail", str(exc))

    display.update_step("Enriching hashes", "active")
    try:
        extraction_results = await enrich_hash_entities(extraction_results, inv_uuid)
        display.update_step("Enriching hashes", "ok")
    except Exception as exc:
        logger.debug("Hash enrichment: %s", exc)
        display.update_step("Enriching hashes", "fail", str(exc))

    display.update_step("Enriching emails", "active")
    try:
        extraction_results = await enrich_email_entities(extraction_results, inv_uuid)
        display.update_step("Enriching emails", "ok")
    except Exception as exc:
        logger.debug("Email enrichment: %s", exc)
        display.update_step("Enriching emails", "fail", str(exc))

    if enrichment_pages:
        try:
            from extractor.pipeline import extract_entities_from_pages as _extr2
            await _extr2(
                pages=enrichment_pages,
                investigation_id=inv_uuid,
                llm=None,
                run_llm_extraction=False,
                max_concurrent=preset["extract_concurrency"],
            )
        except Exception as exc:
            console.print(f"[grey50]Enrichment extraction failed: {exc}[/grey50]")

    # --- Step 7 — build graph (co-occurrence) ----------------------------
    display.update_step("Building graph", "active")
    try:
        edges_written = await asyncio.to_thread(_build_cooccurrence_edges, investigation_id)
        display.update_step("Building graph", "ok", f"{edges_written} edges")
    except Exception as exc:
        display.update_step("Building graph", "fail", str(exc))

    # --- Step 8 — summary -------------------------------------------------
    display.update_step("Generating summary", "active")
    summary_text = ""
    if llm is not None:
        try:
            from open_intel.llm import generate_summary
            pages_to_summarize = scraped_pages[:10]
            if pages_to_summarize:
                summary_text = await asyncio.to_thread(
                    generate_summary, llm, refined, pages_to_summarize, "threat_intel"
                )
            display.update_step("Generating summary", "ok")
        except Exception as exc:
            display.update_step("Generating summary", "fail", str(exc))
    else:
        display.update_step("Generating summary", "skip", "--no-llm")

    # --- Step 9 — finalize & write outputs --------------------------------
    display.update_step("Finalizing results", "active")
    final_entities = sqlite_adapter.get_entities(investigation_id)
    final_relationships = sqlite_adapter.get_relationships(investigation_id)
    sqlite_adapter.update_investigation(
        investigation_id,
        {
            "status": "completed",
            "summary": summary_text or None,
            "entity_count": len(final_entities),
            "page_count": len(scraped_pages),
            "current_step": 9,
            "current_step_label": "Completed",
        },
    )

    slug = _slugify(query)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    json_path = out_dir / f"{slug}-{ts}.json"
    md_path = out_dir / f"{slug}-{ts}.md"

    payload = {
        "id": investigation_id,
        "query": query,
        "refined_query": refined,
        "model_used": chosen_model if llm is not None else None,
        "status": "completed" if final_entities or scraped_pages else "completed_no_results",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary_text,
        "sources_used": sources_used,
        "entities": final_entities,
        "relationships": final_relationships,
        "pages_scraped": [{"url": p["url"], "source": p.get("source", "")} for p in scraped_pages],
    }

    if fmt in ("json", "both"):
        json_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    if fmt in ("md", "both"):
        md_path.write_text(_render_markdown(payload), encoding="utf-8")

    display.update_step("Finalizing results", "ok")

    c2_count = sum(
        1 for e in final_entities
        if e["entity_type"] == "ip_address"
        and (e.get("corroborating_sources") or "").lower().find("c2") >= 0
    )

    display.complete(
        {
            "entity_count": len(final_entities),
            "page_count": len(scraped_pages),
            "c2_ips": c2_count,
            "sources_used": sum(1 for v in sources_used.values() if v.get("status") == "ok"),
            "report_path": str(md_path) if fmt in ("md", "both") else None,
            "data_path": str(json_path) if fmt in ("json", "both") else None,
        }
    )

    # Close any cached aiohttp sessions so the event loop exits cleanly
    # (otherwise aiohttp prints "Unclosed client session" warnings).
    await _close_cached_sessions()


def _patch_llm_extraction_cache(sqlite_adapter: Any) -> None:
    """Use sqlite adapter for cache reads (naive ISO strings from SQLite)."""
    try:
        import extractor.llm_extract as llm_extract
    except Exception:
        return
    llm_extract._load_from_cache = sqlite_adapter.get_page_extraction_cache


async def _close_cached_sessions() -> None:
    try:
        from scraper.scrape import close_cached_sessions as _close_scrape
        await _close_scrape()
    except Exception:
        pass
    try:
        from search import close_search_session as _close_search
        await _close_search()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Side-source helpers (each gracefully degrades if module missing/disabled)
# ---------------------------------------------------------------------------


async def _scrape_pastes(query: str) -> list[dict]:
    try:
        from sources.paste_scraper import scrape_paste_sites
    except Exception:
        return []
    if os.getenv("PASTE_SCRAPING_ENABLED", "true").lower() != "true":
        return []
    try:
        return await scrape_paste_sites(query) or []
    except Exception:
        return []


async def _scrape_github(query: str) -> list[dict]:
    try:
        from sources.github_scraper import scrape_github
    except Exception:
        return []
    if os.getenv("GITHUB_SCRAPING_ENABLED", "true").lower() != "true":
        return []
    try:
        return await scrape_github(query) or []
    except Exception:
        return []


async def _scrape_gitlab(query: str) -> list[dict]:
    try:
        from sources.gitlab_scraper import scrape_gitlab
    except Exception:
        return []
    if os.getenv("GITLAB_SCRAPING_ENABLED", "true").lower() != "true":
        return []
    try:
        return await scrape_gitlab(query) or []
    except Exception:
        return []


async def _scrape_rss(query: str) -> list[dict]:
    try:
        from sources.rss_scraper import scrape_rss_feeds
    except Exception:
        return []
    if os.getenv("RSS_FEEDS_ENABLED", "true").lower() != "true":
        return []
    try:
        return await scrape_rss_feeds(query) or []
    except Exception:
        return []


async def _scrape_intelx(query: str) -> list[dict]:
    try:
        from sources.intelx_scraper import scrape_intelx
    except Exception:
        return []
    try:
        return await scrape_intelx(query) or []
    except Exception:
        return []


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------


def _lookup_page_ids(urls: list[str]) -> dict[str, uuid.UUID]:
    if not urls:
        return {}
    try:
        from db.models import Page
        from db.session import get_session
    except Exception:
        return {}
    out: dict[str, uuid.UUID] = {}
    with get_session() as session:
        rows = session.query(Page).filter(Page.url.in_(urls)).all()
        for r in rows:
            out[r.url] = r.id
    return out


def _build_cooccurrence_edges(investigation_id: str) -> int:
    """Generate CO_APPEARED_ON edges for entities sharing a page."""
    try:
        from db.models import Entity
        from db.session import get_session
    except Exception:
        return 0
    from open_intel_cli.adapters.sqlite import save_relationships

    edges: list[dict] = []
    inv_uuid = uuid.UUID(investigation_id)

    with get_session() as session:
        rows = (
            session.query(Entity.id, Entity.page_id)
            .filter(Entity.investigation_id == inv_uuid)
            .all()
        )
    by_page: dict[uuid.UUID, list[uuid.UUID]] = {}
    for ent_id, page_id in rows:
        if page_id is None:
            continue
        by_page.setdefault(page_id, []).append(ent_id)

    for ents in by_page.values():
        if len(ents) < 2:
            continue
        for i in range(len(ents)):
            for j in range(i + 1, len(ents)):
                edges.append(
                    {
                        "entity_a_id": str(ents[i]),
                        "entity_b_id": str(ents[j]),
                        "relationship_type": "CO_APPEARED_ON",
                        "confidence": 0.8,
                    }
                )
    return save_relationships(investigation_id, edges)


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


def _slugify(s: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "-", s).strip("-").lower()
    return s[:50] or "investigation"


def _render_markdown(payload: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"# Investigation: {payload['query']}")
    lines.append(
        f"**Date:** {payload['created_at']}  |  **Model:** {payload.get('model_used') or '—'}"
    )
    if payload.get("refined_query") and payload["refined_query"] != payload["query"]:
        lines.append(f"**Refined:** {payload['refined_query']}")
    lines.append("")
    lines.append("## Summary")
    lines.append(payload.get("summary") or "_(no summary — LLM disabled or unavailable)_")
    lines.append("")

    entities = payload.get("entities", [])
    by_type: dict[str, list[dict]] = {}
    for e in entities:
        by_type.setdefault(e["entity_type"], []).append(e)

    c2_ips = [
        e for e in entities
        if e["entity_type"] == "ip_address"
        and (e.get("corroborating_sources") or "").lower().find("c2") >= 0
    ]
    lines.append("## Key findings")
    lines.append(f"- {len(c2_ips)} confirmed C2 IP addresses")
    lines.append(
        f"- {len(by_type.get('ransomware_group', []))} ransomware group(s) identified"
    )
    lines.append(f"- {len(by_type.get('onion_url', []))} .onion URLs mapped")
    lines.append(f"- {len(entities)} entities total")
    lines.append("")

    lines.append(f"## Entities ({len(entities)} total)")
    for etype in sorted(by_type.keys()):
        rows = by_type[etype]
        lines.append(f"\n### {etype} ({len(rows)})")
        lines.append("| Value | Confidence | Method | Tags |")
        lines.append("|---|---|---|---|")
        for r in rows[:50]:
            tags = (r.get("corroborating_sources") or "").replace("|", "/")
            val = (r.get("canonical_value") or r.get("value") or "").replace("|", "/")
            conf = r.get("confidence")
            lines.append(
                f"| {val} | {conf:.2f} | {r.get('extraction_method') or ''} | {tags} |"
            )
        if len(rows) > 50:
            lines.append(f"\n_…and {len(rows) - 50} more (see JSON)_")
    lines.append("")

    lines.append("## Sources used")
    for name, info in payload.get("sources_used", {}).items():
        glyph = "✓" if info.get("status") == "ok" else ("↷" if info.get("status") == "skipped" else "✗")
        detail = f" ({info.get('count', 0)} results)" if "count" in info else ""
        lines.append(f"- {glyph} {name}{detail}")

    return "\n".join(lines) + "\n"
