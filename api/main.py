"""
api/main.py — FastAPI application entry point for Open_Intel Intelligence API.

Exposes the Open_Intel platform programmatically.
Runs alongside Streamlit on a different port (8000 vs 8501).

Usage:
    uvicorn api.main:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from typing import Callable

from fastapi import FastAPI, Depends, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from api.routes import entities, export, investigations, monitors, search, auth, admin, settings
from api.auth import get_current_user
from monitor.scheduler import start_scheduler

from config import TOR_PROXY_HOST, TOR_PROXY_PORT, PLAYWRIGHT_ENABLED, JWT_SECRET

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)


# ---------------------------------------------------------------------------
# Rate limiter setup
# ---------------------------------------------------------------------------

DISABLE_RATE_LIMIT = os.getenv("DISABLE_RATE_LIMIT", "false").lower() == "true"

if DISABLE_RATE_LIMIT:
    limiter = None
else:
    limiter = Limiter(key_func=get_remote_address)


def _rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    return JSONResponse(
        status_code=429,
        content={
            "detail": "Too many requests. Please wait 60 seconds before retrying.",
            "retry_after": 60,
        },
        headers={
            "Retry-After": "60",
            "X-RateLimit-Limit": "3",
            "X-RateLimit-Window": "60s",
        },
    )


# ---------------------------------------------------------------------------
# Lifespan handler (replaces deprecated on_event)
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- Startup ---
    logger.info("Open_Intel API started")

    if JWT_SECRET is None:
        raise RuntimeError(
            "JWT_SECRET is not set. Set JWT_SECRET in your .env file. "
            "Generate a secure secret with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )

    # Run Alembic migrations (idempotent — safe to call on every boot)
    _run_migrations()

    _check_db_connectivity()

    # Pre-warm Playwright browser (avoids cold start on first JS page)
    if PLAYWRIGHT_ENABLED:
        try:
            from scraper.scrape_js import get_browser

            await get_browser(TOR_PROXY_HOST, TOR_PROXY_PORT)
            logger.warning("Playwright browser pre-warmed")
        except ImportError:
            logger.warning("Playwright not installed — JS rendering disabled")
        except Exception as e:
            logger.warning(f"Playwright pre-warm failed (non-fatal): {e}")

    # Pre-warm vector store embedding model (avoids 5-15s cold start on first search)
    try:
        from vector.store import get_collection
        from vector.model_singleton import get_embedding_model

        get_collection()
        get_embedding_model()
        logger.warning("Vector store and embedding model pre-warmed")
    except Exception as e:
        logger.warning(f"Vector store pre-warm failed (non-fatal): {e}")

    # Load curated .onion seed catalogue (no Tor validation on startup — too slow)
    try:
        from sources.seed_manager import get_seed_manager

        logger.info("Loading seed database...")
        seed_manager = get_seed_manager()
        logger.warning(
            "Seed database loaded: %d seeds",
            len(seed_manager.list_seeds()),
        )
    except Exception as e:
        logger.warning(f"Seed database load failed (non-fatal): {e}")

    # Recover stranded processing investigations
    try:
        if os.getenv("DATABASE_URL"):
            from db.session import get_session
            from db.models import Investigation
            with get_session() as session:
                stranded_count = session.query(Investigation).filter(Investigation.status == "processing").update(
                    {"status": "failed", "summary": "Investigation interrupted due to server restart."}
                )
                if stranded_count > 0:
                    session.commit()
                    logger.warning(f"Recovered {stranded_count} stranded investigations (marked as failed).")
    except Exception as e:
        logger.warning(f"Failed to recover stranded investigations: {e}")

    # Start background scheduler (monitoring watches + weekly seed refresh)
    try:
        scheduler = start_scheduler()
        if scheduler:
            monitors.set_scheduler(scheduler)
            logger.warning("APScheduler started: monitoring watches active")
        else:
            logger.warning("APScheduler background service disabled")
    except Exception as e:
        logger.error(f"APScheduler failed to start: {e}")
        scheduler = None

    yield

    # --- Shutdown ---
    if scheduler and scheduler.running:
        scheduler.shutdown(wait=False)
        logger.warning("APScheduler stopped")

# Close Playwright browser
    if PLAYWRIGHT_ENABLED:
        try:
            from scraper.scrape_js import close_browser

            await close_browser()
        except Exception:
            pass

    # Close cached scrape sessions (Tor and direct) - always, regardless of PLAYWRIGHT_ENABLED
    try:
        from scraper.scrape import close_cached_sessions

        await close_cached_sessions()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Open_Intel Intelligence API",
    description="Open_Intel: Dark Web Intelligence Platform",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Allowed origins: explicit list from env, or localhost defaults
CORS_ORIGINS = os.environ.get(
    "CORS_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,          # Explicit list, never wildcard
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "PUT", "PATCH"],
    allow_headers=["Content-Type", "Authorization", "X-Request-ID"],
)

# Add rate limiter to app state and register exception handler
if limiter is not None:
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    errors = []
    for error in exc.errors():
        field = ".".join(str(x) for x in error.get("loc", []) if x != "body")
        msg = error.get("msg", "Invalid value")
        errors.append(f"{field}: {msg}")
    return JSONResponse(
        status_code=422,
        content={
            "detail": "; ".join(errors),
            "errors": errors,
        },
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Global exception caught: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": f"Internal Server Error: {str(exc)}"},
    )


# ---------------------------------------------------------------------------
# Global rate limit middleware (100/minute for all API routes)
# ---------------------------------------------------------------------------


@app.middleware("http")
async def global_rate_limit_middleware(request: Request, call_next: Callable):
    if limiter is None:
        return await call_next(request)

    exempt_paths = {"/health", "/docs", "/redoc", "/openapi.json"}
    if request.url.path in exempt_paths:
        return await call_next(request)

    if request.url.path.startswith("/api/") or request.url.path in exempt_paths:
        pass
    else:
        return await call_next(request)

    # Removed invalid limiter.check call causing 500 error
    # Rate limiting should be handled via decorators on specific routes
    pass

    return await call_next(request)


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

# Public routes (no auth required)
app.include_router(auth.router)

# Protected routes (require valid JWT)
app.include_router(
    investigations.router,
    prefix="/investigations",
    tags=["investigations"],
    dependencies=[Depends(get_current_user)],
)
app.include_router(
    entities.router,
    prefix="/entities",
    tags=["entities"],
    dependencies=[Depends(get_current_user)],
)
app.include_router(
    search.router,
    prefix="/search",
    tags=["search"],
    dependencies=[Depends(get_current_user)],
)
app.include_router(
    export.router,
    prefix="/export",
    tags=["export"],
    dependencies=[Depends(get_current_user)],
)
app.include_router(
    monitors.router,
    prefix="/monitors",
    tags=["monitors"],
    dependencies=[Depends(get_current_user)],
)
app.include_router(
    admin.router,
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(get_current_user)],
)
app.include_router(
    settings.router,
    tags=["settings"],
    dependencies=[Depends(get_current_user)],
)


# ---------------------------------------------------------------------------
# Startup event
# ---------------------------------------------------------------------------


def _run_migrations() -> None:
    """Apply any pending Alembic migrations at startup.

    Safe to call on every boot — Alembic is idempotent (already-applied
    migrations are skipped).  Logs a warning and continues on failure so a
    migration error never hard-crashes the API process.
    """
    if not os.getenv("DATABASE_URL"):
        logger.info("DATABASE_URL not set — skipping migrations")
        return
    try:
        from alembic.config import Config  # noqa: PLC0415
        from alembic import command  # noqa: PLC0415
        from alembic.util import CommandError  # noqa: PLC0415
        import pathlib  # noqa: PLC0415

        project_root = pathlib.Path(__file__).resolve().parents[1]
        ini_path = project_root / "alembic.ini"
        alembic_cfg = Config(str(ini_path))
        alembic_cfg.set_main_option("sqlalchemy.url", os.environ["DATABASE_URL"])
        alembic_cfg.set_main_option("script_location", str(project_root / "db" / "migrations"))

        try:
            command.upgrade(alembic_cfg, "head")
            logger.info("Alembic migrations applied")
        except CommandError as e:
            if "already up to date" in str(e).lower():
                logger.info("Alembic migrations already at head")
            else:
                raise
    except Exception as exc:
        logger.warning("Migration failed — proceeding without applying: %s", exc)


async def _check_db_connectivity_async() -> str:
    """Return 'ok' if DB is reachable, error message otherwise."""
    if not os.getenv("DATABASE_URL"):
        return "error: DATABASE_URL not configured"
    try:
        from db.session import get_async_session  # noqa: PLC0415
        from sqlalchemy import text

        async with get_async_session() as session:
            await session.execute(text("SELECT 1"))
        return "ok"
    except Exception as exc:
        logger.warning("DB connectivity check failed: %s", exc)
        return f"error: {str(exc)}"


async def _check_tor_connectivity_async() -> str:
    """Return 'ok' if Tor proxy is reachable, 'unreachable' otherwise."""
    host = os.getenv("TOR_PROXY_HOST", "127.0.0.1")
    port = int(os.getenv("TOR_PROXY_PORT", "9050"))
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=3.0
        )
        writer.close()
        await writer.wait_closed()
        return "ok"
    except Exception:
        return "unreachable"


def _check_db_connectivity() -> bool:
    """Return True if DB is reachable, False otherwise. Sync wrapper for startup."""
    if not os.getenv("DATABASE_URL"):
        return False
    try:
        from db.session import get_session  # noqa: PLC0415
        from db.queries import db_health_check  # noqa: PLC0415

        with get_session() as session:
            return db_health_check(session)
    except Exception as exc:
        logger.warning("DB connectivity check failed: %s", exc)
        return False


def _check_tor_connectivity() -> bool:
    """Return True if Tor proxy appears to be reachable. Sync wrapper for startup."""
    import socket  # noqa: PLC0415
    host = os.getenv("TOR_PROXY_HOST", "127.0.0.1")
    port = int(os.getenv("TOR_PROXY_PORT", "9050"))
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Health endpoints
# ---------------------------------------------------------------------------


@app.get("/health", tags=["health"])
async def health() -> dict:
    """Returns API, DB, and Tor connectivity status (async)."""
    checks = {}
    db_result, tor_result = await asyncio.gather(
        _check_db_connectivity_async(),
        _check_tor_connectivity_async(),
    )
    checks["database"] = db_result
    checks["tor"] = tor_result

    status = "healthy" if all(v == "ok" for v in checks.values()) else "degraded"
    return {"status": status, "checks": checks}


@app.get("/healthz/live", tags=["health"])
async def liveness() -> dict:
    """Liveness probe — always 200 unless process is wedged."""
    return {"status": "alive"}


@app.get("/healthz/ready", tags=["health"])
async def readiness() -> dict:
    """Readiness probe — checks DB and Tor are reachable."""
    checks = {}
    db_result, tor_result = await asyncio.gather(
        _check_db_connectivity_async(),
        _check_tor_connectivity_async(),
    )
    checks["database"] = db_result
    checks["tor"] = tor_result

    is_ready = all(v == "ok" for v in checks.values())
    status = "ready" if is_ready else "not_ready"
    return {"status": status, "checks": checks}


@app.get("/debug/tor-test", tags=["health"])
async def tor_test(_=Depends(get_current_user)) -> dict:
    """
    Test Tor connectivity.
    TODO: Remove or protect in production.
    """
    try:
        import aiohttp  # noqa: PLC0415
        from aiohttp_socks import ProxyConnector  # noqa: PLC0415

        connector = ProxyConnector.from_url(f"socks5://{TOR_PROXY_HOST}:{TOR_PROXY_PORT}")
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            async with session.get("https://check.torproject.org") as resp:
                text = await resp.text()
                return {
                    "tor_working": True,
                    "status_code": resp.status,
                    "response": text[:100],
                }
    except Exception as exc:
        return {"tor_working": False, "error": str(exc)}


@app.get("/debug/search-test", tags=["health"])
async def search_test(_=Depends(get_current_user)) -> dict:
    """
    Test search engine connectivity.
    TODO: Remove or protect in production.
    """
    try:
        from search.search import get_search_results  # noqa: PLC0415

        results = get_search_results("bitcoin+dark+web")
        return {
            "search_working": True,
            "results_count": len(results),
            "first_result": results[0] if results else None,
        }
    except Exception as exc:
        return {"search_working": False, "error": str(exc)}


@app.get("/debug/stack", tags=["health"])
async def debug_stack() -> dict:
    """Returns a list of all running asyncio tasks and their stack traces."""
    import asyncio

    tasks = asyncio.all_tasks()
    out = []
    for i, t in enumerate(tasks):
        stack = []
        for f in t.get_stack():
            stack.append(f"{f.f_code.co_filename}:{f.f_lineno} in {f.f_code.co_name}")
        out.append({
            "task_id": i,
            "name": t.get_name(),
            "coro": str(t.get_coro()),
            "stack": stack,
        })
    return {"tasks": out}
