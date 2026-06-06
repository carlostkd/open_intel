"""
api/routes/monitors.py — Monitor/watch management endpoints.

GET    /monitors              — list all watches from monitors.yaml
POST   /monitors              — create a new watch (writes to monitors.yaml)
DELETE /monitors/{watch_name} — delete a watch from monitors.yaml
POST   /monitors/{watch_name}/trigger — trigger a specific watch immediately
GET    /monitors/status       — job status for all scheduled watches
"""

from __future__ import annotations

import asyncio
import logging
import os

from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from filelock import FileLock
from pydantic import BaseModel

# Cross-platform file lock strategy:
# - Uses `filelock` library (works on Linux/Windows/macOS)
# - Replaces fcntl.flock() which is Linux-only and silently failed on Windows
# - FileLock creates a .lock file alongside monitors.yaml for inter-process locking
# - Provides thread-safety for concurrent config writes across deployments

from db.queries import (
    acknowledge_alerts,
    get_alert_counts_by_monitor,
    get_alerts_for_monitor,
    get_monitor_stats,
    get_unacknowledged_alert_count,
)
from api.auth import require_password_not_reset_pending, CurrentUser
from db.session import get_session

logger = logging.getLogger(__name__)
router = APIRouter()

# Module-level scheduler reference (populated externally if running with scheduler)
_scheduler = None


def _get_monitor_config_path() -> Path:
    """Get the path to monitors.yaml, configurable via MONITORS_CONFIG_PATH env var."""
    env_path = os.getenv("MONITORS_CONFIG_PATH")
    if env_path:
        return Path(env_path)
    return Path(__file__).resolve().parents[2] / "data" / "monitors.yaml"


def _ensure_monitors_yaml_exists() -> None:
    """Create default empty monitors.yaml if it doesn't exist."""
    path = _get_monitor_config_path()
    if not path.exists():
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            import yaml
            path.write_text(
                yaml.dump({"watches": []}, default_flow_style=False),
                encoding="utf-8",
            )
            logger.info(f"Created default monitors.yaml at {path}")
        except Exception as e:
            logger.warning(f"Could not create monitors.yaml: {e}")


_ensure_monitors_yaml_exists()


def set_scheduler(scheduler) -> None:
    """Inject the APScheduler instance into this module."""
    global _scheduler
    _scheduler = scheduler


_monitors_lock = asyncio.Lock()


async def _load_monitors_no_lock() -> list[dict]:
    """Load monitors.yaml safely, return [] if file missing. NOT thread-safe on its own."""
    path = _get_monitor_config_path()
    if not path.exists():
        import yaml
        try:
            await asyncio.to_thread(
                path.write_text,
                yaml.dump({"watches": []}, default_flow_style=False),
                encoding="utf-8"
            )
        except Exception as e:
            logger.error(f"Failed to create default monitors.yaml: {e}")
        return []

    try:
        import yaml
        content = await asyncio.to_thread(path.read_text, encoding="utf-8")
        data = yaml.safe_load(content)
        if not data or not isinstance(data, dict):
            return []
        watches = data.get("watches", [])
        return watches if isinstance(watches, list) else []
    except Exception as e:
        logger.error(f"Failed to load monitors.yaml: {e}")
        return []


async def _save_monitors_no_lock(watches: list[dict]) -> None:
    """Save monitors.yaml safely with fsync. NOT thread-safe on its own."""
    import yaml
    path = _get_monitor_config_path()
    content = yaml.dump({"watches": watches}, default_flow_style=False, allow_unicode=True)

    def _sync_save():
        tmp_path = path.with_suffix(".tmp")
        with open(tmp_path, 'w', encoding='utf-8') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)

    await asyncio.to_thread(_sync_save)


async def _load_monitors() -> list[dict]:
    """Thread-safe YAML load."""
    async with _monitors_lock:
        return await _load_monitors_no_lock()


async def _save_monitors(watches: list[dict]) -> None:
    """Thread-safe YAML save."""
    async with _monitors_lock:
        await _save_monitors_no_lock(watches)


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class AcknowledgeAlertsBody(BaseModel):
    alert_ids: list[int] | None = None


class CreateMonitorRequest(BaseModel):
    name: str
    type: str  # "keyword" | "url"
    query: Optional[str] = None
    url: Optional[str] = None
    interval_hours: float = 48.0
    alert_on: str = "new_results"
    webhook_url: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    email: Optional[str] = None
    enabled: bool = True


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("")
async def list_monitors() -> list[dict]:
    """
    Return all watches defined in monitors.yaml with aggregate stats from DB.
    """
    watches = await _load_monitors()
    if not watches:
        return watches

    with get_session() as session:
        result = []
        for watch in watches:
            name = watch.get("name", "")
            stats = get_monitor_stats(session, name)
            enriched = {**watch, **stats}
            result.append(enriched)
        return result


@router.get("/alerts/count")
async def get_alert_count() -> dict:
    """
    Total unacknowledged alert count across all monitors.
    Used by MonitorNavBadge for the live count.
    """
    with get_session() as session:
        count = get_unacknowledged_alert_count(session)
        by_monitor = get_alert_counts_by_monitor(session)
    return {
        "total_unacknowledged": count,
        "by_monitor": by_monitor,
    }


@router.get("/status")
async def monitors_status() -> list[dict]:
    """Return job status for all scheduled watches."""
    try:
        from monitor.scheduler import get_job_status  # noqa: PLC0415

        status = get_job_status(_scheduler)
        result = []
        for s in status:
            result.append({
                "name": s.get("name"),
                "next_run_time": (
                    s["next_run_time"].isoformat()
                    if s.get("next_run_time") else None
                ),
                "last_run_time": (
                    s["last_run_time"].isoformat()
                    if s.get("last_run_time") else None
                ),
            })
        return result
    except Exception as exc:
        logger.warning("monitors_status failed: %s", exc)
        return []


@router.get("/{monitor_name}/alerts")
async def get_monitor_alerts(
    monitor_name: str,
    limit: int = Query(20, ge=1, le=200),
    include_acknowledged: bool = Query(True),
) -> dict:
    """
    Alert history for a specific monitor.
    Used by MonitorDetail inline panel.
    """
    with get_session() as session:
        alerts = get_alerts_for_monitor(
            session,
            monitor_name=monitor_name,
            limit=limit,
            include_acknowledged=include_acknowledged,
        )
    return {
        "monitor_name": monitor_name,
        "alerts": [
            {
                "id": a.id,
                "triggered_at": a.triggered_at.isoformat(),
                "change_type": a.change_type,
                "summary": a.summary,
                "severity": str(a.severity),
                "entity_count_delta": a.entity_count_delta,
                "delivered": a.delivered,
                "delivery_channels": a.delivery_channels or [],
                "acknowledged": a.acknowledged,
                "acknowledged_at": (
                    a.acknowledged_at.isoformat() if a.acknowledged_at else None
                ),
                "diff_data": a.diff_data,
            }
            for a in alerts
        ],
        "total": len(alerts),
    }


@router.post("/{monitor_name}/alerts/acknowledge")
async def acknowledge_monitor_alerts(
    monitor_name: str,
    body: AcknowledgeAlertsBody | None = None,
) -> dict:
    """
    Mark alerts as acknowledged.
    Body: {"alert_ids": [1, 2, 3]} or empty body to acknowledge all.
    """
    alert_ids = body.alert_ids if body else None
    with get_session() as session:
        count = acknowledge_alerts(session, monitor_name, alert_ids)
    return {"acknowledged": count}


@router.post("")
async def create_monitor(
    req: CreateMonitorRequest,
    current_user: CurrentUser = Depends(require_password_not_reset_pending),
) -> dict:
    """Create a new watch and append it to monitors.yaml."""
    if req.type not in ("keyword", "url"):
        raise HTTPException(status_code=422, detail="type must be 'keyword' or 'url'")
    if req.type == "keyword" and not req.query:
        raise HTTPException(status_code=422, detail="query is required for keyword watches")
    if req.type == "url" and not req.url:
        raise HTTPException(status_code=422, detail="url is required for url watches")
    if req.interval_hours < 0.5:
        raise HTTPException(status_code=422, detail="interval_hours must be >= 0.5")
    valid_alert_on = {"new_results", "any_change", "any_appearance"}
    if req.alert_on not in valid_alert_on:
        raise HTTPException(
            status_code=422,
            detail=f"alert_on must be one of {sorted(valid_alert_on)}",
        )
    if not req.name or not req.name.strip():
        raise HTTPException(status_code=422, detail="name is required")

    name = req.name.strip()

    try:
        path = _get_monitor_config_path()
        if not path.exists():
            await _load_monitors()

        lock_path = str(path) + ".lock"

        def _sync_create():
            with FileLock(lock_path, timeout=10):
                with open(path, 'r+', encoding='utf-8') as f:
                    content = f.read()
                    import yaml
                    data = yaml.safe_load(content) or {"watches": []}
                    watches = data.get("watches", [])
                    if not isinstance(watches, list):
                        watches = []

                    if any(w.get("name") == name for w in watches if isinstance(w, dict)):
                        return "duplicate"

                    entry: dict = {
                        "name": name,
                        "type": req.type,
                        "interval_hours": req.interval_hours,
                        "alert_on": req.alert_on,
                        "enabled": req.enabled,
                        "webhook_url": req.webhook_url or None,
                        "telegram_chat_id": req.telegram_chat_id or None,
                        "email": req.email or None,
                    }
                    if req.type == "keyword":
                        entry["query"] = req.query.strip()
                    else:
                        entry["url"] = req.url.strip()

                    watches.append(entry)

                    f.seek(0)
                    f.truncate()
                    f.write(yaml.dump({"watches": watches}, default_flow_style=False, allow_unicode=True))
                    f.flush()
                    os.fsync(f.fileno())
                    return "ok"

        res = await asyncio.to_thread(_sync_create)
        if res == "duplicate":
            raise HTTPException(
                status_code=409, detail=f"Monitor {name!r} already exists"
            )

        return {"created": True, "name": name}

    except HTTPException:
        raise
    except Exception as exc:
        logger.error("create_monitor failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.delete("/{watch_name}")
async def delete_monitor(watch_name: str) -> dict:
    """Remove a watch from monitors.yaml by name."""
    try:
        logger.debug(f"Lock ID: {id(_monitors_lock)}")
        async with _monitors_lock:
            watches = await _load_monitors_no_lock()
            before = len(watches)
            watches = [w for w in watches if not (isinstance(w, dict) and w.get("name") == watch_name)]
            if len(watches) == before:
                raise HTTPException(status_code=404, detail=f"Watch {watch_name!r} not found")
            await _save_monitors_no_lock(watches)
        return {"deleted": True, "name": watch_name}

    except HTTPException:
        raise
    except Exception as exc:
        logger.error("delete_monitor failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/{watch_name}/trigger")
async def trigger_monitor(watch_name: str) -> dict:
    """Trigger a specific watch immediately."""
    try:
        from monitor.config import get_watch_by_name  # noqa: PLC0415
        from monitor.scheduler import trigger_job_now  # noqa: PLC0415

        watch = get_watch_by_name(watch_name)
        if watch is None:
            raise HTTPException(status_code=404, detail=f"Watch {watch_name!r} not found")

        triggered = trigger_job_now(_scheduler, watch_name)
        return {"triggered": triggered, "watch_name": watch_name}
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("trigger_monitor failed: %s", exc)
        return {"triggered": False, "watch_name": watch_name}