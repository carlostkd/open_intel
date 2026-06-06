"""
monitor — Phase 4 continuous monitoring, diffing, and alerts.
"""

from monitor.alerts import dispatch_alerts
from monitor.config import load_watches
from monitor.diff import compute_diff, is_significant_change
from monitor.jobs import run_keyword_watch, run_url_watch
from monitor.scheduler import (
    get_job_status,
    start_scheduler,
    stop_scheduler,
    trigger_job_now,
)

__all__ = [
    "load_watches",
    "run_keyword_watch",
    "run_url_watch",
    "compute_diff",
    "is_significant_change",
    "dispatch_alerts",
    "start_scheduler",
    "stop_scheduler",
    "get_job_status",
    "trigger_job_now",
]
