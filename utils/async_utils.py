"""
Async utilities for safely running coroutines in various contexts.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any, Coroutine, TypeVar

logger = logging.getLogger(__name__)

_T = TypeVar("_T")

_executor: ThreadPoolExecutor | None = None
_executor_lock = threading.Lock()


def _get_executor() -> ThreadPoolExecutor:
    global _executor
    if _executor is None:
        with _executor_lock:
            if _executor is None:
                _executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="async_utils_")
    return _executor


def run_async(coro: Coroutine[Any, Any, _T]) -> _T:
    """
    Safely run a coroutine regardless of whether there's already a running event loop.

    Uses a thread-isolated event loop when called from:
    - An already-running event loop (e.g., inside APScheduler jobs, pytest-asyncio)
    - A synchronous context

    Args:
        coro: The coroutine to run

    Returns:
        The result of the coroutine

    Raises:
        RuntimeError: If the coroutine fails to run
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None:
        return _run_in_thread(coro)

    try:
        return asyncio.run(coro)
    except RuntimeError as e:
        if "already running" in str(e).lower():
            return _run_in_thread(coro)
        raise


def _run_in_thread(coro: Coroutine[Any, Any, _T]) -> _T:
    """
    Run a coroutine in a dedicated thread with its own event loop.
    """
    future: Future[_T] = Future()

    def _run() -> None:
        local_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(local_loop)
        try:
            result = local_loop.run_until_complete(coro)
            future.set_result(result)
        except Exception as exc:
            future.set_exception(exc)
        finally:
            local_loop.close()

    executor = _get_executor()
    executor.submit(_run)
    return future.result()


def run_async_optional(coro: Coroutine[Any, Any, _T] | None) -> _T | None:
    """Run a coroutine if provided, otherwise return None."""
    if coro is None:
        return None
    return run_async(coro)