"""
Circuit breaker for search engine resilience using Redis.

Provides shared, persistent state across Uvicorn workers:
- circuit:{engine_name}:failures — integer counter
- circuit:{engine_name}:last_success — Unix timestamp
- circuit:{engine_name}:state — "closed" | "open" | "half_open"

Gracefully degrades to in-memory dict if Redis is unavailable.
"""

import logging
import time
from typing import Optional

from config import REDIS_URL

try:
    import redis.asyncio as redis
    _redis_available = True
except ImportError:
    redis = None  # type: ignore[assignment]
    _redis_available = False

logger = logging.getLogger(__name__)

FAILURE_THRESHOLD = 8
OPEN_DURATION_SECONDS = 900
HALF_OPEN_TEST_INTERVAL = 60
HALF_OPEN_MAX_ATTEMPTS = 2

CIRCUIT_PREFIX = "circuit:"

_pool = None
_redis_client = None
_circuit_breaker_enabled = False
_redis_unavailable = False  # latched True once we decide Redis isn't reachable

_engine_failures: dict[str, int] = {}
_engine_last_success: dict[str, float] = {}
_engine_state: dict[str, str] = {}
_engine_open_time: dict[str, float] = {}


async def _get_redis():
    global _pool, _redis_client, _circuit_breaker_enabled, _redis_unavailable

    if not _redis_available or _redis_unavailable:
        return None

    if REDIS_URL is None:
        _circuit_breaker_enabled = False
        if not _redis_unavailable:
            logger.info("REDIS_URL not configured — circuit breaker using in-memory fallback")
        _redis_unavailable = True
        return None

    if _redis_client is None:
        try:
            _pool = redis.ConnectionPool.from_url(
                REDIS_URL,
                decode_responses=True,
            )
            _redis_client = redis.Redis(connection_pool=_pool)
            await _redis_client.ping()
            _circuit_breaker_enabled = True
            logger.info("Circuit breaker enabled via Redis")
        except Exception as e:
            logger.warning("Failed to connect to Redis: %s — circuit breaker using in-memory fallback", e)
            _redis_client = None
            _circuit_breaker_enabled = False
            _redis_unavailable = True

    return _redis_client


async def record_failure(engine_name: str) -> None:
    """
    Record a failure for the given engine. Opens circuit after FAILURE_THRESHOLD failures.
    """
    client = await _get_redis()

    if client is None or not _circuit_breaker_enabled:
        _fallback_record_failure(engine_name)
        return

    try:
        failure_key = f"{CIRCUIT_PREFIX}{engine_name}:failures"
        state_key = f"{CIRCUIT_PREFIX}{engine_name}:state"

        failures = await client.incr(failure_key)
        logger.debug(f"Engine {engine_name} failures: {failures}")

        if failures >= FAILURE_THRESHOLD:
            await client.set(state_key, "open")
            await client.set(f"{CIRCUIT_PREFIX}{engine_name}:last_failure", str(time.time()))
            logger.warning(f"Circuit opened for {engine_name} after {failures} failures")
    except Exception as e:
        logger.error(f"Failed to record failure for {engine_name}: %s", e)
        _fallback_record_failure(engine_name)


async def record_success(engine_name: str) -> None:
    """
    Record a success for the given engine. Resets failure counter and closes circuit.
    """
    client = await _get_redis()

    if client is None or not _circuit_breaker_enabled:
        _fallback_record_success(engine_name)
        return

    try:
        failure_key = f"{CIRCUIT_PREFIX}{engine_name}:failures"
        state_key = f"{CIRCUIT_PREFIX}{engine_name}:state"
        success_key = f"{CIRCUIT_PREFIX}{engine_name}:last_success"

        await client.set(failure_key, "0")
        await client.set(state_key, "closed")
        await client.set(success_key, str(time.time()))
        logger.debug(f"Circuit closed for {engine_name}")
    except Exception as e:
        logger.error(f"Failed to record success for {engine_name}: %s", e)
        _fallback_record_success(engine_name)


async def is_open(engine_name: str) -> bool:
    """
    Check if circuit is open for the given engine.
    Auto-transitions from open -> half_open after OPEN_DURATION_SECONDS.
    Auto-transitions from half_open -> closed on success.
    """
    client = await _get_redis()

    if client is None or not _circuit_breaker_enabled:
        return _fallback_is_open(engine_name)

    try:
        state_key = f"{CIRCUIT_PREFIX}{engine_name}:state"
        last_failure_key = f"{CIRCUIT_PREFIX}{engine_name}:last_failure"

        state = await client.get(state_key) or "closed"

        if state == "open":
            last_failure = await client.get(last_failure_key)
            if last_failure:
                elapsed = time.time() - float(last_failure)
                if elapsed >= OPEN_DURATION_SECONDS:
                    await client.set(state_key, "half_open")
                    logger.info(f"Circuit for {engine_name} transitioned to half_open")
                    return False
            return True

        if state == "half_open":
            last_failure = await client.get(last_failure_key)
            if last_failure:
                elapsed = time.time() - float(last_failure)
                if elapsed >= HALF_OPEN_TEST_INTERVAL:
                    await client.set(state_key, "half_open")
                    return False
            return False

        return False
    except Exception as e:
        logger.error(f"Failed to check circuit state for {engine_name}: %s", e)
        return _fallback_is_open(engine_name)


async def get_all_states() -> dict:
    """
    Get the current state of all circuit breakers.
    Returns dict mapping engine_name to {state, failures, last_success}.
    """
    client = await _get_redis()

    if client is None or not _circuit_breaker_enabled:
        return _fallback_get_all_states()

    result = {}
    try:
        keys = await client.keys(f"{CIRCUIT_PREFIX}*:state")
        for key in keys:
            engine_name = key.replace(f"{CIRCUIT_PREFIX}", "").replace(":state", "")
            state = await client.get(key) or "closed"
            failures = await client.get(f"{CIRCUIT_PREFIX}{engine_name}:failures") or "0"
            last_success = await client.get(f"{CIRCUIT_PREFIX}{engine_name}:last_success")

            result[engine_name] = {
                "state": state,
                "failures": int(failures),
                "last_success": last_success,
            }
    except Exception as e:
        logger.error(f"Failed to get circuit states: %s", e)
        return _fallback_get_all_states()

    return result


def _fallback_record_failure(engine_name: str) -> None:
    _engine_failures[engine_name] = _engine_failures.get(engine_name, 0) + 1
    if _engine_failures[engine_name] >= FAILURE_THRESHOLD:
        _engine_state[engine_name] = "open"
        _engine_open_time[engine_name] = time.time()
        logger.warning(f"[Fallback] Circuit opened for {engine_name}")


def _fallback_record_success(engine_name: str) -> None:
    _engine_failures[engine_name] = 0
    _engine_last_success[engine_name] = time.time()
    _engine_state[engine_name] = "closed"
    logger.debug(f"[Fallback] Circuit closed for {engine_name}")


def _fallback_is_open(engine_name: str) -> bool:
    state = _engine_state.get(engine_name, "closed")

    if state == "open":
        open_time = _engine_open_time.get(engine_name, 0)
        if time.time() - open_time >= OPEN_DURATION_SECONDS:
            _engine_state[engine_name] = "half_open"
            logger.info(f"[Fallback] Circuit for {engine_name} transitioned to half_open")
            return False
        return True

    if state == "half_open":
        return False

    return False


def _fallback_get_all_states() -> dict:
    result = {}
    for engine_name in _engine_state:
        result[engine_name] = {
            "state": _engine_state[engine_name],
            "failures": _engine_failures.get(engine_name, 0),
            "last_success": str(_engine_last_success.get(engine_name, 0)),
        }
    return result


async def close() -> None:
    """Close Redis connection pool."""
    global _pool, _redis_client

    if _redis_client is not None:
        await _redis_client.aclose()
        _redis_client = None
    if _pool is not None:
        await _pool.disconnect()
        _pool = None