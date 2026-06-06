"""
Token blacklist using Redis for JWT revocation.

Provides:
- revoke_token(jti, expires_in_seconds): Add JTI to blacklist with TTL
- is_token_revoked(jti): Check if JTI is in blacklist

Gracefully degrades if Redis is unavailable (REDIS_URL not set).
"""

import logging
import redis.asyncio as redis
from typing import Optional

from config import REDIS_URL

logger = logging.getLogger(__name__)

_pool: Optional[redis.ConnectionPool] = None
_redis_client: Optional[redis.Redis] = None
_blacklist_enabled = False
_redis_unavailable = False

BLACKLIST_PREFIX = "blacklist:"


async def _get_redis() -> Optional[redis.Redis]:
    global _pool, _redis_client, _blacklist_enabled, _redis_unavailable

    if _redis_unavailable:
        return None

    if REDIS_URL is None:
        _blacklist_enabled = False
        if not _redis_unavailable:
            logger.info("REDIS_URL not configured — token blacklist disabled")
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
            _blacklist_enabled = True
            logger.info("Token blacklist enabled via Redis")
        except Exception as e:
            logger.warning("Failed to connect to Redis: %s — token blacklist disabled", e)
            _redis_client = None
            _blacklist_enabled = False
            _redis_unavailable = True

    return _redis_client


async def revoke_token(jti: str, expires_in_seconds: int) -> bool:
    """
    Add a JWT ID to the blacklist with TTL matching token expiry.

    Args:
        jti: The JWT ID to revoke
        expires_in_seconds: Seconds until token expiry (used as Redis TTL)

    Returns:
        True if added to blacklist, False if blacklist disabled
    """
    client = await _get_redis()
    if client is None or not _blacklist_enabled:
        return False

    try:
        key = f"{BLACKLIST_PREFIX}{jti}"
        await client.setex(key, expires_in_seconds, "revoked")
        return True
    except Exception as e:
        logger.error("Failed to revoke token %s: %s", jti, e)
        return False


async def is_token_revoked(jti: str) -> bool:
    """
    Check if a JWT ID has been revoked.

    Args:
        jti: The JWT ID to check

    Returns:
        True if the token is revoked, False otherwise
    """
    client = await _get_redis()
    if client is None or not _blacklist_enabled:
        return False

    try:
        key = f"{BLACKLIST_PREFIX}{jti}"
        result = await client.exists(key)
        return result > 0
    except Exception as e:
        logger.error("Failed to check token revocation for %s: %s", jti, e)
        return False


async def close():
    """Close Redis connection pool."""
    global _pool, _redis_client

    if _redis_client is not None:
        await _redis_client.aclose()
        _redis_client = None
    if _pool is not None:
        await _pool.disconnect()
        _pool = None