"""
Per-user API key resolution with fallback chain.

resolve_api_key checks the user's personal key first, then falls back to
the server-level environment variable in config.py.
"""

from sqlalchemy import select as sa_select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import UserApiKey
from utils.encryption import decrypt_api_key
import config as _config


async def get_user_key(user_id: int, key_name: str, session: AsyncSession) -> str | None:
    result = await session.execute(
        sa_select(UserApiKey).where(
            UserApiKey.user_id == user_id,
            UserApiKey.key_name == key_name,
        )
    )
    record = result.scalar_one_or_none()
    if record:
        return decrypt_api_key(record.encrypted_value)
    return None


async def resolve_api_key(user_id: int, key_name: str, session: AsyncSession) -> str:
    user_key = await get_user_key(user_id, key_name, session)
    if user_key:
        return user_key
    return getattr(_config, key_name, "") or ""
