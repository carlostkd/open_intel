"""
JWT authentication for Open_Intel API.

Flow:
1. POST /auth/login → returns access_token (JWT, 8hr expiry)
2. All protected routes require: Authorization: Bearer {token}
3. First login with default password → returns {must_reset: true}
4. POST /auth/reset-password → sets new password, clears must_reset flag
"""

import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy.orm import Session

from config import JWT_SECRET
from db.models import User
from db.session import get_session, get_db
from auth.token_blacklist import is_token_revoked

# Config — single canonical source from config.py
SECRET = JWT_SECRET
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 8

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer()


# ─── Pydantic schemas ──────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    must_reset_password: bool

class ResetPasswordRequest(BaseModel):
    current_password: str
    new_password: str
    confirm_password: str

class TokenData(BaseModel):
    user_id: int
    email: str
    jti: Optional[str] = None


# ─── Core functions ────────────────────────────────────────────────────────

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)

def create_access_token(user_id: int, email: str) -> tuple[str, str]:
    jti = secrets.token_hex(16)
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "email": email,
        "jti": jti,
        "exp": now + timedelta(hours=JWT_EXPIRY_HOURS),
        "iat": now,
    }
    token = jwt.encode(payload, SECRET, algorithm=JWT_ALGORITHM)
    return token, jti

class TokenPayload(BaseModel):
    user_id: int
    email: str
    jti: str
    exp: datetime


def decode_token(token: str) -> TokenPayload:
    payload = jwt.decode(token, SECRET, algorithms=[JWT_ALGORITHM])
    user_id = int(payload["sub"])
    email = payload["email"]
    jti = payload.get("jti", "")
    exp = payload["exp"]
    return TokenPayload(user_id=user_id, email=email, jti=jti, exp=exp)


from pydantic import BaseModel, ConfigDict


# ─── FastAPI dependency ────────────────────────────────────────────────────

class CurrentUser(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    user: User
    jti: str
    exp: Optional[datetime] = None


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> CurrentUser:
    """
    Dependency for protected routes.
    Usage: current: CurrentUser = Depends(get_current_user)
    Now uses request-scoped 'db' session to ensure user is not detached.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    revoked_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token has been revoked",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        token_payload = decode_token(credentials.credentials)
    except JWTError:
        raise credentials_exception

    if token_payload.jti:
        if await is_token_revoked(token_payload.jti):
            raise revoked_exception

    user = db.query(User).filter(
        User.id == token_payload.user_id,
        User.is_active == True,
    ).first()

    if not user:
        raise credentials_exception

    return CurrentUser(user=user, jti=token_payload.jti, exp=token_payload.exp)


async def require_password_not_reset_pending(
    current_user: CurrentUser = Depends(get_current_user),
) -> CurrentUser:
    """Dependency for resource-creating endpoints — blocks access when a password reset is required."""
    if getattr(current_user.user, "must_reset_password", False):
        raise HTTPException(
            status_code=403,
            detail={
                "error": "password_reset_required",
                "message": (
                    "You must change your password before continuing. "
                    "Use POST /auth/reset-password"
                ),
                "code": "PASSWORD_RESET_REQUIRED",
            },
        )
    return current_user
