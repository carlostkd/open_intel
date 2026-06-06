"""Auth endpoints: login, reset-password, me, logout."""

import os
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Depends, status, Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from api.auth import (
    LoginRequest, LoginResponse, ResetPasswordRequest,
    verify_password, hash_password, create_access_token,
    get_current_user, CurrentUser,
)
from auth.token_blacklist import revoke_token
from db.models import User
from db.session import get_session, get_db
from sqlalchemy.orm import Session
from config import REDIS_URL

router = APIRouter(prefix="/auth", tags=["auth"])

DISABLE_RATE_LIMIT = os.getenv("DISABLE_RATE_LIMIT", "false").lower() == "true"
if DISABLE_RATE_LIMIT:
    _limiter = None
else:
    _limiter = Limiter(key_func=get_remote_address)


def _no_op_decorator(func):
    return func

login_limit = _limiter.limit("5/minute") if _limiter else _no_op_decorator
reset_limit = _limiter.limit("3/minute") if _limiter else _no_op_decorator

def validate_password_strength(password: str) -> None:
    """
    Validate password meets minimum requirements.
    Raises ValueError with a user-friendly message.
    """
    if len(password) < 8:
        raise ValueError(
            "Password must be at least 8 characters"
        )
    if len(password) > 128:
        raise ValueError(
            "Password must be under 128 characters"
        )
    # Must have at least one letter and one number
    has_letter = any(c.isalpha() for c in password)
    has_digit = any(c.isdigit() for c in password)
    if not has_letter or not has_digit:
        raise ValueError(
            "Password must contain at least one "
            "letter and one number"
        )


@router.post("/login", response_model=LoginResponse)
@login_limit
async def login(request: Request, body: LoginRequest, db: Session = Depends(get_db)):
    """
    Authenticate with email + password.
    Returns JWT token.
    """
    user = db.query(User).filter(
        User.email == body.email.lower().strip(),
        User.is_active == True,
    ).first()

    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    user.last_login_at = datetime.now(timezone.utc)
    db.commit()

    token, jti = create_access_token(user.id, user.email)

    return LoginResponse(
        access_token=token,
        must_reset_password=user.must_reset_password,
    )


@router.post("/reset-password")
@reset_limit
async def reset_password(
    request: Request,
    body: ResetPasswordRequest,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(get_current_user),
):
    """
    Reset password. Requires valid JWT token.
    Clears must_reset_password flag on success.
    """
    if body.new_password != body.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password and confirmation do not match",
        )

    try:
        validate_password_strength(body.new_password)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    if not verify_password(body.current_password, current.user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect",
        )

    current.user.hashed_password = hash_password(body.new_password)
    current.user.must_reset_password = False
    db.commit()

    return {"message": "Password updated successfully"}


@router.get("/me")
async def get_me(current: CurrentUser = Depends(get_current_user)):
    """Return current user info. Safe as user is bound to request session."""
    return {
        "id": current.user.id,
        "email": current.user.email,
        "must_reset_password": current.user.must_reset_password,
        "last_login_at": current.user.last_login_at.isoformat() if current.user.last_login_at else None,
    }


@router.post("/logout")
async def logout(
    current: CurrentUser = Depends(get_current_user),
):
    """Logout: revoke the current token."""
    if current.jti and current.exp:
        now = datetime.now(timezone.utc)
        exp = current.exp
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        remaining_seconds = int((exp - now).total_seconds())
        if remaining_seconds > 0:
            success = await revoke_token(current.jti, remaining_seconds)
            if not success and REDIS_URL:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Logout failed due to internal token store error",
                )

    return {"message": "Logged out successfully"}