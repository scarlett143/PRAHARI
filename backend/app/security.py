"""Authentication, authorisation, and Ed25519 identity verification."""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import get_settings
from .database import get_db
from .models import User
from .crypto.identity import (
    ED25519_PUB_BYTES,
    bundle_signing_payload,
    password_reset_signing_payload,
    session_offer_signing_payload,
    verify_ed25519_signature,
)

_hasher = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=4)
_dummy_password_hash = _hasher.hash("prahari-unknown-user-timing-equalizer")
_bearer = HTTPBearer(auto_error=False)

CHALLENGE_TTL_SECONDS = 300


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("password must be at least 12 characters")
    return _hasher.hash(password)


def verify_password(stored_hash: str, password: str) -> tuple[bool, Optional[str]]:
    try:
        _hasher.verify(stored_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False, None
    if _hasher.check_needs_rehash(stored_hash):
        return True, _hasher.hash(password)
    return True, None


def consume_unknown_user_password_cost(password: str) -> None:
    """Burn one Argon2 verification for missing usernames to reduce timing leakage."""
    verify_password(_dummy_password_hash, password)


def issue_access_token(*, user_id: str, username: str, role: str) -> tuple[str, int]:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    ttl = settings.access_token_ttl_minutes
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ttl)).timestamp()),
        "jti": secrets.token_urlsafe(16),
        "iss": "prahari",
        "aud": "prahari-api",
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm), ttl * 60


def decode_access_token(token: str) -> dict:
    settings = get_settings()
    try:
        return jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            audience="prahari-api",
            issuer="prahari",
            options={"require": ["exp", "iat", "sub", "aud", "iss"]},
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="token expired") from None
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="invalid token") from None


def new_challenge() -> str:
    return secrets.token_urlsafe(32)


def verify_signature(*, ed25519_public_key: bytes, message: bytes, signature: bytes) -> bool:
    return verify_ed25519_signature(public_key=ed25519_public_key, message=message, signature=signature)


def verify_key_ownership(*, ed25519_public_key: bytes, challenge: str, signature: bytes) -> bool:
    return verify_signature(
        ed25519_public_key=ed25519_public_key,
        message=challenge.encode("utf-8"),
        signature=signature,
    )


async def current_user(
    credentials: Annotated[Optional[HTTPAuthorizationCredentials], Depends(_bearer)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    claims = decode_access_token(credentials.credentials)
    user = (await db.execute(select(User).where(User.id == claims["sub"]))).scalars().first()
    if user is None:
        raise HTTPException(status_code=401, detail="invalid token")
    if user.status != "active":
        raise HTTPException(status_code=403, detail="account is not active")
    return user


async def require_admin(user: Annotated[User, Depends(current_user)]) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="administrator role required")
    return user


CurrentUser = Annotated[User, Depends(current_user)]
AdminUser = Annotated[User, Depends(require_admin)]
