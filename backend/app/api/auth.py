from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import security
from ..crypto import pqc
from ..database import get_db
from ..models import User
from ..security import CurrentUser
from .common import audit, b64d, b64e

router = APIRouter(prefix="/api/v2", tags=["auth"])


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=256)
    ed25519_public_key: str

    @field_validator("password")
    @classmethod
    def reject_trivial_passwords(cls, value: str) -> str:
        if value.lower() in {"password1234", "changemeplease", "123456789012"}:
            raise ValueError("password is too common")
        return value


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: str
    username: str
    role: str
    key_verified: bool


class PublishKeysRequest(BaseModel):
    x25519_public_key: str
    ml_kem_encapsulation_key: str
    challenge_signature: str
    bundle_signature: str


def token_response(user: User) -> TokenResponse:
    token, ttl = security.issue_access_token(user_id=user.id, username=user.username, role=user.role)
    return TokenResponse(
        access_token=token,
        expires_in=ttl,
        user_id=user.id,
        username=user.username,
        role=user.role,
        key_verified=user.key_verified,
    )


@router.post("/auth/register", response_model=TokenResponse)
async def register(
    body: RegisterRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    existing = (await db.execute(select(User).where(User.username == body.username))).scalars().first()
    if existing:
        raise HTTPException(400, "registration failed")

    ed_pub = b64d(body.ed25519_public_key, expect=32, field="ed25519_public_key")
    try:
        password_hash = security.hash_password(body.password)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None

    user = User(username=body.username, password_hash=password_hash, ed25519_public_key=ed_pub)
    db.add(user)
    await db.flush()
    await audit(db, event="user.register", actor_id=user.id, request=request)
    await db.commit()
    await db.refresh(user)
    return token_response(user)


@router.post("/auth/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    user = (await db.execute(select(User).where(User.username == body.username))).scalars().first()
    if user is None:
        security.consume_unknown_user_password_cost(body.password)
        raise HTTPException(401, "invalid credentials")

    ok, rehash = security.verify_password(user.password_hash, body.password)
    if not ok:
        await audit(db, event="auth.failed_login", actor_id=user.id, severity="medium", request=request)
        await db.commit()
        raise HTTPException(401, "invalid credentials")
    if user.status != "active":
        raise HTTPException(403, "account is not active")

    if rehash:
        user.password_hash = rehash
    user.last_login = datetime.now(timezone.utc)
    await audit(db, event="auth.login", actor_id=user.id, request=request)
    await db.commit()
    return token_response(user)


@router.get("/auth/me")
async def me(user: CurrentUser):
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "kind": user.kind,
        "status": user.status,
        "key_verified": user.key_verified,
        "created_at": user.created_at,
    }


@router.post("/auth/challenge")
async def challenge(user: CurrentUser, db: Annotated[AsyncSession, Depends(get_db)]):
    value = security.new_challenge()
    user.pending_challenge = value
    user.challenge_issued_at = datetime.now(timezone.utc)
    await db.commit()
    return {"challenge": value, "ttl_seconds": security.CHALLENGE_TTL_SECONDS}


@router.post("/keys/publish")
async def publish_keys(
    body: PublishKeysRequest,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    if not user.pending_challenge or not user.challenge_issued_at:
        raise HTTPException(400, "request a challenge first")

    issued = user.challenge_issued_at
    if issued.tzinfo is None:
        issued = issued.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) - issued > timedelta(seconds=security.CHALLENGE_TTL_SECONDS):
        user.pending_challenge = None
        await db.commit()
        raise HTTPException(400, "challenge expired")

    x_pub = b64d(body.x25519_public_key, expect=32, field="x25519_public_key")
    ml_pub = b64d(body.ml_kem_encapsulation_key, expect=pqc.EK_BYTES, field="ml_kem_encapsulation_key")
    challenge_sig = b64d(body.challenge_signature, expect=64, field="challenge_signature")
    bundle_sig = b64d(body.bundle_signature, expect=64, field="bundle_signature")

    if not security.verify_key_ownership(
        ed25519_public_key=user.ed25519_public_key,
        challenge=user.pending_challenge,
        signature=challenge_sig,
    ):
        await audit(db, event="keys.ownership_proof_failed", actor_id=user.id, severity="high", request=request)
        await db.commit()
        raise HTTPException(400, "key ownership proof failed")

    payload = security.bundle_signing_payload(
        x25519_public_key=x_pub, ml_kem_encapsulation_key=ml_pub
    )
    if not security.verify_signature(
        ed25519_public_key=user.ed25519_public_key,
        message=payload,
        signature=bundle_sig,
    ):
        await audit(db, event="keys.bundle_signature_failed", actor_id=user.id, severity="high", request=request)
        await db.commit()
        raise HTTPException(400, "key bundle signature failed")

    user.x25519_public_key = x_pub
    user.ml_kem_encapsulation_key = ml_pub
    user.key_bundle_signature = bundle_sig
    user.key_verified = True
    user.pending_challenge = None
    user.challenge_issued_at = None
    await audit(db, event="keys.published", actor_id=user.id, request=request)
    await db.commit()
    return {"key_verified": True, "algorithm": f"X25519 + {pqc.ALGORITHM}"}


@router.get("/keys/{username}")
async def get_key_bundle(
    username: str,
    _: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    target = (await db.execute(select(User).where(User.username == username))).scalars().first()
    if target is None or not target.key_verified:
        raise HTTPException(404, "no verified key bundle for that user")
    return {
        "user_id": target.id,
        "username": target.username,
        "ed25519_public_key": b64e(target.ed25519_public_key),
        "x25519_public_key": b64e(target.x25519_public_key),
        "ml_kem_encapsulation_key": b64e(target.ml_kem_encapsulation_key),
        "bundle_signature": b64e(target.key_bundle_signature),
        "key_verified": True,
        "algorithm": f"X25519 + {pqc.ALGORITHM}",
    }
