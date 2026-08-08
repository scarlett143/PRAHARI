"""Passkey registration and sign-in.

A passkey is an *additional* way in, never the only one, and never something that can lock
someone out. That follows from the credential hierarchy this system already settled on:
the identity key outranks everything, because it is what decrypts the messages every other
factor exists to protect and the only way back from a lost device. So an identity-key
password reset evicts registered passkeys along with TOTP, and a user who loses their
authenticator still recovers through the identity key exactly as before.

Verification lives in `crypto/webauthn.py`, which explains why this needs no WebAuthn
dependency.
"""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import security
from ..config import get_settings
from ..crypto import webauthn
from ..database import get_db
from ..models import PasskeyCredential, User
from ..security import CurrentUser
from .common import audit, b64d
from .auth import token_response

router = APIRouter(prefix="/api/v2/auth/passkeys", tags=["passkeys"])
settings = get_settings()

#: Long enough to cross a fingerprint prompt or a phone hand-off, short enough that a
#: challenge captured from a screen is useless by the time it is typed anywhere.
CHALLENGE_TTL_SECONDS = 180


async def _issue_challenge(db: AsyncSession, user: User) -> str:
    challenge = webauthn.b64url_encode(secrets.token_bytes(32))
    user.webauthn_challenge = challenge
    user.webauthn_challenge_at = datetime.now(timezone.utc)
    await db.commit()
    return challenge


def _take_challenge(user: User) -> str:
    """Read the pending challenge and require it to be fresh.

    The caller clears it on *every* path, success or failure. A challenge that survives a
    failed attempt is a challenge that can be retried, which is the whole property a nonce
    is supposed to remove.
    """
    issued = user.webauthn_challenge_at
    if not user.webauthn_challenge or issued is None:
        raise HTTPException(400, "request a challenge first")
    if issued.tzinfo is None:
        issued = issued.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) - issued > timedelta(seconds=CHALLENGE_TTL_SECONDS):
        raise HTTPException(400, "challenge expired")
    return user.webauthn_challenge


def _clear_challenge(user: User) -> None:
    user.webauthn_challenge = None
    user.webauthn_challenge_at = None


def _serialize(credential: PasskeyCredential) -> dict:
    return {
        "id": credential.id,
        "label": credential.label,
        "created_at": credential.created_at,
        "last_used_at": credential.last_used_at,
    }


# -- registration ------------------------------------------------------------


@router.post("/register/challenge")
async def registration_challenge(
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    challenge = await _issue_challenge(db, user)
    existing = (
        await db.execute(
            select(PasskeyCredential.credential_id).where(PasskeyCredential.user_id == user.id)
        )
    ).scalars().all()
    return {
        "challenge": challenge,
        "rp": {"id": settings.webauthn_relying_party, "name": settings.webauthn_rp_name},
        "user": {
            # The user handle is the account id, not the username: WebAuthn stores this on
            # the authenticator, and a username can be changed while an id cannot.
            "id": webauthn.b64url_encode(user.id.encode("utf-8")),
            "name": user.username,
            "displayName": user.username,
        },
        # So the browser refuses to enrol a key this account already has, rather than
        # creating a duplicate the user cannot tell apart in the list.
        "excludeCredentials": [webauthn.b64url_encode(row) for row in existing],
        "timeout_ms": CHALLENGE_TTL_SECONDS * 1000,
    }


class RegisterRequest(BaseModel):
    credential_id: str = Field(min_length=1, max_length=2048)
    client_data_json: str = Field(min_length=1, max_length=8192)
    authenticator_data: str = Field(min_length=1, max_length=8192)
    #: SPKI DER from the browser's getPublicKey(). See crypto/webauthn.py for why this
    #: shape is taken instead of the attestation object.
    public_key: str = Field(min_length=1, max_length=4096)
    label: str = Field(default="", max_length=64)


@router.post("/register")
async def register_passkey(
    body: RegisterRequest,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    challenge = _take_challenge(user)
    credential_id = webauthn.b64url_decode(body.credential_id)
    public_key = b64d(body.public_key, field="public_key")

    try:
        parsed = webauthn.verify_registration(
            client_data_json=webauthn.b64url_decode(body.client_data_json),
            authenticator_data=webauthn.b64url_decode(body.authenticator_data),
            public_key_der=public_key,
            challenge=challenge,
            rp_id=settings.webauthn_relying_party,
            origins=settings.webauthn_origins,
        )
    except webauthn.WebAuthnError as exc:
        _clear_challenge(user)
        await audit(
            db,
            event="passkey.registration_failed",
            actor_id=user.id,
            severity="medium",
            request=request,
            detail=str(exc),
        )
        await db.commit()
        raise HTTPException(400, "passkey registration failed") from None

    _clear_challenge(user)
    duplicate = (
        await db.execute(
            select(PasskeyCredential).where(PasskeyCredential.credential_id == credential_id)
        )
    ).scalars().first()
    if duplicate is not None:
        await db.commit()
        raise HTTPException(409, "that passkey is already registered")

    credential = PasskeyCredential(
        user_id=user.id,
        credential_id=credential_id,
        public_key=public_key,
        sign_count=parsed.sign_count,
        label=body.label.strip() or None,
    )
    db.add(credential)
    await audit(
        db, event="passkey.registered", actor_id=user.id, severity="medium", request=request
    )
    await db.commit()
    await db.refresh(credential)
    return _serialize(credential)


@router.get("")
async def list_passkeys(user: CurrentUser, db: Annotated[AsyncSession, Depends(get_db)]):
    rows = (
        await db.execute(
            select(PasskeyCredential)
            .where(PasskeyCredential.user_id == user.id)
            .order_by(PasskeyCredential.created_at.asc())
        )
    ).scalars().all()
    return [_serialize(row) for row in rows]


@router.delete("/{credential_id}")
async def remove_passkey(
    credential_id: str,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    credential = (
        await db.execute(
            select(PasskeyCredential).where(
                PasskeyCredential.id == credential_id, PasskeyCredential.user_id == user.id
            )
        )
    ).scalars().first()
    if credential is None:
        raise HTTPException(404, "no such passkey")

    await db.delete(credential)
    await audit(
        db, event="passkey.removed", actor_id=user.id, severity="medium", request=request
    )
    await db.commit()
    # Removing the last passkey is allowed on purpose: the password plus the identity-key
    # reset path remain, so this cannot strand anyone.
    return {"removed": credential_id}


# -- sign-in -----------------------------------------------------------------


class LoginChallengeRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)


@router.post("/login/challenge")
async def login_challenge(
    body: LoginChallengeRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Start a passkey sign-in.

    Answers identically for an unknown username and for a known one with no passkeys: a
    real challenge and an empty credential list. Refusing here would turn this endpoint
    into a way to ask which accounts exist.
    """
    user = (
        await db.execute(select(User).where(User.username == body.username))
    ).scalars().first()

    if user is None or user.status != "active":
        return {
            "challenge": webauthn.b64url_encode(secrets.token_bytes(32)),
            "allowCredentials": [],
            "rp_id": settings.webauthn_relying_party,
            "timeout_ms": CHALLENGE_TTL_SECONDS * 1000,
        }

    challenge = await _issue_challenge(db, user)
    rows = (
        await db.execute(
            select(PasskeyCredential.credential_id).where(PasskeyCredential.user_id == user.id)
        )
    ).scalars().all()
    return {
        "challenge": challenge,
        "allowCredentials": [webauthn.b64url_encode(row) for row in rows],
        "rp_id": settings.webauthn_relying_party,
        "timeout_ms": CHALLENGE_TTL_SECONDS * 1000,
    }


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    credential_id: str = Field(min_length=1, max_length=2048)
    client_data_json: str = Field(min_length=1, max_length=8192)
    authenticator_data: str = Field(min_length=1, max_length=8192)
    signature: str = Field(min_length=1, max_length=4096)


@router.post("/login")
async def login_with_passkey(
    body: LoginRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Complete a passkey sign-in and mint a session.

    No password and no TOTP prompt. That is not a downgrade: possession of the
    authenticator plus the user-presence test it enforces is already two factors, and
    unlike a password the assertion cannot be replayed or phished onto another origin --
    the origin is inside the signed client data.
    """
    generic = HTTPException(401, "passkey authentication failed")

    user = (
        await db.execute(select(User).where(User.username == body.username))
    ).scalars().first()
    if user is None or user.status != "active":
        raise generic

    credential_id = webauthn.b64url_decode(body.credential_id)
    credential = (
        await db.execute(
            select(PasskeyCredential).where(
                PasskeyCredential.credential_id == credential_id,
                # Scoped to this account: without it, a valid assertion for one user's
                # credential would authenticate whoever named themselves in `username`.
                PasskeyCredential.user_id == user.id,
            )
        )
    ).scalars().first()
    if credential is None:
        raise generic

    try:
        challenge = _take_challenge(user)
        parsed = webauthn.verify_assertion(
            client_data_json=webauthn.b64url_decode(body.client_data_json),
            authenticator_data=webauthn.b64url_decode(body.authenticator_data),
            signature=webauthn.b64url_decode(body.signature),
            public_key_der=credential.public_key,
            challenge=challenge,
            rp_id=settings.webauthn_relying_party,
            origins=settings.webauthn_origins,
            stored_sign_count=credential.sign_count,
        )
    except (webauthn.WebAuthnError, HTTPException) as exc:
        _clear_challenge(user)
        await audit(
            db,
            event="passkey.login_failed",
            actor_id=user.id,
            severity="high",
            request=request,
            detail=str(getattr(exc, "detail", exc)),
        )
        await db.commit()
        raise generic from None

    _clear_challenge(user)
    credential.sign_count = max(parsed.sign_count, credential.sign_count)
    credential.last_used_at = datetime.now(timezone.utc)
    user.last_login = datetime.now(timezone.utc)
    await audit(db, event="auth.login_passkey", actor_id=user.id, request=request)
    await db.commit()
    return await token_response(db, user, request)
