from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import security
from ..crypto import pqc, totp
from ..database import get_db
from ..models import Session, User
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
    #: Required only once the account has a confirmed second factor.
    totp_code: str | None = Field(default=None, max_length=12)


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


async def token_response(
    db: AsyncSession, user: User, request: Request | None = None
) -> TokenResponse:
    """Issue a token and register the session it belongs to.

    The two happen together on purpose: a token minted without a session row is one that
    can never be listed or revoked, and validation now refuses those outright.
    """
    token, ttl, jti, expires_at = security.issue_access_token(
        user_id=user.id, username=user.username, role=user.role
    )
    security.record_session(
        db, user_id=user.id, jti=jti, expires_at=expires_at, request=request
    )
    await db.commit()
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
    return await token_response(db, user, request)


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

    if user.totp_enabled:
        # A distinct answer once the password is known good. It does reveal that the
        # password was correct, which is unavoidable -- the client cannot be asked for a
        # code it was never told to collect -- and is what every second-factor flow does.
        if not body.totp_code:
            raise HTTPException(
                401,
                detail={
                    "code": "totp_required",
                    "message": "this account requires a verification code",
                },
            )
        if not totp.verify(user.totp_secret, body.totp_code):
            await audit(
                db, event="auth.totp_failed", actor_id=user.id, severity="medium", request=request
            )
            await db.commit()
            raise HTTPException(401, detail={"code": "totp_invalid", "message": "that code is not valid"})

    if rehash:
        user.password_hash = rehash
    user.last_login = datetime.now(timezone.utc)
    await audit(db, event="auth.login", actor_id=user.id, request=request)
    await db.commit()
    return await token_response(db, user, request)


@router.get("/auth/me")
async def me(user: CurrentUser):
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "kind": user.kind,
        "status": user.status,
        "key_verified": user.key_verified,
        "totp_enabled": bool(user.totp_enabled),
        "created_at": user.created_at,
    }


class RecoveryChallengeRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)


class PasswordResetRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    challenge: str = Field(min_length=1, max_length=128)
    signature: str
    new_password: str = Field(min_length=12, max_length=256)

    @field_validator("new_password")
    @classmethod
    def reject_trivial_passwords(cls, value: str) -> str:
        if value.lower() in {"password1234", "changemeplease", "123456789012"}:
            raise ValueError("password is too common")
        return value


@router.post("/auth/recovery/challenge")
async def recovery_challenge(
    body: RecoveryChallengeRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Issue a nonce for a password reset proved with the account's identity key.

    Unauthenticated by necessity -- the caller has lost the password, which is the only
    thing `login` would have accepted. What replaces it is a signature from the Ed25519
    private key the account was registered with, which is a strictly stronger claim: that
    key is the account, and no message in the system is readable without it.

    A challenge is returned whether or not the username exists, so this cannot be used to
    enumerate accounts. For an unknown name the value is simply one that will never
    verify.
    """
    user = (
        await db.execute(select(User).where(User.username == body.username))
    ).scalars().first()

    value = security.new_challenge()
    if user is not None and user.status == "active":
        user.pending_challenge = value
        user.challenge_issued_at = datetime.now(timezone.utc)
        await db.commit()

    return {"challenge": value, "ttl_seconds": security.CHALLENGE_TTL_SECONDS}


@router.post("/auth/recovery/reset", response_model=TokenResponse)
async def recovery_reset(
    body: PasswordResetRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Set a new password on proof of holding the account's Ed25519 private key.

    Signing in immediately afterwards is safe: the proof just given is stronger than the
    password being replaced.

    Note what this does NOT restore. The password only ever authenticated to the server;
    message history is decryptable solely with the private keys in the browser's storage.
    Someone who still has those keys can reset a forgotten password here. Someone who has
    lost them has lost the account, and no server-side flow can change that.
    """
    generic = HTTPException(400, "password reset failed")

    user = (
        await db.execute(select(User).where(User.username == body.username))
    ).scalars().first()
    if user is None or user.status != "active":
        raise generic
    if not user.pending_challenge or not user.challenge_issued_at:
        raise generic

    issued = user.challenge_issued_at
    if issued.tzinfo is None:
        issued = issued.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) - issued > timedelta(seconds=security.CHALLENGE_TTL_SECONDS):
        user.pending_challenge = None
        user.challenge_issued_at = None
        await db.commit()
        raise HTTPException(400, "challenge expired")

    # Compare against the stored challenge rather than trusting the one supplied, so a
    # caller cannot pick the nonce they already hold a signature for.
    if not secrets.compare_digest(user.pending_challenge, body.challenge):
        raise generic

    signature = b64d(body.signature, expect=64, field="signature")
    payload = security.password_reset_signing_payload(
        username=user.username,
        challenge=user.pending_challenge,
        new_password_digest=hashlib.sha256(body.new_password.encode("utf-8")).digest(),
    )
    if not security.verify_signature(
        ed25519_public_key=user.ed25519_public_key,
        message=payload,
        signature=signature,
    ):
        # Burn the challenge: a failed proof must not leave a live nonce to grind against.
        user.pending_challenge = None
        user.challenge_issued_at = None
        await audit(
            db,
            event="auth.password_reset_proof_failed",
            actor_id=user.id,
            severity="high",
            request=request,
        )
        await db.commit()
        raise generic

    try:
        user.password_hash = security.hash_password(body.new_password)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None

    user.pending_challenge = None
    user.challenge_issued_at = None
    user.last_login = datetime.now(timezone.utc)
    # Clearing the second factor here is deliberate. A reset is proved with the identity
    # key, which is a strictly stronger credential than password-plus-code -- it is the
    # thing that decrypts the messages a second factor exists to protect. Leaving TOTP on
    # would also make a lost authenticator unrecoverable, since this is the only way back.
    if user.totp_enabled or user.totp_secret:
        user.totp_enabled = False
        user.totp_secret = None
    await audit(
        db,
        event="auth.password_reset",
        actor_id=user.id,
        severity="medium",
        request=request,
    )
    await security.revoke_sessions(db, user_id=user.id)
    await db.commit()
    return await token_response(db, user, request)


class TotpEnableRequest(BaseModel):
    code: str = Field(min_length=6, max_length=12)


class TotpDisableRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)
    code: str = Field(min_length=6, max_length=12)


@router.post("/auth/2fa/setup")
async def totp_setup(
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Mint a secret and hand back what an authenticator needs to import it.

    The secret is stored immediately but `totp_enabled` stays false, so an abandoned
    setup never becomes a factor the account is judged against. Calling this again
    replaces an unconfirmed secret, which is what someone retrying after losing the first
    screen expects.
    """
    if user.totp_enabled:
        raise HTTPException(409, "two-step verification is already on")

    secret = totp.generate_secret()
    user.totp_secret = secret
    user.totp_enabled = False
    await db.commit()
    return {
        "secret": secret,
        "formatted_secret": totp.format_for_entry(secret),
        "otpauth_uri": totp.provisioning_uri(secret, username=user.username),
        "digits": totp.DIGITS,
        "period_seconds": totp.PERIOD_SECONDS,
    }


@router.post("/auth/2fa/enable")
async def totp_enable(
    body: TotpEnableRequest,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Confirm the authenticator agrees before the factor starts being required.

    Turning it on without this check is how people lock themselves out: a mistyped
    secret or a badly skewed clock would only surface at the next sign-in, when it is too
    late to fix from inside the account.
    """
    if user.totp_enabled:
        raise HTTPException(409, "two-step verification is already on")
    if not user.totp_secret:
        raise HTTPException(409, "start setup first")
    if not totp.verify(user.totp_secret, body.code):
        raise HTTPException(400, "that code is not valid — check your device's clock")

    user.totp_enabled = True
    await audit(
        db, event="auth.totp_enabled", actor_id=user.id, severity="medium", request=request
    )
    await db.commit()
    return {"totp_enabled": True}


@router.post("/auth/2fa/disable")
async def totp_disable(
    body: TotpDisableRequest,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Both the password and a current code, because an unlocked session is not proof.

    The realistic threat is someone who sat down at a signed-in machine. Requiring the
    two factors again means switching protection off costs exactly what getting in did.
    """
    if not user.totp_enabled:
        raise HTTPException(409, "two-step verification is not on")

    ok, _ = security.verify_password(user.password_hash, body.password)
    if not ok or not totp.verify(user.totp_secret, body.code):
        await audit(
            db, event="auth.totp_disable_failed", actor_id=user.id, severity="high", request=request
        )
        await db.commit()
        raise HTTPException(400, "password or code is not valid")

    user.totp_enabled = False
    user.totp_secret = None
    await audit(
        db, event="auth.totp_disabled", actor_id=user.id, severity="high", request=request
    )
    await db.commit()
    return {"totp_enabled": False}


@router.get("/auth/sessions")
async def list_sessions(user: CurrentUser, db: Annotated[AsyncSession, Depends(get_db)]):
    """Every place this account is currently signed in.

    Only live sessions are listed: a revoked or expired one is no longer a way in, and
    showing it would turn a security screen into a history page.
    """
    now = datetime.now(timezone.utc)
    rows = (
        await db.execute(
            select(Session)
            .where(
                Session.user_id == user.id,
                Session.revoked_at.is_(None),
                Session.expires_at > now,
            )
            .order_by(Session.last_seen_at.desc())
        )
    ).scalars().all()

    return [
        {
            "id": row.id,
            "kind": row.kind,
            "user_agent": row.user_agent,
            "ip_address": row.ip_address,
            "created_at": row.created_at,
            "last_seen_at": row.last_seen_at,
            "expires_at": row.expires_at,
            # So the UI can label one "this device" and refuse to let you cut your own
            # branch without meaning to.
            "current": row.id == getattr(user, "current_session_id", None),
        }
        for row in rows
    ]


@router.delete("/auth/sessions/{session_id}")
async def revoke_session(
    session_id: str,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Sign one session out. Its token stops working on the next request it makes."""
    session = (
        await db.execute(
            select(Session).where(Session.id == session_id, Session.user_id == user.id)
        )
    ).scalars().first()
    if session is None:
        raise HTTPException(404, "session not found")
    if session.revoked_at is None:
        session.revoked_at = datetime.now(timezone.utc)
    await audit(
        db,
        event="auth.session_revoked",
        actor_id=user.id,
        severity="medium",
        request=request,
        detail=session_id,
    )
    await db.commit()
    return {"revoked": session_id}


@router.post("/auth/sessions/revoke-others")
async def revoke_other_sessions(
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Sign out everywhere except here — the standard response to a lost device."""
    current = getattr(user, "current_session_id", None)
    count = await security.revoke_sessions(db, user_id=user.id, keep=current)
    await audit(
        db,
        event="auth.sessions_revoked_others",
        actor_id=user.id,
        severity="medium",
        request=request,
        detail=str(count),
    )
    await db.commit()
    return {"revoked": count}


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
