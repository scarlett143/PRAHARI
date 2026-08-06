"""Fleet provisioning and enrolment for unmanned endpoints.

A UAV is not a special case of the crypto stack -- it is an ordinary peer. It holds its
own Ed25519 identity key, publishes a signed X25519 + ML-KEM-768 bundle, and establishes
exactly the same two-party hybrid session as a human user. Everything in this module is
provisioning and bookkeeping; none of it touches key material or plaintext.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from .. import security
from ..database import get_db
from ..models import Channel, Server, UavProfile, User, _uuid, server_members
from ..security import CurrentUser
from .common import audit, b64d

router = APIRouter(prefix="/api/v2/fleet", tags=["fleet"])

#: Placeholder identity key held until the aircraft enrols and presents its real one.
UNENROLLED_ED25519 = bytes(32)
FLEET_SERVER_NAME = "Fleet Operations"
MAX_BULK_PROVISION = 1000


def hash_enrollment_token(token: str) -> str:
    """Hash a provisioning token with SHA-256 rather than Argon2.

    Argon2 exists to make *low-entropy* human passwords expensive to guess. An enrolment
    token is 256 bits of CSPRNG output that is used once and then cleared, so there is no
    guessing attack to slow down -- and Argon2 at 64 MiB per hash would make provisioning
    a 1000-aircraft fleet cost 64 GiB of sequential work for no security gain.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_enrollment_token(stored_hash: str, token: str) -> bool:
    return hmac.compare_digest(stored_hash, hash_enrollment_token(token))


class ProvisionRequest(BaseModel):
    callsign: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    airframe: str | None = Field(default=None, max_length=96)
    fleet: str = Field(default="default", max_length=96)


class BulkProvisionRequest(BaseModel):
    callsign_prefix: str = Field(min_length=1, max_length=48, pattern=r"^[A-Za-z0-9_.-]+$")
    count: int = Field(ge=1, le=MAX_BULK_PROVISION)
    airframe: str | None = Field(default=None, max_length=96)
    fleet: str = Field(default="default", max_length=96)
    start_index: int = Field(default=1, ge=0)


class EnrollRequest(BaseModel):
    callsign: str
    enrollment_token: str
    ed25519_public_key: str


async def _require_operator(user: User) -> User:
    if user.kind != "human":
        raise HTTPException(403, "only human operators can manage a fleet")
    return user


async def _fleet_server(db: AsyncSession, operator: User) -> Server:
    """The operator's dedicated workspace holding one link channel per aircraft."""
    server = (
        await db.execute(
            select(Server).where(
                Server.owner_id == operator.id, Server.name == FLEET_SERVER_NAME
            )
        )
    ).scalars().first()
    if server is not None:
        return server
    server = Server(name=FLEET_SERVER_NAME, owner_id=operator.id)
    server.members.append(operator)
    db.add(server)
    await db.flush()
    return server


def _serialize(profile: UavProfile, account: User) -> dict:
    return {
        "callsign": profile.callsign,
        "user_id": profile.user_id,
        "airframe": profile.airframe,
        "fleet": profile.fleet,
        "status": account.status,
        "key_verified": account.key_verified,
        "enrolled_at": profile.enrolled_at,
        "last_seen_at": profile.last_seen_at,
        "link_channel_id": profile.link_channel_id,
        "created_at": profile.created_at,
    }


def _provision_one(
    db: AsyncSession, operator: User, *, callsign: str, airframe: str | None, fleet: str
) -> tuple[UavProfile, str]:
    """Stage one aircraft record. The caller decides when to flush.

    The account id is generated here rather than read back from the database, so
    provisioning a whole fleet costs one flush instead of one per aircraft.
    """
    token = secrets.token_urlsafe(32)
    account = User(
        id=_uuid(),
        username=callsign,
        # Unmanned endpoints never authenticate with a password; they enrol with a
        # single-use token and thereafter sign a challenge. Store an unusable hash.
        password_hash="!unmanned-endpoint-no-password-login",
        role="member",
        status="pending_enrollment",
        kind="uav",
        ed25519_public_key=UNENROLLED_ED25519,
    )
    db.add(account)
    profile = UavProfile(
        user_id=account.id,
        operator_id=operator.id,
        callsign=callsign,
        airframe=airframe,
        fleet=fleet,
        enrollment_token_hash=hash_enrollment_token(token),
    )
    db.add(profile)
    return profile, token


@router.post("/uavs")
async def provision_uav(
    body: ProvisionRequest,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Create an unenrolled aircraft record and return its one-time enrolment token."""
    await _require_operator(user)
    profile, token = _provision_one(
        db, user, callsign=body.callsign, airframe=body.airframe, fleet=body.fleet
    )
    await db.flush()
    await audit(
        db,
        event="fleet.uav_provisioned",
        actor_id=user.id,
        request=request,
        detail=f"callsign={body.callsign};fleet={body.fleet}",
    )
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(409, "callsign already exists") from None
    await db.refresh(profile)
    account = (await db.execute(select(User).where(User.id == profile.user_id))).scalars().first()
    return {
        **_serialize(profile, account),
        # Shown exactly once. The server keeps only a hash.
        "enrollment_token": token,
    }


@router.post("/uavs/bulk")
async def provision_fleet(
    body: BulkProvisionRequest,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Provision a whole fleet in one transaction (used for scale validation)."""
    await _require_operator(user)
    issued: list[dict] = []
    width = max(4, len(str(body.start_index + body.count - 1)))
    for offset in range(body.count):
        callsign = f"{body.callsign_prefix}-{body.start_index + offset:0{width}d}"
        _, token = _provision_one(
            db, user, callsign=callsign, airframe=body.airframe, fleet=body.fleet
        )
        issued.append({"callsign": callsign, "enrollment_token": token})
    # One flush for the whole fleet rather than one per aircraft.
    await db.flush()
    await audit(
        db,
        event="fleet.bulk_provisioned",
        actor_id=user.id,
        request=request,
        detail=f"count={body.count};fleet={body.fleet}",
    )
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(409, "one or more callsigns already exist") from None
    return {"fleet": body.fleet, "provisioned": len(issued), "endpoints": issued}


@router.post("/enroll")
async def enroll(
    body: EnrollRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Redeem a one-time token and bind the aircraft's real Ed25519 identity key.

    Unauthenticated by necessity -- the aircraft has no credentials yet. The token is the
    credential, it is single-use, and it only ever grants access to one provisioned record.
    """
    ed_pub = b64d(body.ed25519_public_key, expect=32, field="ed25519_public_key")
    if ed_pub == UNENROLLED_ED25519:
        raise HTTPException(400, "ed25519_public_key must be a real identity key")

    profile = (
        await db.execute(select(UavProfile).where(UavProfile.callsign == body.callsign))
    ).scalars().first()
    account = (
        (await db.execute(select(User).where(User.id == profile.user_id))).scalars().first()
        if profile
        else None
    )

    # Uniform failure: never reveal whether the callsign exists or the token was wrong.
    if (
        profile is None
        or account is None
        or not profile.enrollment_token_hash
        or not verify_enrollment_token(profile.enrollment_token_hash, body.enrollment_token)
    ):
        await audit(
            db,
            event="fleet.enrollment_failed",
            severity="high",
            request=request,
            detail=f"callsign={body.callsign}",
        )
        await db.commit()
        raise HTTPException(401, "enrolment failed")

    account.ed25519_public_key = ed_pub
    account.status = "active"
    profile.enrollment_token_hash = None  # single use
    profile.enrolled_at = datetime.now(timezone.utc)
    await audit(
        db,
        event="fleet.uav_enrolled",
        actor_id=account.id,
        request=request,
        detail=f"callsign={profile.callsign}",
    )
    await db.commit()
    await db.refresh(account)

    token, ttl, jti, expires_at = security.issue_access_token(
        user_id=account.id, username=account.username, role=account.role
    )
    # Aircraft sessions are recorded and revocable like any other -- an endpoint that
    # cannot be cut off is worse than a browser that cannot, not better.
    security.record_session(
        db, user_id=account.id, jti=jti, expires_at=expires_at, request=request, kind="uav"
    )
    await db.commit()
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": ttl,
        "user_id": account.id,
        "callsign": profile.callsign,
        # The aircraft must still publish its signed X25519 + ML-KEM bundle via
        # /auth/challenge + /keys/publish before any session can be established.
        "key_verified": account.key_verified,
    }


class DeviceChallengeRequest(BaseModel):
    callsign: str


class DeviceTokenRequest(BaseModel):
    callsign: str
    challenge_signature: str


@router.post("/auth/challenge")
async def device_challenge(
    body: DeviceChallengeRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Issue a nonce for an enrolled aircraft to sign.

    Handing out a nonce reveals nothing: it is useless without the Ed25519 private key
    that only the aircraft holds, so this responds identically for unknown callsigns.
    """
    challenge = secrets.token_urlsafe(32)
    profile = (
        await db.execute(select(UavProfile).where(UavProfile.callsign == body.callsign))
    ).scalars().first()
    if profile is not None and profile.enrolled_at is not None:
        profile.auth_challenge = challenge
        profile.auth_challenge_issued_at = datetime.now(timezone.utc)
        await db.commit()
    return {"challenge": challenge, "ttl_seconds": security.CHALLENGE_TTL_SECONDS}


@router.post("/auth/token")
async def device_token(
    body: DeviceTokenRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Exchange a signed challenge for an access token.

    This is how an aircraft renews credentials: it holds no password, so possession of
    the enrolment-bound Ed25519 private key *is* the credential.
    """
    signature = b64d(body.challenge_signature, expect=64, field="challenge_signature")
    profile = (
        await db.execute(select(UavProfile).where(UavProfile.callsign == body.callsign))
    ).scalars().first()
    account = (
        (await db.execute(select(User).where(User.id == profile.user_id))).scalars().first()
        if profile
        else None
    )

    valid = False
    if profile is not None and account is not None and profile.auth_challenge:
        issued = profile.auth_challenge_issued_at
        if issued is not None:
            if issued.tzinfo is None:
                issued = issued.replace(tzinfo=timezone.utc)
            fresh = (datetime.now(timezone.utc) - issued).total_seconds() <= (
                security.CHALLENGE_TTL_SECONDS
            )
            valid = fresh and account.status == "active" and security.verify_key_ownership(
                ed25519_public_key=account.ed25519_public_key,
                challenge=profile.auth_challenge,
                signature=signature,
            )

    if not valid:
        if profile is not None:
            profile.auth_challenge = None
            profile.auth_challenge_issued_at = None
        await audit(
            db,
            event="fleet.device_auth_failed",
            severity="high",
            request=request,
            detail=f"callsign={body.callsign}",
        )
        await db.commit()
        raise HTTPException(401, "device authentication failed")

    # Single-use: a captured signature cannot be replayed.
    profile.auth_challenge = None
    profile.auth_challenge_issued_at = None
    profile.last_seen_at = datetime.now(timezone.utc)
    await audit(db, event="fleet.device_auth", actor_id=account.id, request=request)
    await db.commit()

    token, ttl, jti, expires_at = security.issue_access_token(
        user_id=account.id, username=account.username, role=account.role
    )
    # Aircraft sessions are recorded and revocable like any other -- an endpoint that
    # cannot be cut off is worse than a browser that cannot, not better.
    security.record_session(
        db, user_id=account.id, jti=jti, expires_at=expires_at, request=request, kind="uav"
    )
    await db.commit()
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": ttl,
        "user_id": account.id,
        "callsign": profile.callsign,
        "key_verified": account.key_verified,
    }


@router.get("/uavs")
async def list_uavs(
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    fleet: str | None = None,
    limit: int = 200,
    offset: int = 0,
):
    await _require_operator(user)
    statement = (
        select(UavProfile, User)
        .join(User, UavProfile.user_id == User.id)
        .where(UavProfile.operator_id == user.id)
    )
    if fleet:
        statement = statement.where(UavProfile.fleet == fleet)
    rows = (
        await db.execute(
            statement.order_by(UavProfile.callsign.asc())
            .offset(max(offset, 0))
            .limit(min(max(limit, 1), 1000))
        )
    ).all()
    total = await db.scalar(
        select(func.count(UavProfile.id)).where(UavProfile.operator_id == user.id)
    )
    return {
        "total": int(total or 0),
        "returned": len(rows),
        "endpoints": [_serialize(profile, account) for profile, account in rows],
    }


@router.post("/uavs/{callsign}/link")
async def establish_link_channel(
    callsign: str,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Create (or return) the dedicated two-party channel carrying this aircraft's link.

    The channel holds exactly the operator and the aircraft, so the standard hybrid
    session applies unchanged: same Ed25519-signed offer, same X25519 + ML-KEM-768
    agreement, same AES-256-GCM envelopes as a human-to-human conversation.
    """
    await _require_operator(user)
    profile = (
        await db.execute(
            select(UavProfile).where(
                UavProfile.callsign == callsign, UavProfile.operator_id == user.id
            )
        )
    ).scalars().first()
    if profile is None:
        raise HTTPException(404, "aircraft not found")

    account = (await db.execute(select(User).where(User.id == profile.user_id))).scalars().first()
    if account.status != "active":
        raise HTTPException(409, "aircraft has not completed enrolment")
    if not account.key_verified:
        raise HTTPException(409, "aircraft has not published a verified key bundle")

    if profile.link_channel_id:
        existing = (
            await db.execute(select(Channel).where(Channel.id == profile.link_channel_id))
        ).scalars().first()
        if existing is not None:
            return {
                "callsign": profile.callsign,
                "channel_id": existing.id,
                "key_epoch": existing.key_epoch,
                "created": False,
            }

    server = await _fleet_server(db, user)
    exists = await db.execute(
        select(server_members.c.user_id).where(
            server_members.c.server_id == server.id,
            server_members.c.user_id == account.id,
        )
    )
    if exists.first() is None:
        await db.execute(
            server_members.insert().values(server_id=server.id, user_id=account.id)
        )

    # The aircraft opens the ratchet because the aircraft speaks first: telemetry starts
    # flowing before any command arrives, and a ratchet responder cannot send until it
    # has received.
    channel = Channel(
        name=f"link-{profile.callsign}", server_id=server.id, initiator_id=account.id
    )
    channel.members.extend([user, account])
    db.add(channel)
    await db.flush()
    profile.link_channel_id = channel.id
    await audit(
        db,
        event="fleet.link_channel_created",
        actor_id=user.id,
        request=request,
        detail=f"callsign={profile.callsign};channel={channel.id}",
    )
    await db.commit()
    await db.refresh(channel)
    return {
        "callsign": profile.callsign,
        "channel_id": channel.id,
        "key_epoch": channel.key_epoch,
        "created": True,
    }


@router.post("/heartbeat")
async def heartbeat(
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Liveness ping from an aircraft. Carries no telemetry -- that stays encrypted."""
    if user.kind != "uav":
        raise HTTPException(403, "only unmanned endpoints report a heartbeat")
    profile = (
        await db.execute(select(UavProfile).where(UavProfile.user_id == user.id))
    ).scalars().first()
    if profile is None:
        raise HTTPException(404, "no fleet profile for this endpoint")
    now = datetime.now(timezone.utc)
    profile.last_seen_at = now
    await db.commit()
    return {"callsign": profile.callsign, "last_seen_at": now}
