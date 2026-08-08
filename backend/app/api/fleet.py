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
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from .. import security
from ..database import get_db
from ..models import Channel, Server, UavProfile, User, _uuid, server_members
from ..realtime import manager
from ..security import CurrentUser
from .common import audit, b64d

router = APIRouter(prefix="/api/v2/fleet", tags=["fleet"])

#: Placeholder identity key held until the aircraft enrols and presents its real one.
UNENROLLED_ED25519 = bytes(32)

#: Containment states. `QUARANTINED` is reversible -- an aircraft that stopped answering,
#: or one flagged pending investigation. `REVOKED` is not: it is for an endpoint believed
#: captured or cloned, and it destroys the enrolment path so the callsign cannot be
#: brought back with the same credentials.
ACTIVE = "active"
QUARANTINED = "quarantined"
REVOKED = "revoked"

#: Attestation verdicts, derived on read rather than stored -- there is no state here that
#: is not already implied by the two measurements, and a stored copy could disagree.
UNPINNED = "unpinned"      # operator has not said what this endpoint should be running
UNREPORTED = "unreported"  # pinned, but the aircraft has not reported since
TRUSTED = "trusted"
DRIFTED = "drifted"


def attestation_state(profile: UavProfile) -> str:
    if not profile.expected_measurement:
        return UNPINNED
    if not profile.last_measurement:
        return UNREPORTED
    # Constant-time: the comparison is against a value the caller supplied, and a timing
    # difference would let one be searched for byte by byte.
    return TRUSTED if hmac.compare_digest(
        profile.expected_measurement, profile.last_measurement
    ) else DRIFTED
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
        "security_state": profile.security_state or ACTIVE,
        "security_state_at": profile.security_state_at,
        "security_state_reason": profile.security_state_reason,
        "attestation_state": attestation_state(profile),
        # Hex, and only the leading bytes: enough for an operator to compare two digests
        # by eye, without printing a full measurement into every listing.
        "expected_measurement": _digest_prefix(profile.expected_measurement),
        "last_measurement": _digest_prefix(profile.last_measurement),
        "last_measurement_at": profile.last_measurement_at,
    }


def _digest_prefix(value: bytes | None, length: int = 8) -> str | None:
    return value.hex()[: length * 2] if value else None


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

    # Uniform failure: never reveal whether the callsign exists, the token was wrong, or
    # the endpoint is contained.
    #
    # The containment check belongs here rather than after it. Enrolment ends with
    # `account.status = "active"`, so without this an endpoint quarantined before it ever
    # enrolled could be brought straight back into service by whoever holds its token --
    # which, if the token is why it was quarantined, is precisely the wrong person.
    if (
        profile is None
        or account is None
        or profile.security_state in (QUARANTINED, REVOKED)
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
    # A contained endpoint is answered like any unknown callsign: it still receives a
    # well-formed nonce, but nothing is recorded, so the signature it returns can never be
    # redeemed. Refusing here instead would turn this endpoint into an oracle for which
    # aircraft have been quarantined.
    contained = profile is not None and profile.security_state in (QUARANTINED, REVOKED)
    if profile is not None and profile.enrolled_at is not None and not contained:
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
    query: str | None = None,
    limit: int = 200,
    offset: int = 0,
):
    """List endpoints, narrowed by fleet name or a search over callsign and fleet.

    Searching has to happen here rather than in the browser: the console pages through a
    registry sized for a thousand endpoints, so filtering only what one page happens to
    hold would silently miss every match on every other page.
    """
    await _require_operator(user)

    conditions = [UavProfile.operator_id == user.id]
    if fleet:
        conditions.append(UavProfile.fleet == fleet)
    if query and query.strip():
        needle = f"%{query.strip().lower()}%"
        conditions.append(
            or_(
                func.lower(UavProfile.callsign).like(needle),
                func.lower(UavProfile.fleet).like(needle),
            )
        )

    rows = (
        await db.execute(
            select(UavProfile, User)
            .join(User, UavProfile.user_id == User.id)
            .where(*conditions)
            .order_by(UavProfile.callsign.asc())
            .offset(max(offset, 0))
            .limit(min(max(limit, 1), 1000))
        )
    ).all()
    # Counted under the same conditions as the rows. Counting everything while returning
    # a filtered page is what produces a search result followed by twenty empty pages.
    total = await db.scalar(select(func.count(UavProfile.id)).where(*conditions))
    return {
        "total": int(total or 0),
        "returned": len(rows),
        "endpoints": [_serialize(profile, account) for profile, account in rows],
    }


class ContainmentRequest(BaseModel):
    reason: str = Field(default="", max_length=256)


async def _owned_profile(db: AsyncSession, callsign: str, operator: User) -> tuple[UavProfile, User]:
    profile = (
        await db.execute(
            select(UavProfile).where(
                UavProfile.callsign == callsign, UavProfile.operator_id == operator.id
            )
        )
    ).scalars().first()
    if profile is None:
        raise HTTPException(404, "aircraft not found")
    account = (await db.execute(select(User).where(User.id == profile.user_id))).scalars().first()
    if account is None:
        raise HTTPException(404, "aircraft not found")
    return profile, account


async def _contain(
    db: AsyncSession,
    *,
    profile: UavProfile,
    account: User,
    operator: User,
    request: Request,
    state: str,
    reason: str,
) -> int:
    """Cut an endpoint off, in the order that closes every door before reporting success.

    Sequence matters here. Marking the account is what refuses the *next* token request,
    but an aircraft that already holds a valid token would keep working until it expired,
    and one holding an open WebSocket would never make another request at all. So all
    three are taken down together: the account status, every recorded session, and the
    live sockets.
    """
    now = datetime.now(timezone.utc)
    profile.security_state = state
    profile.security_state_at = now
    profile.security_state_reason = reason.strip() or None
    account.status = state
    # A pending challenge is a half-finished authentication; leaving it would let a
    # signature computed moments before containment still be redeemed.
    profile.auth_challenge = None
    profile.auth_challenge_issued_at = None

    if state == REVOKED:
        # Permanent by construction rather than by policy. Clearing the enrolment hash
        # means the callsign cannot be re-enrolled with the credential that was captured,
        # and dropping key_verified makes the link path refuse it even if something later
        # flips the status back.
        profile.enrollment_token_hash = None
        account.key_verified = False

    revoked = await security.revoke_sessions(db, user_id=account.id)
    await audit(
        db,
        event=f"fleet.{state}",
        severity="high",
        actor_id=operator.id,
        request=request,
        detail=f"callsign={profile.callsign};sessions={revoked};reason={reason.strip()[:120]}",
    )
    await db.commit()
    await manager.close_user(account.id, reason=state)
    return revoked


@router.post("/uavs/{callsign}/quarantine")
async def quarantine_endpoint(
    callsign: str,
    body: ContainmentRequest,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Suspend an endpoint, reversibly.

    For the ambiguous case -- an aircraft behaving oddly, or off the air longer than it
    should be -- where cutting it off is prudent but destroying its enrolment is not.
    """
    await _require_operator(user)
    profile, account = await _owned_profile(db, callsign, user)
    if profile.security_state == REVOKED:
        raise HTTPException(409, "endpoint is revoked; revocation cannot be downgraded")

    revoked = await _contain(
        db, profile=profile, account=account, operator=user,
        request=request, state=QUARANTINED, reason=body.reason,
    )
    return {"callsign": callsign, "security_state": QUARANTINED, "sessions_revoked": revoked}


@router.post("/uavs/{callsign}/revoke")
async def revoke_endpoint(
    callsign: str,
    body: ContainmentRequest,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Permanently cut off an endpoint believed captured, cloned or compromised.

    What this cannot do is worth stating plainly: it revokes the endpoint's ability to
    *authenticate to this relay*. It does not reach the aircraft, and it does not make
    ciphertext an attacker already holds unreadable. Messages the endpoint sent before
    revocation stay exactly as readable to whoever holds the keys as they were before.
    Rotate the channel epoch to stop it reading anything sent after this point.
    """
    await _require_operator(user)
    profile, account = await _owned_profile(db, callsign, user)

    revoked = await _contain(
        db, profile=profile, account=account, operator=user,
        request=request, state=REVOKED, reason=body.reason,
    )
    return {"callsign": callsign, "security_state": REVOKED, "sessions_revoked": revoked}


@router.post("/uavs/{callsign}/restore")
async def restore_endpoint(
    callsign: str,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Return a quarantined endpoint to service. Revocation is deliberately not reversible."""
    await _require_operator(user)
    profile, account = await _owned_profile(db, callsign, user)
    if profile.security_state == REVOKED:
        raise HTTPException(
            409,
            "a revoked endpoint cannot be restored; provision a new callsign and re-enrol it",
        )
    if (profile.security_state or ACTIVE) == ACTIVE:
        return {"callsign": callsign, "security_state": ACTIVE, "sessions_revoked": 0}

    profile.security_state = ACTIVE
    profile.security_state_at = datetime.now(timezone.utc)
    profile.security_state_reason = None
    account.status = ACTIVE
    await audit(
        db,
        event="fleet.restored",
        severity="high",
        actor_id=user.id,
        request=request,
        detail=f"callsign={callsign}",
    )
    await db.commit()
    # The aircraft must re-authenticate: containment revoked its sessions, and restoring
    # does not hand them back.
    return {"callsign": callsign, "security_state": ACTIVE, "sessions_revoked": 0}


class AttestationPinRequest(BaseModel):
    #: Base64 SHA-256 of the approved firmware or boot image. Empty clears the pin.
    measurement_b64: str = Field(default="", max_length=128)


@router.post("/uavs/{callsign}/attestation")
async def pin_measurement(
    callsign: str,
    body: AttestationPinRequest,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Record which firmware digest this endpoint is supposed to be running.

    Read the limit before relying on this. The measurement is *self-reported* over an
    authenticated channel: it proves the endpoint holds its enrolment key, not that it is
    running the software it names. An attacker who controls the airframe can report the
    digest the operator pinned while running anything at all. Only a hardware root of
    trust -- a TPM or secure element signing the measurement with a key the main processor
    cannot read -- would close that, and this fleet does not assume one.

    What it does catch is the common case rather than the clever one: a downgrade, a
    mis-flashed image, an unapproved build, an endpoint that came back from maintenance
    running something nobody signed off. That is worth having, provided nobody mistakes it
    for proof the aircraft is honest.
    """
    await _require_operator(user)
    profile, _ = await _owned_profile(db, callsign, user)

    previous = profile.expected_measurement
    if body.measurement_b64:
        measurement = b64d(body.measurement_b64, expect=32, field="measurement_b64")
        profile.expected_measurement = measurement
    else:
        profile.expected_measurement = None

    await audit(
        db,
        event="fleet.attestation_pinned" if body.measurement_b64 else "fleet.attestation_cleared",
        severity="high",
        actor_id=user.id,
        request=request,
        detail=(
            f"callsign={callsign};"
            f"was={_digest_prefix(previous) or 'none'};"
            f"now={_digest_prefix(profile.expected_measurement) or 'none'}"
        ),
    )
    await db.commit()
    await db.refresh(profile)
    return {
        "callsign": callsign,
        "attestation_state": attestation_state(profile),
        "expected_measurement": _digest_prefix(profile.expected_measurement),
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


class HeartbeatRequest(BaseModel):
    #: Optional so an aircraft running older firmware keeps reporting liveness.
    measurement_b64: str = Field(default="", max_length=128)


@router.post("/heartbeat")
async def heartbeat(
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    body: HeartbeatRequest | None = None,
):
    """Liveness ping from an aircraft. Carries no telemetry -- that stays encrypted.

    The optional firmware measurement rides along here rather than on an endpoint of its
    own: it is the same claim on the same schedule, and a second request per heartbeat
    across a thousand endpoints is load this deployment cannot spend.
    """
    if user.kind != "uav":
        raise HTTPException(403, "only unmanned endpoints report a heartbeat")
    profile = (
        await db.execute(select(UavProfile).where(UavProfile.user_id == user.id))
    ).scalars().first()
    if profile is None:
        raise HTTPException(404, "no fleet profile for this endpoint")

    now = datetime.now(timezone.utc)
    profile.last_seen_at = now

    if body is not None and body.measurement_b64:
        measurement = b64d(body.measurement_b64, expect=32, field="measurement_b64")
        drifted_before = attestation_state(profile) == DRIFTED
        profile.last_measurement = measurement
        profile.last_measurement_at = now
        # Audited only on the transition into drift. Logging every heartbeat of a drifted
        # endpoint would bury the moment it happened under thousands of identical rows,
        # and the audit table lives on a disk shared with the operator's other services.
        if attestation_state(profile) == DRIFTED and not drifted_before:
            await audit(
                db,
                event="fleet.attestation_drift",
                severity="high",
                actor_id=user.id,
                request=request,
                detail=(
                    f"callsign={profile.callsign};"
                    f"expected={_digest_prefix(profile.expected_measurement)};"
                    f"reported={_digest_prefix(measurement)}"
                ),
            )

    await db.commit()
    return {
        "callsign": profile.callsign,
        "last_seen_at": now,
        "attestation_state": attestation_state(profile),
    }
