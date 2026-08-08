"""Signed firmware releases.

The image never touches this server. What is published is a digest plus an Ed25519
signature over it made with the operator's identity key, so an endpoint can fetch the
bytes from any mirror, hash them, and refuse to install unless the hash matches something
the operator actually approved. A hostile mirror can serve the wrong bytes; it cannot make
them verify.

That choice is also what keeps this affordable. Firmware is tens of megabytes a release,
and storing or proxying it would make this the largest thing a two-core shared box does,
in exchange for no security the signature does not already provide.

This closes the loop with attestation. A release records the same SHA-256 an endpoint
reports as its measurement, so "which firmware is approved" and "which firmware is
running" are the same kind of value and can simply be compared -- which is what turns a
completed update into a verifiable fact rather than a hopeful one.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..crypto.identity import firmware_release_signing_payload, verify_ed25519_signature
from ..database import get_db
from ..models import FirmwareRelease, UavProfile, User
from ..security import CurrentUser
from .common import audit, b64d, b64e

router = APIRouter(prefix="/api/v2/firmware", tags=["firmware"])


class PublishReleaseRequest(BaseModel):
    fleet: str = Field(min_length=1, max_length=96)
    version: str = Field(min_length=1, max_length=64)
    measurement_b64: str = Field(min_length=1, max_length=128)
    signature_b64: str = Field(min_length=1, max_length=128)
    image_url: str = Field(default="", max_length=512)
    size_bytes: int | None = Field(default=None, ge=0)


def _serialize(release: FirmwareRelease, *, operator_key: bytes | None = None) -> dict:
    return {
        "id": release.id,
        "fleet": release.fleet,
        "version": release.version,
        "measurement": release.measurement.hex(),
        "signature": b64e(release.signature),
        # Returned so an endpoint can verify without a second request. It is the operator's
        # *public* key; the point of shipping it is that the endpoint compares it against
        # the one it was provisioned with rather than trusting whatever arrives.
        "operator_public_key": b64e(operator_key) if operator_key else None,
        "image_url": release.image_url,
        "size_bytes": release.size_bytes,
        "withdrawn_at": release.withdrawn_at,
        "withdrawn_reason": release.withdrawn_reason,
        "created_at": release.created_at,
    }


@router.post("/releases")
async def publish_release(
    body: PublishReleaseRequest,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Approve one image for one fleet.

    The signature is verified here as well as on the endpoint. Not because the endpoint's
    check is insufficient -- it is the one that matters -- but because an unverifiable
    release stored now becomes a support call later, from a fleet that silently refuses
    every update and cannot say why.
    """
    measurement = b64d(body.measurement_b64, expect=32, field="measurement_b64")
    signature = b64d(body.signature_b64, expect=64, field="signature_b64")

    payload = firmware_release_signing_payload(
        fleet=body.fleet.strip(), version=body.version.strip(), measurement=measurement
    )
    if not verify_ed25519_signature(
        public_key=user.ed25519_public_key, message=payload, signature=signature
    ):
        await audit(
            db,
            event="firmware.signature_rejected",
            actor_id=user.id,
            severity="high",
            request=request,
            detail=f"fleet={body.fleet};version={body.version}",
        )
        await db.commit()
        raise HTTPException(400, "release signature failed")

    existing = (
        await db.execute(
            select(FirmwareRelease).where(
                FirmwareRelease.fleet == body.fleet.strip(),
                FirmwareRelease.version == body.version.strip(),
            )
        )
    ).scalars().first()
    if existing is not None:
        # Versions are immutable on purpose. Letting one be republished with a different
        # digest means an endpoint that already verified "v4.2" cannot rely on what that
        # name refers to, which is the property the signature exists to establish.
        raise HTTPException(409, "that version already exists; publish a new version")

    release = FirmwareRelease(
        operator_id=user.id,
        fleet=body.fleet.strip(),
        version=body.version.strip(),
        measurement=measurement,
        signature=signature,
        image_url=body.image_url.strip() or None,
        size_bytes=body.size_bytes,
    )
    db.add(release)
    await audit(
        db,
        event="firmware.published",
        actor_id=user.id,
        severity="medium",
        request=request,
        detail=f"fleet={release.fleet};version={release.version};digest={measurement.hex()[:16]}",
    )
    await db.commit()
    await db.refresh(release)
    return _serialize(release, operator_key=user.ed25519_public_key)


@router.get("/releases")
async def list_releases(
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    fleet: str | None = None,
    include_withdrawn: bool = False,
    limit: int = 50,
):
    conditions = [FirmwareRelease.operator_id == user.id]
    if fleet:
        conditions.append(FirmwareRelease.fleet == fleet)
    if not include_withdrawn:
        conditions.append(FirmwareRelease.withdrawn_at.is_(None))

    rows = (
        await db.execute(
            select(FirmwareRelease)
            .where(*conditions)
            .order_by(FirmwareRelease.created_at.desc())
            .limit(min(max(limit, 1), 200))
        )
    ).scalars().all()
    return [_serialize(row, operator_key=user.ed25519_public_key) for row in rows]


class WithdrawRequest(BaseModel):
    reason: str = Field(default="", max_length=256)


@router.post("/releases/{release_id}/withdraw")
async def withdraw_release(
    release_id: str,
    body: WithdrawRequest,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Mark a release as no longer approved.

    Withdrawal is advisory and the limit is worth stating: it stops endpoints that check
    before installing, and does nothing to one already running the image. Getting a fleet
    off a bad build still means shipping a newer release; this only stops the bleeding.
    """
    release = (
        await db.execute(
            select(FirmwareRelease).where(
                FirmwareRelease.id == release_id, FirmwareRelease.operator_id == user.id
            )
        )
    ).scalars().first()
    if release is None:
        raise HTTPException(404, "no such release")

    if release.withdrawn_at is None:
        release.withdrawn_at = datetime.now(timezone.utc)
        release.withdrawn_reason = body.reason.strip() or None
        await audit(
            db,
            event="firmware.withdrawn",
            actor_id=user.id,
            severity="high",
            request=request,
            detail=f"fleet={release.fleet};version={release.version};reason={body.reason.strip()[:120]}",
        )
        await db.commit()
        await db.refresh(release)
    return _serialize(release)


@router.get("/available")
async def available_for_endpoint(
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """What an aircraft should be running, and whether it already is.

    Called by the endpoint itself. The comparison is against the measurement the endpoint
    last reported, so this answers "do I need to update?" without the aircraft having to
    reason about it -- and without this service being trusted, since the release it names
    carries a signature the endpoint checks for itself.
    """
    if user.kind != "uav":
        raise HTTPException(403, "only unmanned endpoints ask for their own firmware")

    profile = (
        await db.execute(select(UavProfile).where(UavProfile.user_id == user.id))
    ).scalars().first()
    if profile is None:
        raise HTTPException(404, "no fleet profile for this endpoint")

    latest = (
        await db.execute(
            select(FirmwareRelease)
            .where(
                FirmwareRelease.fleet == profile.fleet,
                FirmwareRelease.operator_id == profile.operator_id,
                FirmwareRelease.withdrawn_at.is_(None),
            )
            .order_by(FirmwareRelease.created_at.desc())
            .limit(1)
        )
    ).scalars().first()
    if latest is None:
        return {"update_available": False, "release": None, "current_matches": None}

    operator = (
        await db.execute(select(User).where(User.id == latest.operator_id))
    ).scalars().first()

    running = profile.last_measurement
    matches = bool(running) and running == latest.measurement
    return {
        "update_available": not matches,
        "current_matches": matches,
        "release": _serialize(latest, operator_key=operator.ed25519_public_key if operator else None),
    }
