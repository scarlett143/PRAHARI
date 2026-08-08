"""Certificate submission, retrieval and revocation.

This service does not issue certificates. It accepts ones already signed by whoever holds
the issuer's keys, verifies them, stores them, and serves chains. See app/pki.py for why
the issuing authority is deliberately kept out of the relay.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import pki
from ..database import get_db
from ..models import Certificate
from ..security import AdminUser, CurrentUser
from .common import audit, b64d, b64e

router = APIRouter(prefix="/api/v2/pki", tags=["pki"])

#: An ML-DSA-65 public key is ~1952 bytes and a signature ~3309. Bounded so a submission
#: cannot be used to park arbitrary data on a shared disk.
MAX_PQ_KEY = 4096
MAX_PQ_SIG = 8192
#: A chain deeper than this is a loop or an attempt to make verification expensive.
MAX_CHAIN_DEPTH = 8


def _body_from(row: Certificate) -> pki.CertificateBody:
    return pki.CertificateBody(
        serial=row.serial,
        issuer_serial=row.issuer_serial,
        subject_id=row.subject_id,
        subject_name=row.subject_name,
        is_ca=row.is_ca,
        ed25519_public_key=row.ed25519_public_key,
        mldsa_public_key=row.mldsa_public_key,
        not_before=row.not_before,
        not_after=row.not_after,
    )


def _serialize(row: Certificate, *, with_keys: bool = True) -> dict:
    data = {
        "serial": row.serial,
        "issuer_serial": row.issuer_serial,
        "subject_id": row.subject_id,
        "subject_name": row.subject_name,
        "is_ca": row.is_ca,
        "trusted_root": row.trusted_root,
        "not_before": row.not_before,
        "not_after": row.not_after,
        "revoked_at": row.revoked_at,
        "revocation_reason": row.revocation_reason,
        "fingerprint": pki.fingerprint(_body_from(row)).hex(),
        "created_at": row.created_at,
    }
    if with_keys:
        data.update(
            ed25519_public_key=b64e(row.ed25519_public_key),
            mldsa_public_key=b64e(row.mldsa_public_key),
            ed25519_signature=b64e(row.ed25519_signature),
            mldsa_signature=b64e(row.mldsa_signature),
        )
    return data


class SubmitCertificateRequest(BaseModel):
    serial: str = Field(min_length=1, max_length=64)
    issuer_serial: str = Field(min_length=1, max_length=64)
    subject_id: str = Field(min_length=1, max_length=128)
    subject_name: str = Field(min_length=1, max_length=128)
    is_ca: bool = False
    ed25519_public_key: str = Field(min_length=1, max_length=128)
    mldsa_public_key: str = Field(min_length=1, max_length=MAX_PQ_KEY * 2)
    ed25519_signature: str = Field(min_length=1, max_length=128)
    mldsa_signature: str = Field(min_length=1, max_length=MAX_PQ_SIG * 2)
    not_before: datetime
    not_after: datetime


@router.post("/certificates")
async def submit_certificate(
    body: SubmitCertificateRequest,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Store a certificate, if it verifies.

    Verified before storage rather than only at use. A certificate that cannot verify is
    never valid, so keeping one would guarantee a confusing failure later at the moment
    someone depends on it -- and would let the table fill with material nobody can use.
    """
    ed_pub = b64d(body.ed25519_public_key, expect=32, field="ed25519_public_key")
    ed_sig = b64d(body.ed25519_signature, expect=64, field="ed25519_signature")
    pq_pub = b64d(body.mldsa_public_key, field="mldsa_public_key")
    pq_sig = b64d(body.mldsa_signature, field="mldsa_signature")
    if len(pq_pub) > MAX_PQ_KEY or len(pq_sig) > MAX_PQ_SIG:
        raise HTTPException(413, "post-quantum key or signature is too large")

    existing = (
        await db.execute(select(Certificate).where(Certificate.serial == body.serial))
    ).scalars().first()
    if existing is not None:
        # Serials are immutable. Rebinding one would let a certificate someone already
        # pinned or cached come to mean a different subject.
        raise HTTPException(409, "that serial already exists")

    candidate = pki.CertificateBody(
        serial=body.serial,
        issuer_serial=body.issuer_serial,
        subject_id=body.subject_id,
        subject_name=body.subject_name,
        is_ca=body.is_ca,
        ed25519_public_key=ed_pub,
        mldsa_public_key=pq_pub,
        not_before=body.not_before,
        not_after=body.not_after,
    )

    self_issued = body.issuer_serial == body.serial
    if self_issued:
        issuer_body = candidate
    else:
        issuer_row = (
            await db.execute(
                select(Certificate).where(Certificate.serial == body.issuer_serial)
            )
        ).scalars().first()
        if issuer_row is None:
            raise HTTPException(400, "the issuing certificate is not known here")
        if not issuer_row.is_ca:
            raise HTTPException(400, "the issuer is not permitted to issue certificates")
        if issuer_row.revoked_at is not None:
            raise HTTPException(400, "the issuing certificate has been revoked")
        issuer_body = _body_from(issuer_row)

    try:
        pki.check_validity(candidate)
        pki.verify_certificate(
            candidate,
            ed25519_signature=ed_sig,
            mldsa_signature=pq_sig,
            issuer_ed25519_public_key=issuer_body.ed25519_public_key,
            issuer_mldsa_public_key=issuer_body.mldsa_public_key,
        )
    except pki.CertificateError as exc:
        await audit(
            db,
            event="pki.certificate_rejected",
            actor_id=user.id,
            severity="high",
            request=request,
            detail=f"serial={body.serial};reason={exc}",
        )
        await db.commit()
        raise HTTPException(400, str(exc)) from None

    row = Certificate(
        serial=body.serial,
        issuer_serial=body.issuer_serial,
        subject_id=body.subject_id,
        subject_name=body.subject_name,
        is_ca=body.is_ca,
        ed25519_public_key=ed_pub,
        mldsa_public_key=pq_pub,
        ed25519_signature=ed_sig,
        mldsa_signature=pq_sig,
        not_before=body.not_before,
        not_after=body.not_after,
        # Never on submission. A self-signed certificate proves only that its holder can
        # sign; trust is an administrator's decision, made separately and on purpose.
        trusted_root=False,
        submitted_by=user.id,
    )
    db.add(row)
    await audit(
        db,
        event="pki.certificate_stored",
        actor_id=user.id,
        severity="medium",
        request=request,
        detail=f"serial={row.serial};subject={row.subject_name};ca={row.is_ca}",
    )
    await db.commit()
    await db.refresh(row)
    return _serialize(row)


@router.get("/certificates/{serial}")
async def get_certificate(
    serial: str,
    _: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    row = (
        await db.execute(select(Certificate).where(Certificate.serial == serial))
    ).scalars().first()
    if row is None:
        raise HTTPException(404, "no such certificate")
    return _serialize(row)


@router.get("/chain/{serial}")
async def get_chain(
    serial: str,
    _: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Return the chain leaf-first, and this server's own verification of it.

    `valid` is offered for convenience and is not the point. The chain is returned in full
    precisely so the caller can verify it themselves -- a relay reporting that its own
    certificates are fine is not evidence, exactly as with the key transparency log.
    """
    chain_rows: list[Certificate] = []
    seen: set[str] = set()
    cursor = serial

    while len(chain_rows) < MAX_CHAIN_DEPTH:
        row = (
            await db.execute(select(Certificate).where(Certificate.serial == cursor))
        ).scalars().first()
        if row is None:
            if not chain_rows:
                raise HTTPException(404, "no such certificate")
            break
        if row.serial in seen:
            # A certificate naming an issuer that eventually names it back. Walking that
            # forever is a denial of service with two rows of setup.
            raise HTTPException(409, "the certificate chain contains a loop")
        seen.add(row.serial)
        chain_rows.append(row)
        if row.issuer_serial == row.serial:
            break
        cursor = row.issuer_serial

    trusted = {
        row.serial
        for row in (
            await db.execute(select(Certificate).where(Certificate.trusted_root.is_(True)))
        ).scalars().all()
    }

    entries = [
        {
            "body": _body_from(row),
            "ed25519_signature": row.ed25519_signature,
            "mldsa_signature": row.mldsa_signature,
            "revoked_at": row.revoked_at,
        }
        for row in chain_rows
    ]

    error: str | None = None
    try:
        pki.verify_chain(entries, trusted_roots=trusted)
    except pki.CertificateError as exc:
        error = str(exc)

    return {
        "valid": error is None,
        "error": error,
        "chain": [_serialize(row) for row in chain_rows],
    }


class TrustRootRequest(BaseModel):
    trusted: bool = True


@router.post("/roots/{serial}")
async def set_root_trust(
    serial: str,
    body: TrustRootRequest,
    admin: AdminUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Pin or unpin a root. Administrator only, because it is the whole trust decision."""
    row = (
        await db.execute(select(Certificate).where(Certificate.serial == serial))
    ).scalars().first()
    if row is None:
        raise HTTPException(404, "no such certificate")
    if row.issuer_serial != row.serial:
        raise HTTPException(400, "only a self-issued certificate can be a trust root")
    if not row.is_ca:
        raise HTTPException(400, "a trust root must be permitted to issue certificates")

    row.trusted_root = bool(body.trusted)
    await audit(
        db,
        event="pki.root_trust_changed",
        actor_id=admin.id,
        severity="high",
        request=request,
        detail=f"serial={serial};trusted={row.trusted_root}",
    )
    await db.commit()
    return {"serial": row.serial, "trusted_root": row.trusted_root}


@router.get("/roots")
async def list_roots(_: CurrentUser, db: Annotated[AsyncSession, Depends(get_db)]):
    rows = (
        await db.execute(
            select(Certificate)
            .where(Certificate.trusted_root.is_(True))
            .order_by(Certificate.subject_name.asc())
        )
    ).scalars().all()
    return [_serialize(row) for row in rows]


class RevokeRequest(BaseModel):
    reason: str = Field(default="", max_length=256)


@router.post("/certificates/{serial}/revoke")
async def revoke_certificate(
    serial: str,
    body: RevokeRequest,
    admin: AdminUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Revoke a certificate.

    Revoking a CA invalidates everything beneath it, because chain walking checks every
    link. That is intended, and it is why revoking one is an administrator action rather
    than something the submitter can do.
    """
    row = (
        await db.execute(select(Certificate).where(Certificate.serial == serial))
    ).scalars().first()
    if row is None:
        raise HTTPException(404, "no such certificate")

    if row.revoked_at is None:
        row.revoked_at = datetime.now(timezone.utc)
        row.revocation_reason = body.reason.strip() or None
        if row.trusted_root:
            # A revoked root cannot stay pinned; leaving it would let chains terminate at
            # something explicitly withdrawn.
            row.trusted_root = False
        await audit(
            db,
            event="pki.certificate_revoked",
            actor_id=admin.id,
            severity="high",
            request=request,
            detail=f"serial={serial};reason={body.reason.strip()[:120]}",
        )
        await db.commit()
        await db.refresh(row)
    return _serialize(row, with_keys=False)
