from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

import base64

from ..crypto import pqsign
from ..blockchain.anchor import AnchorError, PolygonAnchor, leaf_hash, merkle_proof, merkle_root, verify_proof
from ..config import get_settings
from ..database import get_db
from ..models import AnchorBatch, Message, channel_members
from ..security import CurrentUser
from .common import audit, b64e

router = APIRouter(prefix="/api/v2/anchors", tags=["anchors"])
settings = get_settings()


@router.post("/batch")
async def build_batch(
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: int = 100,
):
    messages = (
        await db.execute(
            select(Message)
            .join(channel_members, channel_members.c.channel_id == Message.channel_id)
            .where(
                Message.anchor_batch_id.is_(None),
                channel_members.c.user_id == user.id,
            )
            # created_at alone is not unique (SQLite CURRENT_TIMESTAMP is second-precision),
            # so ties would order differently here than when the proof is rebuilt and the
            # recomputed root would not match the stored one. id breaks the tie.
            .order_by(Message.created_at.asc(), Message.id.asc())
            .limit(min(max(limit, 1), 1000))
        )
    ).scalars().all()
    if not messages:
        raise HTTPException(400, "no unanchored messages available")

    leaves = [leaf_hash(message.content_hash) for message in messages]
    root = merkle_root(leaves)
    batch = AnchorBatch(
        merkle_root=root,
        leaf_count=len(messages),
        status="local_verified",
        confirmed=False,
    )
    db.add(batch)
    await db.flush()
    for message in messages:
        message.anchor_batch_id = batch.id

    # Signed before any chain publication is attempted. The attestation is about the root
    # this server produced, and it should exist whether or not Polygon is reachable.
    if settings.anchor_pq_secret_key:
        try:
            batch.pq_signature = pqsign.sign(
                base64.b64decode(settings.anchor_pq_secret_key),
                pqsign.anchor_signing_payload(merkle_root=root, leaf_count=len(messages)),
            )
            batch.pq_algorithm = pqsign.ALGORITHM
        except pqsign.PQSignError:
            # An unsigned batch is still Merkle-verifiable, and refusing to anchor at all
            # because a signing key is missing would lose the proof to protect the label.
            batch.pq_signature = None
            batch.pq_algorithm = None

    chain_note = "Polygon not configured; Merkle batch verified locally"
    if settings.polygon_rpc_url and settings.anchor_contract_address and settings.anchor_private_key:
        try:
            result = PolygonAnchor(
                rpc_url=settings.polygon_rpc_url,
                contract_address=settings.anchor_contract_address,
                private_key=settings.anchor_private_key,
            ).anchor(leaves)
            batch.chain_tx_hash = result.tx_hash
            batch.confirmed = result.confirmed
            batch.status = "chain_confirmed"
            chain_note = result.note
        except AnchorError as exc:
            batch.status = "chain_failed"
            chain_note = str(exc)

    await audit(
        db,
        event="anchor.batch_created",
        actor_id=user.id,
        request=request,
        detail=f"batch={batch.id};leaves={len(messages)};status={batch.status}",
    )
    await db.commit()
    await db.refresh(batch)
    return _serialize_batch(batch, note=chain_note)


@router.get("")
async def list_batches(user: CurrentUser, db: Annotated[AsyncSession, Depends(get_db)]):
    rows = (
        await db.execute(
            select(AnchorBatch)
            .join(Message, Message.anchor_batch_id == AnchorBatch.id)
            .join(channel_members, channel_members.c.channel_id == Message.channel_id)
            .where(channel_members.c.user_id == user.id)
            .distinct()
            .order_by(AnchorBatch.created_at.desc())
            .limit(100)
        )
    ).scalars().all()
    return [_serialize_batch(row) for row in rows]


@router.get("/{batch_id}/proof/{message_id}")
async def inclusion_proof(
    batch_id: str,
    message_id: str,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    batch = (await db.execute(select(AnchorBatch).where(AnchorBatch.id == batch_id))).scalars().first()
    if batch is None:
        raise HTTPException(404, "batch not found")

    accessible = (
        await db.execute(
            select(Message.id)
            .join(channel_members, channel_members.c.channel_id == Message.channel_id)
            .where(
                Message.id == message_id,
                Message.anchor_batch_id == batch.id,
                channel_members.c.user_id == user.id,
            )
        )
    ).first()
    if accessible is None:
        raise HTTPException(404, "message is not part of an accessible batch")

    messages = (
        await db.execute(
            select(Message)
            .where(Message.anchor_batch_id == batch.id)
            .order_by(Message.created_at.asc(), Message.id.asc())
        )
    ).scalars().all()
    index = next((i for i, message in enumerate(messages) if message.id == message_id), None)
    if index is None:
        raise HTTPException(404, "message is not part of this batch")
    leaves = [leaf_hash(message.content_hash) for message in messages]
    path = merkle_proof(leaves, index)
    verified = verify_proof(leaves[index], path, batch.merkle_root)
    return {
        "batch_id": batch.id,
        "message_id": message_id,
        "leaf": leaves[index].hex(),
        "root": batch.merkle_root.hex(),
        "proof": [{"side": side, "hash": value.hex()} for side, value in path],
        "verified": verified,
        "chain_confirmed": batch.confirmed,
        "tx_hash": batch.chain_tx_hash,
    }


def _serialize_batch(batch: AnchorBatch, *, note: str | None = None) -> dict:
    return {
        "id": batch.id,
        "merkle_root": batch.merkle_root.hex(),
        "leaf_count": batch.leaf_count,
        "transaction_hash": batch.chain_tx_hash,
        "status": batch.status,
        "confirmed": batch.confirmed,
        "created_at": batch.created_at,
        # Present only when an anchor signing key is configured. Absent is stated rather
        # than implied: a batch with no signature carries no attestation of origin.
        "pq_algorithm": batch.pq_algorithm,
        "pq_signature": b64e(batch.pq_signature) if batch.pq_signature else None,
        "pq_public_key": settings.anchor_pq_public_key or None,
        "note": note,
    }
