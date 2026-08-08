from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import datetime, timezone
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..database import get_db
from ..models import Message, MessageReceipt, User
from ..realtime import manager
from ..security import CurrentUser
from .common import audit, b64d, b64e, channel_member_users, require_channel_member

router = APIRouter(prefix="/api/v2", tags=["messages"])
settings = get_settings()


class SendMessageRequest(BaseModel):
    client_message_id: str = Field(min_length=8, max_length=64)
    channel_id: str
    key_epoch: int
    envelope_b64: str


async def _rekey_required(db: AsyncSession, channel) -> tuple[bool, str | None]:
    started = channel.epoch_started_at
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    age_minutes = (datetime.now(timezone.utc) - started).total_seconds() / 60
    if age_minutes >= settings.rekey_after_minutes:
        return True, "time_limit"
    count = await db.scalar(
        select(func.count(Message.id)).where(
            Message.channel_id == channel.id,
            Message.key_epoch == channel.key_epoch,
        )
    )
    if int(count or 0) >= settings.rekey_after_messages:
        return True, "message_limit"
    return False, None


@router.post("/messages")
async def send_message(
    body: SendMessageRequest,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    channel = await require_channel_member(db, body.channel_id, user)
    if not user.key_verified:
        raise HTTPException(409, "publish a verified key bundle before messaging")
    if body.key_epoch != channel.key_epoch:
        raise HTTPException(409, "wrong key epoch")

    required, reason = await _rekey_required(db, channel)
    if required:
        raise HTTPException(
            409,
            detail={
                "code": "rekey_required",
                "reason": reason,
                "current_epoch": channel.key_epoch,
            },
        )

    envelope = b64d(body.envelope_b64, field="envelope_b64")
    if len(envelope) < 30:
        raise HTTPException(400, "envelope too short")
    if len(envelope) > settings.max_message_bytes:
        raise HTTPException(413, "encrypted envelope too large")

    message = Message(
        client_message_id=body.client_message_id,
        sender_id=user.id,
        channel_id=channel.id,
        envelope=envelope,
        key_epoch=channel.key_epoch,
        content_hash=hashlib.sha256(envelope).digest(),
    )
    db.add(message)
    await audit(
        db,
        event="message.created",
        actor_id=user.id,
        request=request,
        detail=f"channel={channel.id};epoch={channel.key_epoch};bytes={len(envelope)}",
    )
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(409, "duplicate client_message_id") from None
    await db.refresh(message)

    members = await channel_member_users(db, channel.id)
    payload = _serialize(message, user.username)
    await manager.notify_users(
        [member.id for member in members],
        {"type": "message.created", "channel_id": channel.id, "message": payload},
    )
    return payload


@router.delete("/messages/{message_id}")
async def retract_message(
    message_id: str,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Drop the stored ciphertext of one's own message.

    This is the server half of a retraction, and it is deliberately the weaker half. The
    authoritative event is the sealed `del` payload the author publishes on the channel:
    peers honour that, and they would honour it even if this endpoint were never called or
    a hostile relay ignored it. What this adds is that the relay stops handing the
    ciphertext to anyone who asks again -- which matters for a device that has not synced
    yet, and not at all for one that already decrypted and cached the message.

    Say plainly what it cannot do: a recipient who has already read the message keeps it.
    No server-side delete can reach a plaintext that only ever existed on someone else's
    device, and promising otherwise would be the kind of claim this product exists not to
    make.

    The row itself stays. `content_hash` is a leaf in a published Merkle tree (see
    `blockchain/`), so removing the row would break every anchor proof issued for that
    batch -- including proofs about *other* people's messages that happen to share it.
    Emptying the envelope removes the content; keeping the hash preserves the proof that
    something stood there and was later withdrawn.
    """
    message = await db.get(Message, message_id)
    # A missing row and someone else's row are answered identically: a probe must not be
    # able to map which message ids exist by watching the status code change.
    if message is None or message.sender_id != user.id:
        raise HTTPException(404, "message not found")
    await require_channel_member(db, message.channel_id, user)

    if message.deleted_at is None:
        message.envelope = b""
        message.deleted_at = datetime.now(timezone.utc)
        await audit(
            db,
            event="message.deleted",
            actor_id=user.id,
            request=request,
            detail=f"channel={message.channel_id};message={message.id}",
        )
        await db.commit()
        await db.refresh(message)

        members = await channel_member_users(db, message.channel_id)
        await manager.notify_users(
            [member.id for member in members],
            {
                "type": "message.deleted",
                "channel_id": message.channel_id,
                "message_id": message.id,
                "deleted_at": jsonable_encoder(message.deleted_at),
            },
        )
    # Idempotent: deleting twice is a retry, not an error.
    return {"id": message.id, "deleted_at": message.deleted_at}


class ReceiptRequest(BaseModel):
    channel_id: str
    message_ids: list[str] = Field(min_length=1, max_length=200)
    state: Literal["delivered", "read"]


@router.post("/messages/receipts")
async def acknowledge_messages(
    body: ReceiptRequest,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Record that a recipient received or displayed messages.

    Metadata only, and only ever about someone else's messages -- acknowledging your own
    would let a client fabricate the receipt its peer is meant to produce.
    """
    channel = await require_channel_member(db, body.channel_id, user)
    rows = (
        await db.execute(
            select(Message.id, Message.sender_id).where(
                Message.id.in_(body.message_ids),
                Message.channel_id == channel.id,
                Message.sender_id != user.id,
            )
        )
    ).all()
    if not rows:
        return {"updated": 0, "state": body.state}

    now = datetime.now(timezone.utc)
    existing = {
        receipt.message_id: receipt
        for receipt in (
            await db.execute(
                select(MessageReceipt).where(
                    MessageReceipt.user_id == user.id,
                    MessageReceipt.message_id.in_([row[0] for row in rows]),
                )
            )
        ).scalars().all()
    }

    by_sender: dict[str, list[dict]] = defaultdict(list)
    updated = 0
    for message_id, sender_id in rows:
        receipt = existing.get(message_id)
        if receipt is None:
            receipt = MessageReceipt(
                message_id=message_id, user_id=user.id, channel_id=channel.id
            )
            db.add(receipt)
        # Reading implies delivery, and neither timestamp is ever moved backwards: a
        # late-arriving "delivered" from a second tab must not undo a read.
        if receipt.delivered_at is None:
            receipt.delivered_at = now
            updated += 1
        if body.state == "read" and receipt.read_at is None:
            receipt.read_at = now
            updated += 1
        by_sender[sender_id].append(
            {
                "message_id": message_id,
                "delivered_at": receipt.delivered_at,
                "read_at": receipt.read_at,
            }
        )

    try:
        await db.commit()
    except IntegrityError:
        # Two tabs acknowledging the same message at once is normal, not an error.
        await db.rollback()
        return {"updated": 0, "state": body.state}

    for sender_id, receipts in by_sender.items():
        await manager.notify_users(
            [sender_id],
            {
                "type": "message.receipts",
                "channel_id": channel.id,
                "by": user.id,
                "by_username": user.username,
                "receipts": jsonable_encoder(receipts),
            },
        )
    return {"updated": updated, "state": body.state}


async def _receipts_for(db: AsyncSession, channel_id: str, sender_id: str) -> dict[str, dict]:
    """Receipt state on `sender_id`'s messages, keyed by message id.

    A channel is two-party, so at most one peer receipt exists per message and the
    collapsed shape below is exact rather than a summary.
    """
    rows = (
        await db.execute(
            select(MessageReceipt)
            .join(Message, Message.id == MessageReceipt.message_id)
            .where(
                MessageReceipt.channel_id == channel_id,
                Message.sender_id == sender_id,
                MessageReceipt.user_id != sender_id,
            )
        )
    ).scalars().all()
    return {
        row.message_id: {"delivered_at": row.delivered_at, "read_at": row.read_at}
        for row in rows
    }


@router.get("/channels/{channel_id}/messages")
async def list_messages(
    channel_id: str,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: int = 100,
):
    await require_channel_member(db, channel_id, user)
    rows = (
        await db.execute(
            select(Message, User.username)
            .join(User, Message.sender_id == User.id)
            .where(Message.channel_id == channel_id)
            .order_by(Message.created_at.desc())
            .limit(min(max(limit, 1), 500))
        )
    ).all()
    receipts = await _receipts_for(db, channel_id, user.id)
    return [
        {**_serialize(message, username), "receipt": receipts.get(message.id)}
        for message, username in reversed(rows)
    ]


def _serialize(message: Message, username: str) -> dict:
    return {
        "id": message.id,
        "client_message_id": message.client_message_id,
        "sender_id": message.sender_id,
        "sender_name": username,
        "channel_id": message.channel_id,
        "envelope_b64": b64e(message.envelope),
        "key_epoch": message.key_epoch,
        "content_hash": message.content_hash.hex(),
        "anchor_batch_id": message.anchor_batch_id,
        "created_at": message.created_at,
        "deleted_at": message.deleted_at,
    }
