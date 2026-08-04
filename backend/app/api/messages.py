from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..database import get_db
from ..models import Message, User
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
    return [_serialize(message, username) for message, username in reversed(rows)]


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
    }
