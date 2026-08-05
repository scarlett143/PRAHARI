from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import Channel, Message, Server, User, channel_members, server_members
from ..realtime import manager
from ..security import CurrentUser
from .common import audit, channel_member_users, require_channel_member

router = APIRouter(prefix="/api/v2/channels", tags=["channels"])


class CreateChannelRequest(BaseModel):
    server_id: str
    name: str = Field(min_length=1, max_length=96)
    # The hybrid session layer is strictly two-party, so a channel is the creator plus at
    # most one peer. Required once the workspace has grown beyond two members.
    peer_username: str | None = Field(default=None, max_length=64)


@router.post("")
async def create_channel(
    body: CreateChannelRequest,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    if not user.key_verified:
        raise HTTPException(409, "publish a verified key bundle before creating channels")
    server = (await db.execute(select(Server).where(Server.id == body.server_id))).scalars().first()
    if server is None:
        raise HTTPException(404, "server not found")
    if server.owner_id != user.id and user.role != "admin":
        raise HTTPException(403, "only the server owner can create channels")

    server_member_rows = (
        await db.execute(
            select(User)
            .join(server_members, server_members.c.user_id == User.id)
            .where(server_members.c.server_id == server.id)
        )
    ).scalars().all()
    by_name = {member.username: member for member in server_member_rows}

    if body.peer_username is not None:
        peer = by_name.get(body.peer_username)
        if peer is None:
            raise HTTPException(404, "peer is not a member of this workspace")
        if peer.id == user.id:
            raise HTTPException(400, "peer must be a different workspace member")
        if not peer.key_verified:
            raise HTTPException(409, "peer has no verified key bundle")
        members = [user, peer]
    elif len(server_member_rows) <= 2:
        members = list(server_member_rows)
    else:
        raise HTTPException(
            400,
            detail={
                "code": "peer_required",
                "message": (
                    "this workspace has more than two members and hybrid sessions are "
                    "two-party, so a channel must name the peer it is created with"
                ),
                "candidates": sorted(name for name in by_name if name != user.username),
            },
        )

    channel = Channel(name=body.name, server_id=server.id)
    channel.members.extend(members)
    db.add(channel)
    await db.flush()
    await audit(db, event="channel.created", actor_id=user.id, request=request, detail=channel.id)
    await db.commit()
    return {"id": channel.id, "name": channel.name, "server_id": channel.server_id, "key_epoch": 0}


@router.get("/{channel_id}")
async def get_channel(
    channel_id: str,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    channel = await require_channel_member(db, channel_id, user)
    members = await channel_member_users(db, channel_id)
    message_count = await db.scalar(
        select(func.count(Message.id)).where(
            Message.channel_id == channel.id, Message.key_epoch == channel.key_epoch
        )
    )
    sorted_members = sorted(members, key=lambda member: member.username.lower())
    return {
        "id": channel.id,
        "name": channel.name,
        "server_id": channel.server_id,
        "key_epoch": channel.key_epoch,
        "epoch_started_at": channel.epoch_started_at,
        "epoch_message_count": int(message_count or 0),
        "members": [
            {
                "id": member.id,
                "username": member.username,
                "kind": member.kind,
                "key_verified": member.key_verified,
            }
            for member in members
        ],
        # An explicit initiator wins: the aircraft link needs the side that transmits
        # first to drive the ratchet, which username order cannot express.
        "session_initiator_id": (
            (channel.initiator_id or sorted_members[0].id) if len(sorted_members) == 2 else None
        ),
        "hybrid_session_supported": len(sorted_members) == 2,
    }


@router.post("/{channel_id}/rotate-key")
async def rotate_key(
    channel_id: str,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    channel = await require_channel_member(db, channel_id, user)
    if not user.key_verified:
        raise HTTPException(409, "publish a verified key bundle before rotating keys")
    channel.key_epoch += 1
    channel.epoch_started_at = datetime.now(timezone.utc)
    members = await channel_member_users(db, channel.id)
    await audit(
        db,
        event="channel.epoch_rotated",
        actor_id=user.id,
        severity="medium",
        request=request,
        detail=f"{channel.id}:epoch={channel.key_epoch}",
    )
    await db.commit()
    await manager.notify_users(
        [member.id for member in members],
        {"type": "channel.epoch_rotated", "channel_id": channel.id, "key_epoch": channel.key_epoch},
    )
    return {"channel_id": channel.id, "key_epoch": channel.key_epoch, "epoch_started_at": channel.epoch_started_at}
