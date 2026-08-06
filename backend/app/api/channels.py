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


#: The epoch key is sealed once per member, so creating a group costs one ML-KEM
#: encapsulation per head. A ceiling keeps that bounded and keeps a typo from asking the
#: browser to do a thousand of them.
MAX_CHANNEL_MEMBERS = 64


class CreateChannelRequest(BaseModel):
    server_id: str
    name: str = Field(min_length=1, max_length=96)
    #: Two-party channel with exactly this peer. Seeds a Double Ratchet.
    peer_username: str | None = Field(default=None, max_length=64)
    #: Group channel with the creator plus these members. Mutually exclusive with
    #: `peer_username`; naming a single member here is the same thing as a peer channel.
    member_usernames: list[str] | None = Field(default=None)


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

    if body.peer_username is not None and body.member_usernames:
        raise HTTPException(400, "give either peer_username or member_usernames, not both")

    if body.member_usernames is not None:
        requested = [name for name in dict.fromkeys(body.member_usernames) if name != user.username]
        if not requested:
            raise HTTPException(400, "member_usernames must name at least one other member")
        if len(requested) + 1 > MAX_CHANNEL_MEMBERS:
            raise HTTPException(400, f"a channel holds at most {MAX_CHANNEL_MEMBERS} members")
        members = [user]
        for name in requested:
            member = by_name.get(name)
            if member is None:
                raise HTTPException(404, f"{name} is not a member of this workspace")
            # Without a published bundle there is nothing to seal the group key to, so
            # they would join and then be unable to read anything.
            if not member.key_verified:
                raise HTTPException(409, f"{name} has no verified key bundle")
            members.append(member)
    elif body.peer_username is not None:
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
                    "this workspace has more than two members, so a channel must say who "
                    "is in it: peer_username for a two-party ratchet, or member_usernames "
                    "for a group"
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
        # first to drive the ratchet, which username order cannot express. On a group the
        # same value decides who mints the epoch key and seals it to everyone else, so
        # both sides of that arrangement agree without another round trip.
        "session_initiator_id": (
            (channel.initiator_id or sorted_members[0].id) if len(sorted_members) >= 2 else None
        ),
        "hybrid_session_supported": len(sorted_members) >= 2,
        # Three or more members means a shared epoch key rather than a pairwise ratchet.
        # The client has to know which of the two it is before it encrypts anything.
        "group": len(sorted_members) > 2,
    }


class AddChannelMemberRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)


@router.post("/{channel_id}/members")
async def add_channel_member(
    channel_id: str,
    body: AddChannelMemberRequest,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Add someone to a group channel and force a re-key.

    The epoch key was sealed to the members present when the epoch opened, so a new
    arrival has no copy of it. Bumping the epoch here is not bookkeeping -- it is what
    makes the channel readable for them, because the initiator then publishes a fresh
    group key sealed to the new member list.

    It also decides what they can read: the new epoch is a clean break, so history from
    earlier epochs stays unreadable to them. That is the intended property, not a
    limitation to work around.
    """
    channel = await require_channel_member(db, channel_id, user)
    if not user.key_verified:
        raise HTTPException(409, "publish a verified key bundle before changing membership")

    members = await channel_member_users(db, channel.id)
    if len(members) < 2:
        raise HTTPException(409, "channel has no established membership yet")
    if len(members) >= MAX_CHANNEL_MEMBERS:
        raise HTTPException(400, f"a channel holds at most {MAX_CHANNEL_MEMBERS} members")

    server = (await db.execute(select(Server).where(Server.id == channel.server_id))).scalars().first()
    if server is None:
        raise HTTPException(404, "workspace not found")
    if server.owner_id != user.id and user.role != "admin":
        raise HTTPException(403, "only the workspace owner can change channel membership")

    target = (
        await db.execute(select(User).where(User.username == body.username))
    ).scalars().first()
    if target is None:
        raise HTTPException(404, "user not found")
    if not target.key_verified:
        raise HTTPException(409, "user must publish a verified key bundle first")
    if any(member.id == target.id for member in members):
        raise HTTPException(409, f"{target.username} is already in this channel")

    in_workspace = (
        await db.execute(
            select(server_members.c.user_id).where(
                server_members.c.server_id == server.id,
                server_members.c.user_id == target.id,
            )
        )
    ).first()
    if in_workspace is None:
        await db.execute(server_members.insert().values(server_id=server.id, user_id=target.id))

    await db.execute(channel_members.insert().values(channel_id=channel.id, user_id=target.id))

    # A two-party channel that gains a third member stops being a ratchet and becomes a
    # group. Naming the initiator keeps key distribution with the person doing the adding
    # rather than letting it move on the next username sort.
    channel.initiator_id = channel.initiator_id or user.id
    channel.key_epoch += 1
    channel.epoch_started_at = datetime.now(timezone.utc)

    await audit(
        db,
        event="channel.member_added",
        actor_id=user.id,
        severity="medium",
        request=request,
        detail=f"{channel.id}:{target.username}:epoch={channel.key_epoch}",
    )
    await db.commit()

    await manager.notify_users(
        [member.id for member in members] + [target.id],
        {
            "type": "channel.epoch_rotated",
            "channel_id": channel.id,
            "key_epoch": channel.key_epoch,
        },
    )
    return {
        "channel_id": channel.id,
        "added": target.username,
        "key_epoch": channel.key_epoch,
        "members": [member.username for member in members] + [target.username],
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
