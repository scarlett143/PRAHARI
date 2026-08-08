from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import Channel, Server, User, channel_members, server_members
from ..realtime import manager
from ..security import CurrentUser
from .common import audit

router = APIRouter(prefix="/api/v2/servers", tags=["servers"])


class CreateServerRequest(BaseModel):
    name: str = Field(min_length=1, max_length=96)


class AddMemberRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)


async def _serialize_server(db: AsyncSession, server: Server, current_user_id: str) -> dict:
    channels = (
        await db.execute(
            select(Channel)
            .join(channel_members, channel_members.c.channel_id == Channel.id)
            .where(Channel.server_id == server.id, channel_members.c.user_id == current_user_id)
            .order_by(Channel.created_at.asc())
        )
    ).scalars().all()
    members = (
        await db.execute(
            select(User.username)
            .join(server_members, server_members.c.user_id == User.id)
            .where(server_members.c.server_id == server.id)
            .order_by(User.username.asc())
        )
    ).scalars().all()
    return {
        "id": server.id,
        "name": server.name,
        "owner_id": server.owner_id,
        "members": list(members),
        "channels": [
            {"id": c.id, "name": c.name, "key_epoch": c.key_epoch, "epoch_started_at": c.epoch_started_at}
            for c in channels
        ],
    }


@router.get("")
async def list_servers(user: CurrentUser, db: Annotated[AsyncSession, Depends(get_db)]):
    rows = await db.execute(
        select(Server)
        .join(server_members, server_members.c.server_id == Server.id)
        .where(server_members.c.user_id == user.id)
        .order_by(Server.created_at.asc())
    )
    servers = rows.scalars().all()
    return [await _serialize_server(db, server, user.id) for server in servers]


@router.post("")
async def create_server(
    body: CreateServerRequest,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    if not user.key_verified:
        raise HTTPException(409, "publish a verified key bundle before creating a workspace")
    server = Server(name=body.name, owner_id=user.id)
    server.members.append(user)
    channel = Channel(name="general")
    channel.members.append(user)
    server.channels.append(channel)
    db.add(server)
    await db.flush()
    await audit(db, event="server.created", actor_id=user.id, request=request, detail=server.id)
    await db.commit()
    await db.refresh(server)
    return await _serialize_server(db, server, user.id)


@router.post("/{server_id}/members")
async def add_member(
    server_id: str,
    body: AddMemberRequest,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    server = (await db.execute(select(Server).where(Server.id == server_id))).scalars().first()
    if server is None:
        raise HTTPException(404, "server not found")
    if server.owner_id != user.id and user.role != "admin":
        raise HTTPException(403, "only the server owner can add members")

    target = (await db.execute(select(User).where(User.username == body.username))).scalars().first()
    if target is None:
        raise HTTPException(404, "user not found")
    if not target.key_verified:
        raise HTTPException(409, "user must publish a verified key bundle first")

    existing = await db.execute(
        select(server_members.c.user_id).where(
            server_members.c.server_id == server.id, server_members.c.user_id == target.id
        )
    )
    if existing.first() is None:
        await db.execute(server_members.insert().values(server_id=server.id, user_id=target.id))

    channels = (await db.execute(select(Channel).where(Channel.server_id == server.id))).scalars().all()
    joined: list[str] = []
    skipped: list[str] = []
    for channel in channels:
        member_ids = {
            row[0]
            for row in (
                await db.execute(
                    select(channel_members.c.user_id).where(
                        channel_members.c.channel_id == channel.id
                    )
                )
            ).all()
        }
        if target.id in member_ids:
            joined.append(channel.name)
            continue
        # Joining a workspace does not join you to conversations already in progress.
        # A channel's epoch key is sealed to the members it had when the epoch opened, so
        # someone dropped in here would hold no copy and read nothing. Growing a group is
        # a deliberate act that re-keys the channel -- see POST /channels/{id}/members.
        if len(member_ids) >= 2:
            skipped.append(channel.name)
            continue
        await db.execute(channel_members.insert().values(channel_id=channel.id, user_id=target.id))
        joined.append(channel.name)

    await audit(
        db,
        event="server.member_added",
        actor_id=user.id,
        request=request,
        detail=f"{server.id}:{target.username};joined={len(joined)};skipped={len(skipped)}",
    )
    await db.commit()

    # Without this the person being added sees nothing until they happen to reload, which
    # makes an invitation feel broken. Existing members are told too, so member lists and
    # presence dots converge without polling.
    existing_members = (
        await db.execute(
            select(server_members.c.user_id).where(server_members.c.server_id == server.id)
        )
    ).all()
    await manager.notify_users(
        [row[0] for row in existing_members],
        {
            "type": "server.member_added",
            "server_id": server.id,
            "user_id": target.id,
            "username": target.username,
            "joined_channels": joined,
        },
    )

    return {
        "server_id": server.id,
        "username": target.username,
        "added": True,
        "joined_channels": joined,
        "skipped_channels": skipped,
        "note": (
            "channels already holding two members were skipped; create a new channel to "
            "start an encrypted session with this member"
        )
        if skipped
        else None,
    }


class RenameServerRequest(BaseModel):
    name: str = Field(min_length=1, max_length=96)


async def _owned_server(db: AsyncSession, server_id: str, user: User) -> Server:
    server = (await db.execute(select(Server).where(Server.id == server_id))).scalars().first()
    if server is None:
        raise HTTPException(404, "server not found")
    if server.owner_id != user.id and user.role != "admin":
        raise HTTPException(403, "only the workspace owner can do that")
    return server


async def _member_ids(db: AsyncSession, server_id: str) -> list[str]:
    rows = (
        await db.execute(
            select(server_members.c.user_id).where(server_members.c.server_id == server_id)
        )
    ).all()
    return [row[0] for row in rows]


@router.patch("/{server_id}")
async def rename_server(
    server_id: str,
    body: RenameServerRequest,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Rename a workspace.

    A name is a label, not a key: nothing is derived from it and no envelope binds it, so
    changing one cannot invalidate a session or orphan a message.
    """
    server = await _owned_server(db, server_id, user)
    members = await _member_ids(db, server.id)
    previous, server.name = server.name, body.name.strip()

    await audit(
        db,
        event="server.renamed",
        actor_id=user.id,
        request=request,
        detail=f"{server.id}:{previous!r}->{server.name!r}",
    )
    await db.commit()
    await manager.notify_users(
        members, {"type": "server.renamed", "server_id": server.id, "name": server.name}
    )
    return await _serialize_server(db, server, user.id)


@router.delete("/{server_id}")
async def delete_server(
    server_id: str,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Destroy a workspace, its channels and their messages.

    Irreversible, and it reaches other people's history as well as the owner's, which is
    why the console asks for the name to be typed before calling this.

    What it cannot do is worth stating: every member who has already read a message holds
    the plaintext locally, and deleting the workspace does not reach their device. This
    removes the relay's copy.
    """
    server = await _owned_server(db, server_id, user)
    members = await _member_ids(db, server.id)
    name = server.name

    await audit(
        db,
        event="server.deleted",
        actor_id=user.id,
        severity="high",
        request=request,
        detail=f"{server.id}:{name!r}",
    )
    # Channels and messages go with it: the relationship cascades, and a channel outliving
    # its workspace would be unreachable rather than merely orphaned.
    await db.delete(server)
    await db.commit()
    await manager.notify_users(
        members, {"type": "server.deleted", "server_id": server_id, "name": name}
    )
    return {"deleted": server_id, "name": name}


async def _detach_member(
    db: AsyncSession, *, server: Server, target_id: str
) -> tuple[list[str], list[str]]:
    """Remove one member from a workspace and every channel in it.

    Returns the channels they left and those whose epoch was advanced. Rotation is the
    point: membership rows stop the relay handing them new envelopes, but the departing
    member still holds the current epoch's key and could read anything sent under it.
    Advancing the epoch is what actually ends their access.
    """
    channels = (
        await db.execute(select(Channel).where(Channel.server_id == server.id))
    ).scalars().all()

    left: list[str] = []
    rotated: list[str] = []
    for channel in channels:
        present = (
            await db.execute(
                select(channel_members.c.user_id).where(
                    channel_members.c.channel_id == channel.id,
                    channel_members.c.user_id == target_id,
                )
            )
        ).first()
        if present is None:
            continue
        await db.execute(
            channel_members.delete().where(
                channel_members.c.channel_id == channel.id,
                channel_members.c.user_id == target_id,
            )
        )
        left.append(channel.id)
        channel.key_epoch += 1
        channel.epoch_started_at = datetime.now(timezone.utc)
        rotated.append(channel.id)

    await db.execute(
        server_members.delete().where(
            server_members.c.server_id == server.id, server_members.c.user_id == target_id
        )
    )
    return left, rotated


@router.delete("/{server_id}/members/{user_id}")
async def remove_member(
    server_id: str,
    user_id: str,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Remove someone from a workspace, and rotate what they could still read."""
    server = await _owned_server(db, server_id, user)
    if user_id == server.owner_id:
        # Removing the owner would leave a workspace nobody can administer.
        raise HTTPException(409, "the owner cannot be removed; transfer or delete instead")

    members_before = await _member_ids(db, server.id)
    if user_id not in members_before:
        raise HTTPException(404, "that user is not a member")

    left, rotated = await _detach_member(db, server=server, target_id=user_id)
    await audit(
        db,
        event="server.member_removed",
        actor_id=user.id,
        severity="medium",
        request=request,
        detail=f"{server.id}:removed={user_id};rotated={len(rotated)}",
    )
    await db.commit()
    await manager.notify_users(
        members_before,
        {
            "type": "server.member_removed",
            "server_id": server.id,
            "user_id": user_id,
            "rotated_channels": rotated,
        },
    )
    return {"server_id": server.id, "removed": user_id, "left_channels": left, "rotated": rotated}


@router.post("/{server_id}/leave")
async def leave_server(
    server_id: str,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Leave a workspace you are a member of.

    Distinct from deleting it: the workspace survives for everyone else. The owner is
    refused, because leaving would strand a workspace with no one able to administer it.
    """
    server = (await db.execute(select(Server).where(Server.id == server_id))).scalars().first()
    if server is None:
        raise HTTPException(404, "server not found")
    if server.owner_id == user.id:
        raise HTTPException(409, "the owner cannot leave; delete the workspace instead")

    members_before = await _member_ids(db, server.id)
    if user.id not in members_before:
        raise HTTPException(404, "you are not a member of that workspace")

    left, rotated = await _detach_member(db, server=server, target_id=user.id)
    await audit(
        db,
        event="server.member_left",
        actor_id=user.id,
        request=request,
        detail=f"{server.id}:rotated={len(rotated)}",
    )
    await db.commit()
    await manager.notify_users(
        members_before,
        {
            "type": "server.member_removed",
            "server_id": server.id,
            "user_id": user.id,
            "rotated_channels": rotated,
        },
    )
    return {"server_id": server.id, "left_channels": left, "rotated": rotated}
