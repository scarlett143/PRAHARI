"""Direct operator-to-operator links.

The same consent model the aircraft link uses: a link exists only once both ends have
agreed to it. A request creates nothing but a pending row -- no channel, no session, no
key exchange -- so nobody can force a session onto a peer, and declining leaves no trace
the requester can act on beyond the verdict itself.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import LinkRequest, Server, User, server_members
from ..realtime import manager
from ..security import CurrentUser
from .common import audit, find_shared_channel, open_two_party_channel

router = APIRouter(prefix="/api/v2/links", tags=["links"])

DIRECT_WORKSPACE_NAME = "Direct Links"


class CreateLinkRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    note: str | None = Field(default=None, max_length=200)


def _serialize(row: LinkRequest, requester: str, target: str) -> dict:
    return {
        "id": row.id,
        "requester_id": row.requester_id,
        "requester": requester,
        "target_id": row.target_id,
        "target": target,
        "status": row.status,
        "note": row.note,
        "channel_id": row.channel_id,
        "created_at": row.created_at,
        "responded_at": row.responded_at,
    }


async def _names(db: AsyncSession, rows: list[LinkRequest]) -> dict[str, str]:
    ids = {row.requester_id for row in rows} | {row.target_id for row in rows}
    if not ids:
        return {}
    found = await db.execute(select(User.id, User.username).where(User.id.in_(ids)))
    return {user_id: username for user_id, username in found.all()}


@router.post("")
async def request_link(
    body: CreateLinkRequest,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    if not user.key_verified:
        raise HTTPException(409, "publish a verified key bundle before requesting a link")

    target = (
        await db.execute(select(User).where(User.username == body.username))
    ).scalars().first()
    if target is None or target.status != "active":
        raise HTTPException(404, "user not found")
    if target.id == user.id:
        raise HTTPException(400, "you cannot link with yourself")
    if target.kind != "human":
        raise HTTPException(400, "unmanned endpoints are linked through the fleet API")
    if not target.key_verified:
        raise HTTPException(409, "that operator has not published a verified key bundle yet")

    existing = await find_shared_channel(db, user.id, target.id)
    if existing is not None:
        return {
            "status": "already_linked",
            "channel_id": existing.id,
            "target": target.username,
        }

    # An inbound request from the same peer is answered by accepting it, not by opening a
    # mirrored second request that would leave two pending rows for one relationship.
    inbound = (
        await db.execute(
            select(LinkRequest).where(
                LinkRequest.requester_id == target.id,
                LinkRequest.target_id == user.id,
                LinkRequest.status == "pending",
            )
        )
    ).scalars().first()
    if inbound is not None:
        return {
            "status": "reciprocal_pending",
            "link_id": inbound.id,
            "message": f"{target.username} already requested a link with you; accept it instead",
        }

    link = LinkRequest(requester_id=user.id, target_id=target.id, note=body.note)
    db.add(link)
    await audit(
        db,
        event="link.requested",
        actor_id=user.id,
        request=request,
        detail=f"target={target.username}",
    )
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(409, "a link request to this operator is already pending") from None
    await db.refresh(link)

    await manager.notify_users(
        [target.id],
        {
            "type": "link.requested",
            "link_id": link.id,
            "requester_id": user.id,
            "requester": user.username,
            "note": link.note,
        },
    )
    return _serialize(link, user.username, target.username)


@router.get("")
async def list_links(
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    rows = (
        await db.execute(
            select(LinkRequest)
            .where(or_(LinkRequest.requester_id == user.id, LinkRequest.target_id == user.id))
            .order_by(LinkRequest.created_at.desc())
            .limit(200)
        )
    ).scalars().all()
    names = await _names(db, list(rows))
    serialized = [
        _serialize(row, names.get(row.requester_id, "?"), names.get(row.target_id, "?"))
        for row in rows
    ]
    return {
        "incoming": [
            row for row in serialized if row["target_id"] == user.id and row["status"] == "pending"
        ],
        "outgoing": [
            row
            for row in serialized
            if row["requester_id"] == user.id and row["status"] == "pending"
        ],
        "history": [row for row in serialized if row["status"] != "pending"],
    }


async def _direct_workspace(db: AsyncSession, owner: User, peer: User) -> Server:
    """The workspace a directly-linked pair lands in, created on first use."""
    server = (
        await db.execute(
            select(Server).where(
                Server.owner_id == owner.id, Server.name == DIRECT_WORKSPACE_NAME
            )
        )
    ).scalars().first()
    if server is None:
        server = Server(name=DIRECT_WORKSPACE_NAME, owner_id=owner.id)
        server.members.append(owner)
        db.add(server)
        await db.flush()

    for member in (owner, peer):
        present = (
            await db.execute(
                select(server_members.c.user_id).where(
                    server_members.c.server_id == server.id,
                    server_members.c.user_id == member.id,
                )
            )
        ).first()
        if present is None:
            await db.execute(
                server_members.insert().values(server_id=server.id, user_id=member.id)
            )
    return server


@router.post("/{link_id}/accept")
async def accept_link(
    link_id: str,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    link = (await db.execute(select(LinkRequest).where(LinkRequest.id == link_id))).scalars().first()
    if link is None or link.target_id != user.id:
        raise HTTPException(404, "link request not found")
    if link.status != "pending":
        raise HTTPException(409, f"link request is already {link.status}")
    if not user.key_verified:
        raise HTTPException(409, "publish a verified key bundle before accepting a link")

    requester = (
        await db.execute(select(User).where(User.id == link.requester_id))
    ).scalars().first()
    if requester is None:
        raise HTTPException(409, "the requesting operator no longer exists")

    channel = await find_shared_channel(db, user.id, requester.id)
    if channel is None:
        server = await _direct_workspace(db, requester, user)
        channel = await open_two_party_channel(
            db,
            server_id=server.id,
            members=[requester, user],
            name=f"{requester.username}-{user.username}",
        )
    else:
        server = (
            await db.execute(select(Server).where(Server.id == channel.server_id))
        ).scalars().first()

    link.status = "accepted"
    link.channel_id = channel.id
    link.server_id = server.id if server else None
    link.responded_at = datetime.now(timezone.utc)

    await audit(
        db,
        event="link.accepted",
        actor_id=user.id,
        request=request,
        detail=f"requester={requester.username};channel={channel.id}",
    )
    await db.commit()

    payload = {
        "type": "link.accepted",
        "link_id": link.id,
        "channel_id": channel.id,
        "server_id": link.server_id,
        "requester": requester.username,
        "target": user.username,
    }
    await manager.notify_users([requester.id, user.id], payload)
    return {
        "id": link.id,
        "status": "accepted",
        "channel_id": channel.id,
        "server_id": link.server_id,
        "peer": requester.username,
    }


@router.post("/{link_id}/decline")
async def decline_link(
    link_id: str,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    link = (await db.execute(select(LinkRequest).where(LinkRequest.id == link_id))).scalars().first()
    if link is None or link.target_id != user.id:
        raise HTTPException(404, "link request not found")
    if link.status != "pending":
        raise HTTPException(409, f"link request is already {link.status}")

    link.status = "declined"
    link.responded_at = datetime.now(timezone.utc)
    await audit(db, event="link.declined", actor_id=user.id, request=request, detail=link.id)
    await db.commit()

    await manager.notify_users(
        [link.requester_id],
        {"type": "link.declined", "link_id": link.id, "target": user.username},
    )
    return {"id": link.id, "status": "declined"}


@router.delete("/{link_id}")
async def cancel_link(
    link_id: str,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    link = (await db.execute(select(LinkRequest).where(LinkRequest.id == link_id))).scalars().first()
    if link is None or link.requester_id != user.id:
        raise HTTPException(404, "link request not found")
    if link.status != "pending":
        raise HTTPException(409, f"link request is already {link.status}")

    link.status = "cancelled"
    link.responded_at = datetime.now(timezone.utc)
    await audit(db, event="link.cancelled", actor_id=user.id, request=request, detail=link.id)
    await db.commit()

    await manager.notify_users(
        [link.target_id],
        {"type": "link.cancelled", "link_id": link.id, "requester": user.username},
    )
    return {"id": link.id, "status": "cancelled"}
