from __future__ import annotations

import base64
from typing import Optional

from fastapi import HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import AuditLog, Channel, User, channel_members


def b64d(value: str, *, expect: Optional[int] = None, field: str = "value") -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception:
        raise HTTPException(400, f"{field} is not valid base64") from None
    if expect is not None and len(raw) != expect:
        raise HTTPException(400, f"{field} must be {expect} bytes, got {len(raw)}")
    return raw


def b64e(value: bytes | None) -> str | None:
    return base64.b64encode(value).decode("ascii") if value is not None else None


async def audit(
    db: AsyncSession,
    *,
    event: str,
    actor_id: str | None = None,
    severity: str = "low",
    request: Request | None = None,
    detail: str | None = None,
) -> None:
    db.add(
        AuditLog(
            actor_id=actor_id,
            event=event,
            severity=severity,
            source_ip=request.client.host if request and request.client else None,
            detail=detail,
        )
    )


async def require_channel_member(db: AsyncSession, channel_id: str, user: User) -> Channel:
    row = await db.execute(
        select(Channel)
        .join(channel_members, channel_members.c.channel_id == Channel.id)
        .where(Channel.id == channel_id, channel_members.c.user_id == user.id)
    )
    channel = row.scalars().first()
    if channel is None:
        raise HTTPException(404, "channel not found")
    return channel


async def find_shared_channel(db: AsyncSession, user_a: str, user_b: str) -> Optional[Channel]:
    """The existing two-party channel joining these users, if there is one."""
    a_channels = select(channel_members.c.channel_id).where(channel_members.c.user_id == user_a)
    b_channels = select(channel_members.c.channel_id).where(channel_members.c.user_id == user_b)
    row = await db.execute(
        select(Channel).where(Channel.id.in_(a_channels), Channel.id.in_(b_channels))
    )
    return row.scalars().first()


async def open_two_party_channel(
    db: AsyncSession, *, server_id: str, members: list[User], name: str
) -> Channel:
    """Create a channel holding exactly the two given peers.

    Every path that opens a link -- invite redemption, a peer link request, the aircraft
    enrolment -- funnels through here so the two-party invariant the hybrid session
    depends on is enforced in one place rather than re-argued at each call site.
    """
    if len(members) != 2 or members[0].id == members[1].id:
        raise HTTPException(400, "a hybrid session channel holds exactly two distinct peers")
    channel = Channel(name=name, server_id=server_id)
    channel.members.extend(members)
    db.add(channel)
    await db.flush()
    return channel


async def peer_user_ids(db: AsyncSession, user_id: str) -> list[str]:
    """Everyone who shares at least one channel with this user.

    This is the audience for presence and typing. Scoping it to actual peers rather than
    broadcasting server-wide keeps the fan-out proportional to a user's real contacts --
    at the 1000-endpoint target a global presence broadcast would be quadratic -- and
    stops anyone from harvesting the liveness of operators they have no link with.
    """
    mine = select(channel_members.c.channel_id).where(channel_members.c.user_id == user_id)
    rows = await db.execute(
        select(channel_members.c.user_id)
        .where(channel_members.c.channel_id.in_(mine), channel_members.c.user_id != user_id)
        .distinct()
    )
    return [row[0] for row in rows.all()]


async def channel_member_users(db: AsyncSession, channel_id: str) -> list[User]:
    rows = await db.execute(
        select(User)
        .join(channel_members, channel_members.c.user_id == User.id)
        .where(channel_members.c.channel_id == channel_id)
        .order_by(User.username.asc())
    )
    return list(rows.scalars().all())
