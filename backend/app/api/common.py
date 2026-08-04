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


async def channel_member_users(db: AsyncSession, channel_id: str) -> list[User]:
    rows = await db.execute(
        select(User)
        .join(channel_members, channel_members.c.user_id == User.id)
        .where(channel_members.c.channel_id == channel_id)
        .order_by(User.username.asc())
    )
    return list(rows.scalars().all())
