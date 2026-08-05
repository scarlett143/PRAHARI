from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import LinkRequest, User
from ..realtime import manager
from ..security import CurrentUser
from .common import peer_user_ids

router = APIRouter(prefix="/api/v2/users", tags=["users"])


@router.get("")
async def search_users(
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    query: str = "",
    limit: int = 20,
):
    statement = select(User).where(
        User.status == "active",
        User.key_verified.is_(True),
        User.id != user.id,
        # Unmanned endpoints are reached through the fleet APIs, not user search.
        User.kind == "human",
    )
    if query.strip():
        statement = statement.where(User.username.ilike(f"%{query.strip()}%"))
    rows = (await db.execute(statement.order_by(User.username.asc()).limit(min(max(limit, 1), 50)))).scalars().all()

    # The directory is only useful if it says what you can do with each row, so it
    # carries the state the "Link" button branches on rather than making the client
    # issue a follow-up request per user.
    linked = {
        peer_id
        for peer_id in await peer_user_ids(db, user.id)
    }
    pending = (
        await db.execute(
            select(LinkRequest).where(
                LinkRequest.status == "pending",
                or_(
                    and_(LinkRequest.requester_id == user.id, LinkRequest.target_id.in_([r.id for r in rows] or [""])),
                    and_(LinkRequest.target_id == user.id, LinkRequest.requester_id.in_([r.id for r in rows] or [""])),
                ),
            )
        )
    ).scalars().all()
    outgoing = {row.target_id: row.id for row in pending if row.requester_id == user.id}
    incoming = {row.requester_id: row.id for row in pending if row.target_id == user.id}

    online = manager.online_users()
    return [
        {
            "id": row.id,
            "username": row.username,
            "key_verified": row.key_verified,
            "online": row.id in online,
            "link_state": (
                "linked"
                if row.id in linked
                else "outgoing_pending"
                if row.id in outgoing
                else "incoming_pending"
                if row.id in incoming
                else "none"
            ),
            "link_id": outgoing.get(row.id) or incoming.get(row.id),
        }
        for row in rows
    ]


@router.get("/presence")
async def presence(
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Liveness of the operators this user actually shares a channel with.

    Scoped to peers on purpose: presence is metadata about a person, and there is no
    reason for one operator to be able to enumerate the liveness of the whole roster.
    """
    peers = await peer_user_ids(db, user.id)
    if not peers:
        return {"online": [], "peers": []}
    rows = (
        await db.execute(select(User.id, User.username).where(User.id.in_(peers)))
    ).all()
    live = manager.online_users()
    return {
        "online": [user_id for user_id, _ in rows if user_id in live],
        "peers": [
            {"id": user_id, "username": username, "online": user_id in live}
            for user_id, username in rows
        ],
    }
