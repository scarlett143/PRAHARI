from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import User
from ..security import CurrentUser

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
    )
    if query.strip():
        statement = statement.where(User.username.ilike(f"%{query.strip()}%"))
    rows = (await db.execute(statement.order_by(User.username.asc()).limit(min(max(limit, 1), 50)))).scalars().all()
    return [
        {"id": row.id, "username": row.username, "key_verified": row.key_verified}
        for row in rows
    ]
