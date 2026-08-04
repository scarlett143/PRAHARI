from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import AuditLog, User
from ..security import AdminUser
from .common import audit

router = APIRouter(prefix="/api/v2/admin", tags=["admin"])


@router.get("/users")
async def list_users(_: AdminUser, db: Annotated[AsyncSession, Depends(get_db)]):
    users = (await db.execute(select(User).order_by(User.username.asc()))).scalars().all()
    return [
        {
            "id": user.id,
            "username": user.username,
            "role": user.role,
            "status": user.status,
            "key_verified": user.key_verified,
            "last_login": user.last_login,
        }
        for user in users
    ]


@router.patch("/users/{user_id}/status")
async def set_user_status(
    user_id: str,
    new_status: str,
    admin: AdminUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    if new_status not in {"active", "suspended"}:
        raise HTTPException(400, "status must be active or suspended")
    target = (await db.execute(select(User).where(User.id == user_id))).scalars().first()
    if target is None:
        raise HTTPException(404, "user not found")
    if target.id == admin.id:
        raise HTTPException(400, "cannot change your own status")
    target.status = new_status
    await audit(
        db,
        event="admin.status_change",
        actor_id=admin.id,
        severity="high",
        request=request,
        detail=f"{target.username}->{new_status}",
    )
    await db.commit()
    return {"user_id": target.id, "status": target.status}


@router.get("/audit")
async def audit_log(_: AdminUser, db: Annotated[AsyncSession, Depends(get_db)], limit: int = 100):
    rows = (
        await db.execute(
            select(AuditLog).order_by(AuditLog.created_at.desc()).limit(min(max(limit, 1), 1000))
        )
    ).scalars().all()
    return [
        {
            "id": row.id,
            "actor_id": row.actor_id,
            "event": row.event,
            "severity": row.severity,
            "source_ip": row.source_ip,
            "detail": row.detail,
            "created_at": row.created_at,
        }
        for row in rows
    ]
