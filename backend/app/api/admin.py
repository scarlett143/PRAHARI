from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit_chain
from ..database import get_db
from ..models import AuditCheckpoint, AuditLog, User
from ..security import AdminUser
from .common import audit

router = APIRouter(prefix="/api/v2/admin", tags=["admin"])


@router.get("/users")
async def list_users(
    _: AdminUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: int = 100,
    offset: int = 0,
    kind: str | None = None,
):
    """Accounts, a page at a time.

    Paginated because this used to select every row. An account is created per unmanned
    endpoint as well as per person, so a fleet sized for this deployment's stated target
    turns "list the users" into a thousand-row serialisation on a two-core box -- and the
    caller almost always wanted the handful of humans.
    """
    conditions = []
    if kind:
        conditions.append(User.kind == kind)

    users = (
        await db.execute(
            select(User)
            .where(*conditions)
            .order_by(User.username.asc())
            .offset(max(offset, 0))
            .limit(min(max(limit, 1), 500))
        )
    ).scalars().all()
    total = await db.scalar(select(func.count(User.id)).where(*conditions))
    return {
        "total": int(total or 0),
        "returned": len(users),
        "users": [
            {
                "id": user.id,
                "username": user.username,
                "kind": user.kind,
                "role": user.role,
                "status": user.status,
                "key_verified": user.key_verified,
                "last_login": user.last_login,
            }
            for user in users
        ],
    }


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


@router.post("/audit/seal")
async def seal_audit_log(
    _: AdminUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: int = audit_chain.CHUNK,
):
    """Stamp newly written audit rows into the tamper-evident chain.

    Explicit rather than automatic, for the same reason anchor batching is: the write path
    stays free of hashing and of the contention a per-write chain would introduce. Call it
    on a schedule that matches how much unprotected history is tolerable -- everything
    written since the last seal can still be deleted without trace.
    """
    return await audit_chain.seal(db, limit=limit)


@router.get("/audit/verify")
async def verify_audit_log(_: AdminUser, db: Annotated[AsyncSession, Depends(get_db)]):
    """Recompute the sealed chain and report whether it still holds."""
    return await audit_chain.verify(db)


@router.get("/audit/checkpoints")
async def list_audit_checkpoints(
    _: AdminUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: int = 50,
):
    """Recorded chain heads, newest first.

    Worth exporting somewhere this server cannot write. A checkpoint held only here is
    one an attacker who can rewrite the log can rewrite too; held elsewhere, it is what
    makes a shortened log provable rather than merely suspected.
    """
    rows = (
        await db.execute(
            select(AuditCheckpoint)
            .order_by(AuditCheckpoint.seq.desc())
            .limit(min(max(limit, 1), 500))
        )
    ).scalars().all()
    return [
        {
            "seq": row.seq,
            "head_hash": row.head_hash.hex(),
            "entry_count": row.entry_count,
            "created_at": row.created_at,
        }
        for row in rows
    ]


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
