"""Shareable workspace invite links.

An invite carries no key material and grants no ability to read anything. Redeeming one
adds the holder to a workspace and opens a two-party channel with the creator; plaintext
still requires the ML-KEM + X25519 handshake against a signed key bundle. That is why the
code can safely travel over whatever channel the operator uses to send a link.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import Invite, Server, User, server_members
from ..realtime import manager
from ..security import CurrentUser
from .common import audit, find_shared_channel, open_two_party_channel

router = APIRouter(prefix="/api/v2", tags=["invites"])

#: 16 url-safe bytes -> ~128 bits of entropy. Guessing is not a threat worth modelling.
CODE_BYTES = 16
MAX_TTL_HOURS = 24 * 30


def hash_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


class CreateInviteRequest(BaseModel):
    server_id: str
    label: str | None = Field(default=None, max_length=96)
    max_uses: int = Field(default=1, ge=1, le=100)
    expires_in_hours: int | None = Field(default=24, ge=1, le=MAX_TTL_HOURS)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _state(invite: Invite) -> str:
    if invite.revoked:
        return "revoked"
    expires = _aware(invite.expires_at)
    if expires and expires <= datetime.now(timezone.utc):
        return "expired"
    if invite.use_count >= invite.max_uses:
        return "used_up"
    return "active"


def _serialize(invite: Invite) -> dict:
    return {
        "id": invite.id,
        "code_hint": invite.code_hint,
        "server_id": invite.server_id,
        "label": invite.label,
        "max_uses": invite.max_uses,
        "use_count": invite.use_count,
        "expires_at": invite.expires_at,
        "state": _state(invite),
        "created_at": invite.created_at,
    }


async def _require_owner(db: AsyncSession, server_id: str, user: User) -> Server:
    server = (await db.execute(select(Server).where(Server.id == server_id))).scalars().first()
    if server is None:
        raise HTTPException(404, "server not found")
    if server.owner_id != user.id and user.role != "admin":
        raise HTTPException(403, "only the workspace owner can manage invites")
    return server


@router.post("/invites")
async def create_invite(
    body: CreateInviteRequest,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    server = await _require_owner(db, body.server_id, user)
    if not user.key_verified:
        raise HTTPException(409, "publish a verified key bundle before creating invites")

    code = secrets.token_urlsafe(CODE_BYTES)
    expires_at = (
        datetime.now(timezone.utc) + timedelta(hours=body.expires_in_hours)
        if body.expires_in_hours
        else None
    )
    invite = Invite(
        code_hash=hash_code(code),
        code_hint=code[:6],
        server_id=server.id,
        created_by=user.id,
        label=body.label,
        max_uses=body.max_uses,
        expires_at=expires_at,
    )
    db.add(invite)
    await audit(
        db,
        event="invite.created",
        actor_id=user.id,
        request=request,
        detail=f"server={server.id};uses={body.max_uses};hint={invite.code_hint}",
    )
    await db.commit()
    await db.refresh(invite)

    # The only time the plaintext code exists outside the creator's browser.
    return {**_serialize(invite), "code": code, "path": f"/join/{code}"}


@router.get("/servers/{server_id}/invites")
async def list_invites(
    server_id: str,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    await _require_owner(db, server_id, user)
    rows = (
        await db.execute(
            select(Invite).where(Invite.server_id == server_id).order_by(Invite.created_at.desc())
        )
    ).scalars().all()
    return [_serialize(invite) for invite in rows]


@router.delete("/invites/{invite_id}")
async def revoke_invite(
    invite_id: str,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    invite = (await db.execute(select(Invite).where(Invite.id == invite_id))).scalars().first()
    if invite is None:
        raise HTTPException(404, "invite not found")
    await _require_owner(db, invite.server_id, user)
    invite.revoked = True
    await audit(db, event="invite.revoked", actor_id=user.id, request=request, detail=invite.id)
    await db.commit()
    return {"id": invite.id, "state": "revoked"}


async def _lookup(db: AsyncSession, code: str) -> Invite:
    invite = (
        await db.execute(select(Invite).where(Invite.code_hash == hash_code(code)))
    ).scalars().first()
    # A wrong code and a revoked code are both reported as 404 so the endpoint cannot be
    # used to confirm that a given code was ever real.
    if invite is None:
        raise HTTPException(404, "invite not found")
    return invite


@router.get("/invites/{code}/preview")
async def preview_invite(
    code: str,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Unauthenticated: someone must be able to see what they are joining before they
    register. Deliberately narrow -- workspace name and validity, nothing about members."""
    invite = await _lookup(code=code, db=db)
    server = (
        await db.execute(select(Server).where(Server.id == invite.server_id))
    ).scalars().first()
    state = _state(invite)
    inviter = (
        await db.execute(select(User.username).where(User.id == invite.created_by))
    ).scalars().first()
    return {
        "workspace_name": server.name if server else "unknown",
        "invited_by": inviter,
        "state": state,
        "valid": state == "active",
        "expires_at": invite.expires_at,
    }


@router.post("/invites/{code}/accept")
async def accept_invite(
    code: str,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    invite = await _lookup(code=code, db=db)
    state = _state(invite)
    if state != "active":
        raise HTTPException(409, detail={"code": f"invite_{state}", "message": f"invite is {state}"})
    if not user.key_verified:
        raise HTTPException(409, "publish a verified key bundle before joining a workspace")

    server = (
        await db.execute(select(Server).where(Server.id == invite.server_id))
    ).scalars().first()
    if server is None:
        raise HTTPException(404, "workspace no longer exists")
    if server.owner_id == user.id:
        raise HTTPException(400, "you already own this workspace")

    already = (
        await db.execute(
            select(server_members.c.user_id).where(
                server_members.c.server_id == server.id, server_members.c.user_id == user.id
            )
        )
    ).first()

    inviter = (
        await db.execute(select(User).where(User.id == invite.created_by))
    ).scalars().first()
    if inviter is None:
        raise HTTPException(409, "the operator who issued this invite no longer exists")

    channel = await find_shared_channel(db, user.id, inviter.id)
    if already is None:
        await db.execute(server_members.insert().values(server_id=server.id, user_id=user.id))
        # Only a genuinely new member consumes a use. Re-opening the link you already
        # redeemed should not burn someone else's seat.
        invite.use_count += 1

    if channel is None:
        channel = await open_two_party_channel(
            db,
            server_id=server.id,
            members=[inviter, user],
            name=f"{inviter.username}-{user.username}",
        )

    await audit(
        db,
        event="invite.accepted",
        actor_id=user.id,
        request=request,
        detail=f"server={server.id};invite={invite.id};channel={channel.id}",
    )
    await db.commit()

    payload = {
        "type": "server.member_joined",
        "server_id": server.id,
        "channel_id": channel.id,
        "user_id": user.id,
        "username": user.username,
        "via": "invite",
    }
    await manager.notify_users([inviter.id], payload)

    return {
        "server_id": server.id,
        "server_name": server.name,
        "channel_id": channel.id,
        "peer": inviter.username,
        "joined": True,
    }
