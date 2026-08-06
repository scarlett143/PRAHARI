from __future__ import annotations

import json
import time

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from ..database import get_session_factory
from ..models import User
from ..realtime import ConnectionLimitReached, manager
from ..security import assert_session_live, decode_access_token
from .common import channel_member_users, peer_user_ids, require_channel_member

router = APIRouter(tags=["websocket"])

#: A typing frame is advisory and high-frequency. Anything faster than this from one
#: socket is dropped rather than fanned out, so a misbehaving client cannot use the
#: relay to amplify traffic at its peers.
TYPING_MIN_INTERVAL_SECONDS = 1.0


async def _broadcast_presence(user_id: str, username: str, online: bool) -> None:
    async with get_session_factory()() as db:
        audience = await peer_user_ids(db, user_id)
    if audience:
        await manager.notify_users(
            audience,
            {
                "type": "presence.changed",
                "user_id": user_id,
                "username": username,
                "online": online,
            },
        )


async def _relay_typing(user_id: str, username: str, frame: dict) -> None:
    channel_id = frame.get("channel_id")
    if not isinstance(channel_id, str) or not channel_id:
        return
    state = "start" if frame.get("state") != "stop" else "stop"

    async with get_session_factory()() as db:
        user = (await db.execute(select(User).where(User.id == user_id))).scalars().first()
        if user is None:
            return
        # Membership is re-checked on every frame: a client must not be able to probe
        # channels it was removed from by continuing to emit typing events.
        try:
            await require_channel_member(db, channel_id, user)
        except Exception:
            return
        members = await channel_member_users(db, channel_id)

    targets = [member.id for member in members if member.id != user_id]
    if not targets:
        return
    await manager.notify_users(
        targets,
        {
            "type": "typing",
            "channel_id": channel_id,
            "user_id": user_id,
            "username": username,
            "state": state,
        },
    )


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    token = websocket.query_params.get("token", "")
    try:
        claims = decode_access_token(token)
    except Exception:
        await websocket.close(code=4401)
        return

    async with get_session_factory()() as db:
        user = (await db.execute(select(User).where(User.id == claims["sub"]))).scalars().first()
        if user is None or user.status != "active":
            await websocket.close(code=4403)
            return
        # A socket outlives the request that opened it, so revocation has to be checked
        # here too -- otherwise signing a device out would leave its live stream running.
        try:
            await assert_session_live(db, claims)
        except Exception:
            await websocket.close(code=4401)
            return
        user_id = user.id
        username = user.username
        peers = await peer_user_ids(db, user_id)

    try:
        came_online = await manager.connect(user_id, websocket)
    except ConnectionLimitReached:
        # 1013 "try again later" tells a well-behaved client to back off and retry
        # rather than treating this as a permanent authentication failure.
        await websocket.close(code=1013)
        return

    try:
        # The snapshot closes the join race: without it a client that connects after its
        # peers would show them offline until one of them happened to reconnect.
        await websocket.send_json(
            {
                "type": "connected",
                "user_id": user_id,
                "online_peers": sorted(set(peers) & manager.online_users()),
            }
        )
        if came_online:
            await _broadcast_presence(user_id, username, online=True)

        last_typing = 0.0
        while True:
            raw = await websocket.receive_text()
            if raw == "ping":
                continue
            try:
                frame = json.loads(raw)
            except (ValueError, TypeError):
                continue
            if not isinstance(frame, dict):
                continue

            kind = frame.get("type")
            if kind == "ping":
                continue
            if kind == "typing":
                now = time.monotonic()
                if now - last_typing < TYPING_MIN_INTERVAL_SECONDS:
                    continue
                last_typing = now
                await _relay_typing(user_id, username, frame)
    except WebSocketDisconnect:
        pass
    finally:
        went_offline = await manager.disconnect(user_id, websocket)
        if went_offline:
            await _broadcast_presence(user_id, username, online=False)
