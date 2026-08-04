from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from ..database import get_session_factory
from ..models import User
from ..realtime import manager
from ..security import decode_access_token

router = APIRouter(tags=["websocket"])


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
        user_id = user.id

    await manager.connect(user_id, websocket)
    try:
        await websocket.send_json({"type": "connected", "user_id": user_id})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        await manager.disconnect(user_id, websocket)
