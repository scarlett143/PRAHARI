"""Small authenticated WebSocket fan-out manager."""
from __future__ import annotations

import asyncio
from collections import defaultdict

from fastapi import WebSocket


class ConnectionManager:
    def __init__(self) -> None:
        self._connections: dict[str, set[WebSocket]] = defaultdict(set)
        self._lock = asyncio.Lock()

    async def connect(self, user_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections[user_id].add(websocket)

    async def disconnect(self, user_id: str, websocket: WebSocket) -> None:
        async with self._lock:
            sockets = self._connections.get(user_id)
            if sockets:
                sockets.discard(websocket)
                if not sockets:
                    self._connections.pop(user_id, None)

    async def notify_users(self, user_ids: list[str], payload: dict) -> None:
        stale: list[tuple[str, WebSocket]] = []
        async with self._lock:
            targets = [(uid, ws) for uid in set(user_ids) for ws in self._connections.get(uid, set())]
        for uid, websocket in targets:
            try:
                await websocket.send_json(payload)
            except Exception:
                stale.append((uid, websocket))
        for uid, websocket in stale:
            await self.disconnect(uid, websocket)


manager = ConnectionManager()
