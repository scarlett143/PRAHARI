"""Authenticated WebSocket fan-out.

Sized for the 1000-endpoint target: a fleet-wide notification must not cost one
sequential round trip per connection, so sends are dispatched concurrently and a slow or
dead socket cannot stall delivery to everyone behind it.
"""
from __future__ import annotations

import asyncio
import logging
from collections import defaultdict

from fastapi import WebSocket

log = logging.getLogger(__name__)

#: A socket that cannot absorb a small JSON frame this quickly is treated as dead.
#: Without a bound, one stalled aircraft would hold up the whole fan-out.
SEND_TIMEOUT_SECONDS = 5.0


class ConnectionLimitReached(RuntimeError):
    pass


class ConnectionManager:
    def __init__(self, max_connections: int = 0) -> None:
        self._connections: dict[str, set[WebSocket]] = defaultdict(set)
        self._lock = asyncio.Lock()
        self._count = 0
        self.max_connections = max_connections

    @property
    def connection_count(self) -> int:
        return self._count

    @property
    def endpoint_count(self) -> int:
        return len(self._connections)

    async def connect(self, user_id: str, websocket: WebSocket) -> None:
        async with self._lock:
            if self.max_connections and self._count >= self.max_connections:
                raise ConnectionLimitReached(
                    f"refusing connection: {self._count} of {self.max_connections} in use"
                )
            self._count += 1
        try:
            await websocket.accept()
        except Exception:
            async with self._lock:
                self._count = max(0, self._count - 1)
            raise
        async with self._lock:
            self._connections[user_id].add(websocket)

    async def disconnect(self, user_id: str, websocket: WebSocket) -> None:
        async with self._lock:
            sockets = self._connections.get(user_id)
            if sockets and websocket in sockets:
                sockets.discard(websocket)
                self._count = max(0, self._count - 1)
                if not sockets:
                    self._connections.pop(user_id, None)

    async def notify_users(self, user_ids: list[str], payload: dict) -> int:
        """Deliver a payload to every live socket of the given users.

        Returns the number of successful deliveries. Failures are pruned rather than
        raised: a dropped link is normal operation, not an error for the caller.
        """
        async with self._lock:
            targets = [
                (uid, ws)
                for uid in set(user_ids)
                for ws in self._connections.get(uid, set())
            ]
        if not targets:
            return 0

        async def deliver(websocket: WebSocket) -> bool:
            try:
                await asyncio.wait_for(
                    websocket.send_json(payload), timeout=SEND_TIMEOUT_SECONDS
                )
                return True
            except Exception:
                return False

        results = await asyncio.gather(
            *(deliver(websocket) for _, websocket in targets), return_exceptions=True
        )

        delivered = 0
        stale: list[tuple[str, WebSocket]] = []
        for (uid, websocket), result in zip(targets, results):
            if result is True:
                delivered += 1
            else:
                stale.append((uid, websocket))

        for uid, websocket in stale:
            await self.disconnect(uid, websocket)
        if stale:
            log.debug("pruned %d stale websocket(s)", len(stale))
        return delivered


manager = ConnectionManager()
