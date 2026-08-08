"""Authenticated WebSocket fan-out.

Sized for the 1000-endpoint target: a fleet-wide notification must not cost one
sequential round trip per connection, so sends are dispatched concurrently and a slow or
dead socket cannot stall delivery to everyone behind it.
"""
from __future__ import annotations

import asyncio
import json
import logging
from collections import defaultdict

from fastapi import WebSocket
from fastapi.encoders import jsonable_encoder

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

    def is_online(self, user_id: str) -> bool:
        return bool(self._connections.get(user_id))

    def online_users(self) -> set[str]:
        return {user_id for user_id, sockets in self._connections.items() if sockets}

    async def connect(self, user_id: str, websocket: WebSocket) -> bool:
        """Register a socket. Returns True when this user just came online.

        A user may hold several sockets at once (two browser tabs, a phone). Presence
        must flip on the *first* and off the *last*, never once per tab, or peers see a
        stream of spurious online/offline churn.
        """
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
            was_offline = not self._connections.get(user_id)
            self._connections[user_id].add(websocket)
            return was_offline

    async def disconnect(self, user_id: str, websocket: WebSocket) -> bool:
        """Drop a socket. Returns True when this user just went offline."""
        async with self._lock:
            sockets = self._connections.get(user_id)
            if not sockets or websocket not in sockets:
                return False
            sockets.discard(websocket)
            self._count = max(0, self._count - 1)
            if not sockets:
                self._connections.pop(user_id, None)
                return True
            return False

    async def close_user(self, user_id: str, *, code: int = 1008, reason: str = "revoked") -> int:
        """Force every live socket of one identity closed. Returns how many were cut.

        Revoking a session marks the database row, which stops the *next* request -- but a
        WebSocket that is already open never makes another one, so a quarantined endpoint
        would keep streaming on the connection it established while it was still trusted.
        A kill switch that leaves the existing link up is not a kill switch.

        The sockets are removed from the registry before being closed, so a concurrent
        fan-out cannot pick them up in the window between the two.
        """
        async with self._lock:
            sockets = list(self._connections.pop(user_id, ()))
            self._count = max(0, self._count - len(sockets))

        cut = 0
        for websocket in sockets:
            try:
                await asyncio.wait_for(
                    websocket.close(code=code, reason=reason), timeout=SEND_TIMEOUT_SECONDS
                )
            except Exception:
                # Already gone, which is the outcome we wanted anyway.
                pass
            cut += 1
        return cut

    async def notify_users(self, user_ids: list[str], payload: dict) -> int:
        """Deliver a payload to every live socket of the given users.

        Returns the number of successful deliveries. Failures are pruned rather than
        raised: a dropped link is normal operation, not an error for the caller.
        """
        # Encode once, before any socket is touched.
        #
        # This is deliberately outside the per-socket try/except. A payload that cannot be
        # serialised -- a stray datetime, say -- is a programming error, and if it were
        # allowed to raise inside `deliver` it would be indistinguishable from a dead
        # peer: every recipient would be quietly pruned as unreachable and the caller
        # would still see a successful request. Encoding up front turns that into a loud
        # failure at the source, and sending the same pre-rendered frame to every socket
        # is cheaper than re-serialising per connection during a fleet-wide fan-out.
        frame = json.dumps(jsonable_encoder(payload))

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
                    websocket.send_text(frame), timeout=SEND_TIMEOUT_SECONDS
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
