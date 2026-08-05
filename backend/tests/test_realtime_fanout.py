"""ConnectionManager fan-out, presence transitions, and pruning.

Driven with fake sockets on a single event loop, so these assert the manager's behaviour
directly rather than through a live server. That matters most for the disconnect path,
which is inherently racy to observe through an HTTP test client.
"""
import asyncio
from datetime import datetime, timezone

import pytest

from app.realtime import ConnectionLimitReached, ConnectionManager


class FakeSocket:
    """Accepts, records frames, and can be told to fail like a dead peer."""

    def __init__(self, fail: bool = False, hang: bool = False):
        self.frames: list[str] = []
        self.accepted = False
        self.fail = fail
        self.hang = hang

    async def accept(self):
        self.accepted = True

    async def send_text(self, text: str):
        if self.fail:
            raise RuntimeError("peer is gone")
        if self.hang:
            await asyncio.sleep(3600)
        self.frames.append(text)


@pytest.mark.asyncio
async def test_payload_with_datetimes_is_delivered_not_silently_dropped():
    """Regression: a datetime in the payload used to raise inside the per-socket send.

    The catch-all there treated it as an unreachable peer, so a serialisation mistake
    disconnected every recipient of the fan-out while the originating request still
    returned 200. Encoding once, up front, is what keeps that honest.
    """
    manager = ConnectionManager()
    socket = FakeSocket()
    await manager.connect("u1", socket)

    delivered = await manager.notify_users(
        ["u1"],
        {
            "type": "message.created",
            "message": {"id": "m1", "created_at": datetime.now(timezone.utc)},
        },
    )

    assert delivered == 1
    assert manager.connection_count == 1, "a serialisable payload must not prune the socket"
    assert '"created_at"' in socket.frames[0]


@pytest.mark.asyncio
async def test_unserialisable_payload_raises_instead_of_pruning_everyone():
    manager = ConnectionManager()
    socket = FakeSocket()
    await manager.connect("u1", socket)

    with pytest.raises(Exception):
        await manager.notify_users(["u1"], {"type": "bad", "value": object()})

    # The failure must not have been mistaken for a dead peer.
    assert manager.connection_count == 1
    assert socket.frames == []


@pytest.mark.asyncio
async def test_presence_flips_on_first_and_last_socket_only():
    manager = ConnectionManager()
    first, second = FakeSocket(), FakeSocket()

    assert await manager.connect("u1", first) is True, "first socket brings the user online"
    assert await manager.connect("u1", second) is False, "a second tab is not a new arrival"
    assert manager.is_online("u1") is True

    assert await manager.disconnect("u1", first) is False, "one tab closing is not going offline"
    assert manager.is_online("u1") is True
    assert await manager.disconnect("u1", second) is True, "the last socket takes the user offline"
    assert manager.is_online("u1") is False
    assert manager.online_users() == set()


@pytest.mark.asyncio
async def test_dead_sockets_are_pruned_without_blocking_healthy_peers():
    manager = ConnectionManager()
    good, dead = FakeSocket(), FakeSocket(fail=True)
    await manager.connect("good", good)
    await manager.connect("dead", dead)

    delivered = await manager.notify_users(["good", "dead"], {"type": "ping"})

    assert delivered == 1
    assert manager.is_online("good") is True
    assert manager.is_online("dead") is False, "an unreachable socket is dropped"
    assert manager.connection_count == 1


@pytest.mark.asyncio
async def test_delivery_to_an_absent_user_is_not_an_error():
    manager = ConnectionManager()
    assert await manager.notify_users(["nobody"], {"type": "ping"}) == 0


@pytest.mark.asyncio
async def test_connection_cap_is_enforced_and_refunded_on_failure():
    manager = ConnectionManager(max_connections=1)
    await manager.connect("u1", FakeSocket())

    with pytest.raises(ConnectionLimitReached):
        await manager.connect("u2", FakeSocket())

    assert manager.connection_count == 1
    assert manager.endpoint_count == 1
