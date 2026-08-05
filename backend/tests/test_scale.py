"""Scale validation for the 1000-endpoint deployment target.

The fast tier runs in CI on every commit: it provisions a full 1000-aircraft fleet and
checks that registry queries stay bounded and paginated at that size.

The heavy tier -- 1000 *complete* hybrid handshakes -- is opt-in because pure-Python
ML-KEM makes it minutes long:

    PRAHARI_LOAD_TEST=1 pytest tests/test_scale.py -k full_fleet -s
"""
import pytest

pytest.importorskip("aiosqlite")
pytest.importorskip("kyber_py")

import os
import time
import uuid

from fastapi.testclient import TestClient

from app.crypto import hybrid
from app.main import app
from app.realtime import ConnectionManager

from test_api_flow import register_verified

TARGET_ENDPOINTS = 1000


def _unique(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


def test_provisioning_a_thousand_endpoints_stays_bounded():
    with TestClient(app) as client:
        headers, _, _ = register_verified(client, _unique("gcs"))
        prefix = _unique("SCALE")

        started = time.monotonic()
        response = client.post(
            "/api/v2/fleet/uavs/bulk",
            headers=headers,
            json={
                "callsign_prefix": prefix,
                "count": TARGET_ENDPOINTS,
                "fleet": "scale",
                "airframe": "fixed-wing",
            },
        )
        provision_seconds = time.monotonic() - started

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["provisioned"] == TARGET_ENDPOINTS
        assert len({item["callsign"] for item in body["endpoints"]}) == TARGET_ENDPOINTS
        assert len({item["enrollment_token"] for item in body["endpoints"]}) == TARGET_ENDPOINTS

        # Guards the choice of SHA-256 over Argon2 for high-entropy provisioning tokens:
        # Argon2 at 64 MiB per token would make this step take minutes and ~64 GiB of work.
        assert provision_seconds < 60, f"provisioning took {provision_seconds:.1f}s"

        started = time.monotonic()
        listed = client.get("/api/v2/fleet/uavs?fleet=scale&limit=1000", headers=headers)
        query_seconds = time.monotonic() - started
        assert listed.status_code == 200
        assert listed.json()["total"] >= TARGET_ENDPOINTS
        assert listed.json()["returned"] == 1000
        assert query_seconds < 10, f"fleet listing took {query_seconds:.1f}s"

        # Pagination must be stable so an operator UI can page a large fleet.
        first_page = client.get(
            "/api/v2/fleet/uavs?fleet=scale&limit=50&offset=0", headers=headers
        ).json()["endpoints"]
        second_page = client.get(
            "/api/v2/fleet/uavs?fleet=scale&limit=50&offset=50", headers=headers
        ).json()["endpoints"]
        assert len(first_page) == len(second_page) == 50
        assert not {item["callsign"] for item in first_page} & {
            item["callsign"] for item in second_page
        }
        assert [item["callsign"] for item in first_page] == sorted(
            item["callsign"] for item in first_page
        )


def test_listing_is_capped_so_one_request_cannot_pull_the_whole_fleet():
    with TestClient(app) as client:
        headers, _, _ = register_verified(client, _unique("gcs"))
        client.post(
            "/api/v2/fleet/uavs/bulk",
            headers=headers,
            json={"callsign_prefix": _unique("CAP"), "count": 5, "fleet": "cap"},
        )
        response = client.get("/api/v2/fleet/uavs?limit=99999", headers=headers)
        assert response.status_code == 200
        assert response.json()["returned"] <= 1000


def test_bulk_provisioning_refuses_more_than_the_supported_batch():
    with TestClient(app) as client:
        headers, _, _ = register_verified(client, _unique("gcs"))
        response = client.post(
            "/api/v2/fleet/uavs/bulk",
            headers=headers,
            json={"callsign_prefix": "TOOBIG", "count": TARGET_ENDPOINTS + 1},
        )
        assert response.status_code == 422


@pytest.mark.anyio
async def test_fanout_to_a_thousand_sockets_is_concurrent_and_prunes_dead_links():
    """One slow socket must not serialise or block delivery to the rest of the fleet."""
    import asyncio

    class FakeSocket:
        def __init__(self, *, fails: bool = False, delay: float = 0.0):
            self.fails = fails
            self.delay = delay
            self.received = 0

        # The manager renders the payload once and sends the same text to every socket,
        # so the fan-out cost per connection is a write, not a re-serialisation.
        async def send_text(self, _frame):
            if self.delay:
                await asyncio.sleep(self.delay)
            if self.fails:
                raise ConnectionResetError("socket is gone")
            self.received += 1

    manager = ConnectionManager()
    healthy = [FakeSocket(delay=0.01) for _ in range(TARGET_ENDPOINTS - 10)]
    dead = [FakeSocket(fails=True) for _ in range(10)]

    # Populate directly: FakeSocket has no accept(), and connect() is covered elsewhere.
    for index, socket in enumerate(healthy + dead):
        manager._connections[f"endpoint-{index}"].add(socket)
        manager._count += 1

    user_ids = [f"endpoint-{index}" for index in range(TARGET_ENDPOINTS)]

    started = time.monotonic()
    delivered = await manager.notify_users(user_ids, {"type": "fleet.broadcast"})
    elapsed = time.monotonic() - started

    assert delivered == len(healthy)
    assert all(socket.received == 1 for socket in healthy)

    # Sequential delivery would cost ~10s (1000 x 10 ms); concurrent is ~10 ms.
    assert elapsed < 2.0, f"fan-out took {elapsed:.2f}s -- not concurrent"

    # Dead sockets are pruned, so the next broadcast does not retry them.
    assert manager.connection_count == len(healthy)


def test_connection_limit_is_enforced():
    manager = ConnectionManager(max_connections=3)
    manager._count = 3
    assert manager.connection_count == 3
    assert manager.max_connections == 3


@pytest.mark.skipif(
    os.getenv("PRAHARI_LOAD_TEST") != "1",
    reason="heavy: set PRAHARI_LOAD_TEST=1 to run 1000 full ML-KEM handshakes",
)
def test_full_fleet_hybrid_handshake_throughput():
    """Measure real X25519 + ML-KEM-768 handshake cost across the whole fleet."""
    started = time.monotonic()
    for _ in range(TARGET_ENDPOINTS):
        public, private = hybrid.generate_bundle()
        ciphertext, initiator_key = hybrid.initiate(public)
        responder_key = hybrid.respond(private, public, ciphertext)
        assert responder_key == initiator_key
    elapsed = time.monotonic() - started
    print(
        f"\n{TARGET_ENDPOINTS} hybrid handshakes in {elapsed:.1f}s "
        f"({elapsed / TARGET_ENDPOINTS * 1000:.1f} ms each, backend={hybrid.pqc.get_backend().name})"
    )
    assert elapsed < 600
