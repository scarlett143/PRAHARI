"""Push delivery, presence, typing relay and receipts.

The server never decrypts, so these tests deliberately post opaque bytes as envelopes:
what is under test is the metadata plane -- who gets told what, and when -- not the AEAD,
which test_aead and test_api_flow already cover.
"""
import base64
import os
import uuid

import pytest

pytest.importorskip("aiosqlite")
pytest.importorskip("kyber_py")

from fastapi.testclient import TestClient

from app.main import app
from test_api_flow import register_verified
from test_collaboration import make_workspace, token_of


def opaque_envelope() -> str:
    """A byte string of legal envelope shape. The relay cannot tell it from a real one."""
    return base64.b64encode(os.urandom(64)).decode()


def linked_pair(client: TestClient, a_name: str, b_name: str):
    a_headers, alice, _ = register_verified(client, a_name)
    b_headers, bob, _ = register_verified(client, b_name)
    link = client.post("/api/v2/links", headers=a_headers, json={"username": b_name}).json()
    accepted = client.post(f"/api/v2/links/{link['id']}/accept", headers=b_headers).json()
    return a_headers, alice, b_headers, bob, accepted["channel_id"]


def send(client: TestClient, headers: dict, channel_id: str) -> dict:
    response = client.post(
        "/api/v2/messages",
        headers=headers,
        json={
            "client_message_id": str(uuid.uuid4()),
            "channel_id": channel_id,
            "key_epoch": 0,
            "envelope_b64": opaque_envelope(),
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_receipts_flow_from_recipient_back_to_sender():
    with TestClient(app) as client:
        a_headers, _, b_headers, _, channel_id = linked_pair(client, "rc_alice", "rc_bob")
        message = send(client, a_headers, channel_id)

        # Before acknowledgement the sender sees no receipt.
        history = client.get(f"/api/v2/channels/{channel_id}/messages", headers=a_headers).json()
        assert history[0]["receipt"] is None

        delivered = client.post(
            "/api/v2/messages/receipts",
            headers=b_headers,
            json={"channel_id": channel_id, "message_ids": [message["id"]], "state": "delivered"},
        )
        assert delivered.status_code == 200, delivered.text
        assert delivered.json()["updated"] == 1

        history = client.get(f"/api/v2/channels/{channel_id}/messages", headers=a_headers).json()
        assert history[0]["receipt"]["delivered_at"] is not None
        assert history[0]["receipt"]["read_at"] is None

        read = client.post(
            "/api/v2/messages/receipts",
            headers=b_headers,
            json={"channel_id": channel_id, "message_ids": [message["id"]], "state": "read"},
        )
        assert read.status_code == 200
        history = client.get(f"/api/v2/channels/{channel_id}/messages", headers=a_headers).json()
        assert history[0]["receipt"]["read_at"] is not None

        # The recipient's own view carries no receipt for someone else's message.
        peer_view = client.get(f"/api/v2/channels/{channel_id}/messages", headers=b_headers).json()
        assert peer_view[0]["receipt"] is None


def test_a_sender_cannot_forge_a_receipt_on_their_own_message():
    with TestClient(app) as client:
        a_headers, _, b_headers, _, channel_id = linked_pair(client, "fg_alice", "fg_bob")
        message = send(client, a_headers, channel_id)

        forged = client.post(
            "/api/v2/messages/receipts",
            headers=a_headers,
            json={"channel_id": channel_id, "message_ids": [message["id"]], "state": "read"},
        )
        assert forged.status_code == 200
        assert forged.json()["updated"] == 0

        history = client.get(f"/api/v2/channels/{channel_id}/messages", headers=a_headers).json()
        assert history[0]["receipt"] is None


def test_receipts_are_idempotent_and_never_move_backwards():
    with TestClient(app) as client:
        a_headers, _, b_headers, _, channel_id = linked_pair(client, "id_alice", "id_bob")
        message = send(client, a_headers, channel_id)
        payload = {"channel_id": channel_id, "message_ids": [message["id"]]}

        client.post("/api/v2/messages/receipts", headers=b_headers, json={**payload, "state": "read"})
        first = client.get(f"/api/v2/channels/{channel_id}/messages", headers=a_headers).json()[0]

        # A late "delivered" from another tab must not clear the read timestamp.
        repeat = client.post(
            "/api/v2/messages/receipts", headers=b_headers, json={**payload, "state": "delivered"}
        )
        assert repeat.json()["updated"] == 0
        second = client.get(f"/api/v2/channels/{channel_id}/messages", headers=a_headers).json()[0]
        assert second["receipt"]["read_at"] == first["receipt"]["read_at"]


def test_receipts_are_scoped_to_channel_membership():
    with TestClient(app) as client:
        a_headers, _, b_headers, _, channel_id = linked_pair(client, "sc_alice", "sc_bob")
        outsider_headers, _, _ = register_verified(client, "sc_outsider")
        message = send(client, a_headers, channel_id)

        blocked = client.post(
            "/api/v2/messages/receipts",
            headers=outsider_headers,
            json={"channel_id": channel_id, "message_ids": [message["id"]], "state": "read"},
        )
        assert blocked.status_code == 404


def test_presence_is_scoped_to_actual_peers():
    with TestClient(app) as client:
        a_headers, _, b_headers, bob, channel_id = linked_pair(client, "pr_alice", "pr_bob")
        stranger_headers, stranger, _ = register_verified(client, "pr_stranger")

        offline = client.get("/api/v2/users/presence", headers=a_headers).json()
        assert [peer["username"] for peer in offline["peers"]] == ["pr_bob"]
        assert offline["online"] == []

        # A user who shares no channel sees nobody at all.
        assert client.get("/api/v2/users/presence", headers=stranger_headers).json()["peers"] == []

        with client.websocket_connect(f"/ws?token={token_of(b_headers)}") as socket:
            assert socket.receive_json()["type"] == "connected"
            live = client.get("/api/v2/users/presence", headers=a_headers).json()
            assert live["online"] == [bob["id"]]
            # And the stranger still cannot observe bob's liveness.
            assert client.get("/api/v2/users/presence", headers=stranger_headers).json()["online"] == []

        assert client.get("/api/v2/users/presence", headers=a_headers).json()["online"] == []


def test_message_is_pushed_to_the_peer_socket_with_its_envelope():
    with TestClient(app) as client:
        a_headers, _, b_headers, _, channel_id = linked_pair(client, "ps_alice", "ps_bob")

        with client.websocket_connect(f"/ws?token={token_of(b_headers)}") as socket:
            assert socket.receive_json()["type"] == "connected"
            sent = send(client, a_headers, channel_id)

            frame = socket.receive_json()
            assert frame["type"] == "message.created"
            assert frame["channel_id"] == channel_id
            # The envelope rides the frame, so the client renders without a refetch.
            assert frame["message"]["envelope_b64"] == sent["envelope_b64"]
            assert frame["message"]["id"] == sent["id"]


def test_presence_change_is_announced_to_peers_only():
    with TestClient(app) as client:
        a_headers, _, b_headers, bob, _ = linked_pair(client, "pc_alice", "pc_bob")

        with client.websocket_connect(f"/ws?token={token_of(a_headers)}") as alice_socket:
            assert alice_socket.receive_json()["type"] == "connected"

            with client.websocket_connect(f"/ws?token={token_of(b_headers)}") as bob_socket:
                hello = bob_socket.receive_json()
                assert hello["type"] == "connected"
                # Bob learns alice was already online without waiting for an event.
                assert hello["online_peers"] != []

                announced = alice_socket.receive_json()
                assert announced["type"] == "presence.changed"
                assert announced["user_id"] == bob["id"]
                assert announced["online"] is True

        # The matching offline announcement is asserted in test_realtime_fanout rather
        # than here: TestClient tears the socket down from the client side, which races
        # the server's disconnect handler and makes the frame's arrival non-deterministic.
        # The manager-level test covers the transition without that race.


def test_typing_is_relayed_only_to_channel_members():
    with TestClient(app) as client:
        a_headers, alice, b_headers, _, channel_id = linked_pair(client, "ty_alice", "ty_bob")

        with client.websocket_connect(f"/ws?token={token_of(b_headers)}") as bob_socket:
            assert bob_socket.receive_json()["type"] == "connected"

            with client.websocket_connect(f"/ws?token={token_of(a_headers)}") as alice_socket:
                assert alice_socket.receive_json()["type"] == "connected"
                assert bob_socket.receive_json()["type"] == "presence.changed"

                alice_socket.send_json(
                    {"type": "typing", "channel_id": channel_id, "state": "start"}
                )
                frame = bob_socket.receive_json()
                assert frame["type"] == "typing"
                assert frame["username"] == "ty_alice"
                assert frame["state"] == "start"

                # A channel the sender is not in produces no relay at all.
                alice_socket.send_json(
                    {"type": "typing", "channel_id": str(uuid.uuid4()), "state": "start"}
                )
                alice_socket.send_json({"type": "ping"})


def test_receipt_acknowledgement_notifies_the_sender_socket():
    with TestClient(app) as client:
        a_headers, _, b_headers, bob, channel_id = linked_pair(client, "rn_alice", "rn_bob")
        message = send(client, a_headers, channel_id)

        with client.websocket_connect(f"/ws?token={token_of(a_headers)}") as alice_socket:
            assert alice_socket.receive_json()["type"] == "connected"

            client.post(
                "/api/v2/messages/receipts",
                headers=b_headers,
                json={"channel_id": channel_id, "message_ids": [message["id"]], "state": "read"},
            )
            frame = alice_socket.receive_json()
            assert frame["type"] == "message.receipts"
            assert frame["by"] == bob["id"]
            assert frame["receipts"][0]["message_id"] == message["id"]
            assert frame["receipts"][0]["read_at"] is not None
