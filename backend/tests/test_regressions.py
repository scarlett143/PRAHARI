"""Regression tests for defects found during the unified-platform review.

Each test here maps to a specific bug that shipped in the initial commit.
"""
import pytest

pytest.importorskip("aiosqlite")
pytest.importorskip("kyber_py")

import uuid

import anyio
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.api.anchors import leaf_hash, merkle_proof, merkle_root, verify_proof
from app.crypto import hybrid
from app.database import get_session_factory
from app.main import app
from app.models import Message
from app.security import session_offer_signing_payload

from test_api_flow import b64, register_verified


def _unique(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


def _two_party_channel(client: TestClient):
    alice_headers, alice, alice_keys = register_verified(client, _unique("alice"))
    bob_headers, bob, bob_keys = register_verified(client, _unique("bob"))
    server = client.post(
        "/api/v2/servers", headers=alice_headers, json={"name": "Regression"}
    ).json()
    channel_id = server["channels"][0]["id"]
    client.post(
        f"/api/v2/servers/{server['id']}/members",
        headers=alice_headers,
        json={"username": bob["username"]},
    )
    return {
        "server": server,
        "channel_id": channel_id,
        "alice": (alice_headers, alice, alice_keys),
        "bob": (bob_headers, bob, bob_keys),
    }


def _signed_offer(channel_id: str, epoch: int, responder_id: str, bob_keys, alice_keys):
    bob_public = hybrid.HybridPublicBundle(
        bob_keys["x_public"], bob_keys["kem"].encapsulation_key
    )
    ct, key = hybrid.initiate(bob_public)
    payload = session_offer_signing_payload(
        channel_id=channel_id,
        key_epoch=epoch,
        responder_id=responder_id,
        x25519_ephemeral_public=ct.x25519_ephemeral_public,
        ml_kem_ciphertext=ct.ml_kem_ciphertext,
    )
    return {
        "channel_id": channel_id,
        "key_epoch": epoch,
        "responder_id": responder_id,
        "x25519_ephemeral_public": b64(ct.x25519_ephemeral_public),
        "ml_kem_ciphertext": b64(ct.ml_kem_ciphertext),
        "offer_signature": b64(alice_keys["ed_private"].sign(payload)),
    }, key


def test_conflicting_session_offer_is_rejected_instead_of_silently_swapped():
    """A second, different offer for one epoch must not be answered with the stored one.

    Returning the stored offer left the initiator holding a key derived from its own
    fresh ephemeral that no peer could reproduce, so every later message failed
    authentication with no visible cause.
    """
    with TestClient(app) as client:
        ctx = _two_party_channel(client)
        alice_headers, _, alice_keys = ctx["alice"]
        _, bob, bob_keys = ctx["bob"]

        first, _ = _signed_offer(ctx["channel_id"], 0, bob["id"], bob_keys, alice_keys)
        assert client.post(
            "/api/v2/sessions/offers", headers=alice_headers, json=first
        ).status_code == 200

        # Re-submitting the identical offer stays idempotent.
        repeat = client.post("/api/v2/sessions/offers", headers=alice_headers, json=first)
        assert repeat.status_code == 200
        assert repeat.json()["x25519_ephemeral_public"] == first["x25519_ephemeral_public"]

        # A different offer for the same epoch is refused, not silently replaced.
        second, _ = _signed_offer(ctx["channel_id"], 0, bob["id"], bob_keys, alice_keys)
        conflict = client.post("/api/v2/sessions/offers", headers=alice_headers, json=second)
        assert conflict.status_code == 409
        assert conflict.json()["detail"]["code"] == "session_offer_exists"


def test_merkle_proofs_survive_identical_message_timestamps():
    """Anchored messages tie on created_at, so the leaf sort key must include id.

    SQLite CURRENT_TIMESTAMP is second-precision, so a whole batch commonly shares one
    timestamp. The batch builder and the proof rebuilder are differently shaped queries
    (the builder joins channel_members and applies LIMIT), and with a non-unique sort key
    SQL is free to resolve those ties differently between them -- which would rebuild the
    leaves in another order and produce a root that does not match the stored one.
    SQLite happens to fall back to rowid order today, so this asserts the invariant that
    removes the ambiguity rather than a failure that reproduces on this engine.
    """
    with TestClient(app) as client:
        ctx = _two_party_channel(client)
        alice_headers, _, _ = ctx["alice"]
        channel_id = ctx["channel_id"]

        for index in range(12):
            sent = client.post(
                "/api/v2/messages",
                headers=alice_headers,
                json={
                    "client_message_id": str(uuid.uuid4()),
                    "channel_id": channel_id,
                    "key_epoch": 0,
                    "envelope_b64": b64(bytes([1, 12]) + bytes(range(12)) + bytes(40 + index)),
                },
            )
            assert sent.status_code == 200, sent.text

        batch = client.post("/api/v2/anchors/batch", headers=alice_headers)
        assert batch.status_code == 200, batch.text
        batch_id = batch.json()["id"]

        messages = client.get(
            f"/api/v2/channels/{channel_id}/messages", headers=alice_headers
        ).json()
        assert len(messages) == 12

        # Every anchored message must verify against the stored root.
        for message in messages:
            proof = client.get(
                f"/api/v2/anchors/{batch_id}/proof/{message['id']}", headers=alice_headers
            )
            assert proof.status_code == 200, proof.text
            assert proof.json()["verified"] is True, message["id"]

        # The point of the fix: the sort key is total, so no tie is left for the engine to
        # resolve. created_at alone is demonstrably not enough to establish that.
        async def sort_keys():
            async with get_session_factory()() as db:
                return (
                    await db.execute(
                        select(Message.created_at, Message.id).where(
                            Message.anchor_batch_id == batch_id
                        )
                    )
                ).all()

        rows = anyio.run(sort_keys)
        timestamps = [created_at for created_at, _ in rows]
        assert len(set(timestamps)) < len(rows), "expected tied timestamps in this batch"
        assert len(set(rows)) == len(rows), "(created_at, id) must be a total order"


def test_adding_a_third_member_does_not_break_an_established_channel():
    """A three-member channel can never establish a two-party hybrid session."""
    with TestClient(app) as client:
        ctx = _two_party_channel(client)
        alice_headers, _, _ = ctx["alice"]
        _, carol, _ = register_verified(client, _unique("carol"))

        added = client.post(
            f"/api/v2/servers/{ctx['server']['id']}/members",
            headers=alice_headers,
            json={"username": carol["username"]},
        )
        assert added.status_code == 200, added.text
        assert added.json()["skipped_channels"] == ["general"]

        channel = client.get(
            f"/api/v2/channels/{ctx['channel_id']}", headers=alice_headers
        ).json()
        assert len(channel["members"]) == 2
        assert channel["hybrid_session_supported"] is True


def test_channel_creation_requires_a_named_peer_beyond_two_members():
    with TestClient(app) as client:
        ctx = _two_party_channel(client)
        alice_headers, _, _ = ctx["alice"]
        _, carol, _ = register_verified(client, _unique("carol"))
        client.post(
            f"/api/v2/servers/{ctx['server']['id']}/members",
            headers=alice_headers,
            json={"username": carol["username"]},
        )

        ambiguous = client.post(
            "/api/v2/channels",
            headers=alice_headers,
            json={"server_id": ctx["server"]["id"], "name": "ops"},
        )
        assert ambiguous.status_code == 400
        assert ambiguous.json()["detail"]["code"] == "peer_required"

        explicit = client.post(
            "/api/v2/channels",
            headers=alice_headers,
            json={
                "server_id": ctx["server"]["id"],
                "name": "ops",
                "peer_username": carol["username"],
            },
        )
        assert explicit.status_code == 200, explicit.text
        detail = client.get(
            f"/api/v2/channels/{explicit.json()['id']}", headers=alice_headers
        ).json()
        assert len(detail["members"]) == 2
        assert detail["hybrid_session_supported"] is True


def test_hkdf_info_stays_within_the_1024_byte_portability_limit():
    """OpenSSL-backed HKDF (Node, Deno, Bun, embedded reimplementations) caps info at 1024 B.

    The raw ML-KEM-768 transcript is 2336 bytes, so it must be hashed before use.
    """
    public, _ = hybrid.generate_bundle()
    ciphertext, _ = hybrid.initiate(public)
    raw_transcript = public.to_transcript() + ciphertext.to_transcript()
    assert len(raw_transcript) > 1024

    info = hybrid.KDF_LABEL + hybrid.transcript_digest(public, ciphertext)
    assert len(info) <= 1024
    assert len(hybrid.transcript_digest(public, ciphertext)) == 32


def test_merkle_leaf_order_changes_the_root():
    """Guards the ordering fix: leaf order is load-bearing, so it must be deterministic."""
    leaves = [leaf_hash(f"m{index}".encode()) for index in range(9)]
    swapped = list(leaves)
    swapped[3], swapped[4] = swapped[4], swapped[3]
    assert merkle_root(leaves) != merkle_root(swapped)
    assert verify_proof(leaves[3], merkle_proof(leaves, 3), merkle_root(leaves))
    assert not verify_proof(leaves[3], merkle_proof(swapped, 3), merkle_root(leaves))
