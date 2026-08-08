"""The key transparency log.

The property under test is narrow and worth stating exactly: a relay cannot change its
answer about someone's key history without the record disagreeing with it. It is not that
the relay cannot lie -- it can decline to show you a row, and on first contact there is
nothing to compare against at all. What it can no longer do is substitute a key and have
the history look as though that key was always there.
"""
import pytest

pytest.importorskip("aiosqlite")
pytest.importorskip("kyber_py")

import anyio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.crypto import pqc
from app.database import get_session_factory
from app.main import app
from app.models import KeyBundleRecord
from app.security import bundle_signing_payload
from app.transparency import entry_hash, verify_chain

from test_api_flow import b64, register_verified
from test_fleet import _unique


def _republish(client: TestClient, headers, ed_private):
    """Publish a fresh X25519 + ML-KEM bundle under the same identity key."""
    challenge = client.post("/api/v2/auth/challenge", headers=headers).json()["challenge"]
    x_private = X25519PrivateKey.generate()
    x_public = x_private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    kem = pqc.get_backend().keygen()
    response = client.post(
        "/api/v2/keys/publish",
        headers=headers,
        json={
            "x25519_public_key": b64(x_public),
            "ml_kem_encapsulation_key": b64(kem.encapsulation_key),
            "challenge_signature": b64(ed_private.sign(challenge.encode())),
            "bundle_signature": b64(
                ed_private.sign(
                    bundle_signing_payload(
                        x25519_public_key=x_public,
                        ml_kem_encapsulation_key=kem.encapsulation_key,
                    )
                )
            ),
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_every_publish_appends_a_linked_entry():
    with TestClient(app) as client:
        username = _unique("alice")
        headers, _, keys = register_verified(client, username)

        first = client.get(f"/api/v2/keys/{username}/history", headers=headers).json()
        assert first["chain_ok"] is True
        assert len(first["entries"]) == 1
        assert first["entries"][0]["seq"] == 1
        assert first["entries"][0]["prev_hash"] is None, "the first entry links to nothing"

        _republish(client, headers, keys["ed_private"])
        second = client.get(f"/api/v2/keys/{username}/history", headers=headers).json()

        assert second["chain_ok"] is True
        assert len(second["entries"]) == 2
        assert second["entries"][1]["prev_hash"] == second["entries"][0]["entry_hash"], (
            "each entry must commit to the one before it"
        )


def test_republishing_an_unchanged_bundle_does_not_grow_the_chain():
    """A history where most rows mean 'nothing happened' is one nobody reads closely."""
    with TestClient(app) as client:
        username = _unique("alice")
        headers, _, keys = register_verified(client, username)

        # Re-publish byte-identical keys: request a fresh challenge, sign the same bundle.
        challenge = client.post("/api/v2/auth/challenge", headers=headers).json()["challenge"]
        x_public = keys["x_public"]
        kem = keys["kem"]
        again = client.post(
            "/api/v2/keys/publish",
            headers=headers,
            json={
                "x25519_public_key": b64(x_public),
                "ml_kem_encapsulation_key": b64(kem.encapsulation_key),
                "challenge_signature": b64(keys["ed_private"].sign(challenge.encode())),
                "bundle_signature": b64(
                    keys["ed_private"].sign(
                        bundle_signing_payload(
                            x25519_public_key=x_public,
                            ml_kem_encapsulation_key=kem.encapsulation_key,
                        )
                    )
                ),
            },
        )
        assert again.status_code == 200, again.text
        assert again.json()["transparency"]["seq"] == 1, "an unchanged bundle is not a new entry"

        history = client.get(f"/api/v2/keys/{username}/history", headers=headers).json()
        assert len(history["entries"]) == 1


def test_the_current_bundle_reports_where_it_sits_in_the_history():
    with TestClient(app) as client:
        username = _unique("alice")
        headers, _, keys = register_verified(client, username)
        _republish(client, headers, keys["ed_private"])

        bundle = client.get(f"/api/v2/keys/{username}", headers=headers).json()
        history = client.get(f"/api/v2/keys/{username}/history", headers=headers).json()

        assert bundle["transparency_seq"] == 2, "a caller can tell a second key from a first"
        assert bundle["transparency_hash"] == history["entries"][-1]["entry_hash"]
        assert bundle["x25519_public_key"] == history["entries"][-1]["x25519_public_key"]


def test_editing_a_past_entry_breaks_every_hash_after_it():
    with TestClient(app) as client:
        username = _unique("alice")
        headers, _, keys = register_verified(client, username)
        _republish(client, headers, keys["ed_private"])
        _republish(client, headers, keys["ed_private"])

        user_id = client.get("/api/v2/auth/me", headers=headers).json()["id"]

        async def tamper():
            async with get_session_factory()() as session:
                rows = (
                    await session.execute(
                        select(KeyBundleRecord)
                        .where(KeyBundleRecord.user_id == user_id)
                        .order_by(KeyBundleRecord.seq.asc())
                    )
                ).scalars().all()
                # Swap the middle entry's key for one the relay prefers, exactly as a
                # hostile or compromised server would.
                rows[1].x25519_public_key = bytes(32)
                await session.commit()

        anyio.run(tamper)

        after = client.get(f"/api/v2/keys/{username}/history", headers=headers).json()
        assert after["chain_ok"] is False
        assert "altered" in after["chain_error"]


def test_removing_an_entry_is_detected():
    with TestClient(app) as client:
        username = _unique("alice")
        headers, _, keys = register_verified(client, username)
        _republish(client, headers, keys["ed_private"])
        _republish(client, headers, keys["ed_private"])

        user_id = client.get("/api/v2/auth/me", headers=headers).json()["id"]

        async def drop_middle():
            async with get_session_factory()() as session:
                rows = (
                    await session.execute(
                        select(KeyBundleRecord)
                        .where(KeyBundleRecord.user_id == user_id)
                        .order_by(KeyBundleRecord.seq.asc())
                    )
                ).scalars().all()
                await session.delete(rows[1])
                await session.commit()

        anyio.run(drop_middle)

        after = client.get(f"/api/v2/keys/{username}/history", headers=headers).json()
        assert after["chain_ok"] is False, "a hole in the sequence must not validate"


def test_one_users_chain_is_independent_of_another():
    """Chained per user on purpose: two people publishing at once must not contend."""
    with TestClient(app) as client:
        alice = _unique("alice")
        bob = _unique("bob")
        alice_headers, _, alice_keys = register_verified(client, alice)
        bob_headers, _, _ = register_verified(client, bob)

        _republish(client, alice_headers, alice_keys["ed_private"])

        bob_history = client.get(f"/api/v2/keys/{bob}/history", headers=bob_headers).json()
        assert bob_history["chain_ok"] is True
        assert len(bob_history["entries"]) == 1
        assert bob_history["entries"][0]["seq"] == 1, "Bob's sequence is his own, not global"


def test_the_hash_binds_field_boundaries():
    """Two different bundles must not hash the same because their bytes concatenate alike."""
    common = dict(prev_hash=None, user_id="u1", seq=1)
    left = entry_hash(
        **common,
        ed25519_public_key=b"AABB",
        x25519_public_key=b"CC",
        ml_kem_encapsulation_key=b"DD",
    )
    right = entry_hash(
        **common,
        ed25519_public_key=b"AA",
        x25519_public_key=b"BBCC",
        ml_kem_encapsulation_key=b"DD",
    )
    assert left != right


def test_verify_chain_rejects_a_resequenced_log():
    class Row:
        def __init__(self, seq, prev_hash, entry_hash_value):
            self.seq = seq
            self.prev_hash = prev_hash
            self.entry_hash = entry_hash_value
            self.user_id = "u1"
            self.ed25519_public_key = b"\x01" * 32
            self.x25519_public_key = b"\x02" * 32
            self.ml_kem_encapsulation_key = b"\x03" * 32

    first_hash = entry_hash(
        prev_hash=None,
        user_id="u1",
        seq=1,
        ed25519_public_key=b"\x01" * 32,
        x25519_public_key=b"\x02" * 32,
        ml_kem_encapsulation_key=b"\x03" * 32,
    )
    # A log that starts at 2 is a log with its first entry removed.
    ok, reason = verify_chain([Row(2, None, first_hash)])
    assert ok is False
    assert "sequence" in reason
