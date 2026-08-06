"""Group channels: one epoch key, sealed separately to every member.

These exercise the property that makes a group work at all -- that three people who never
ran a pairwise handshake with each other all arrive at the *same* key, and that the relay
storing the sealed copies cannot read or retarget any of them.
"""
import pytest

pytest.importorskip("aiosqlite")
pytest.importorskip("kyber_py")

import os
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi.testclient import TestClient

from app.crypto import aead, hybrid
from app.main import app
from app.security import session_offer_signing_payload

from test_api_flow import b64, raw_x25519_private, register_verified

WRAP_NONCE_BYTES = 12


def wrap_aad(channel_id: str, epoch: int, responder_id: str) -> bytes:
    """Byte-for-byte the string groupSession.js binds a wrapped key to."""
    return f"prahari/group-key-wrap/v1|{channel_id}|{epoch}|{responder_id}".encode()


def seal(wrapping_key: bytes, group_key: bytes, channel_id: str, epoch: int, responder_id: str) -> bytes:
    nonce = os.urandom(WRAP_NONCE_BYTES)
    sealed = AESGCM(wrapping_key).encrypt(nonce, group_key, wrap_aad(channel_id, epoch, responder_id))
    return nonce + sealed


def unseal(wrapping_key: bytes, wrapped: bytes, channel_id: str, epoch: int, responder_id: str) -> bytes:
    nonce, sealed = wrapped[:WRAP_NONCE_BYTES], wrapped[WRAP_NONCE_BYTES:]
    return AESGCM(wrapping_key).decrypt(nonce, sealed, wrap_aad(channel_id, epoch, responder_id))


def public_bundle(keys) -> hybrid.HybridPublicBundle:
    return hybrid.HybridPublicBundle(keys["x_public"], keys["kem"].encapsulation_key)


def private_bundle(keys) -> hybrid.HybridPrivateBundle:
    return hybrid.HybridPrivateBundle(
        raw_x25519_private(keys["x_private"]), keys["kem"].decapsulation_key
    )


def build_offer(initiator_keys, channel_id: str, epoch: int, member_id: str, member_keys, group_key: bytes):
    """One member's sealed copy, signed by the initiator over its own recipient id."""
    ciphertext, wrapping_key = hybrid.initiate(public_bundle(member_keys))
    wrapped = seal(wrapping_key, group_key, channel_id, epoch, member_id)
    payload = session_offer_signing_payload(
        channel_id=channel_id,
        key_epoch=epoch,
        responder_id=member_id,
        x25519_ephemeral_public=ciphertext.x25519_ephemeral_public,
        ml_kem_ciphertext=ciphertext.ml_kem_ciphertext,
        wrapped_group_key=wrapped,
    )
    return {
        "responder_id": member_id,
        "x25519_ephemeral_public": b64(ciphertext.x25519_ephemeral_public),
        "ml_kem_ciphertext": b64(ciphertext.ml_kem_ciphertext),
        "offer_signature": b64(initiator_keys["ed_private"].sign(payload)),
        "wrapped_group_key": b64(wrapped),
    }


def make_group(client: TestClient, suffix: str):
    """Alice, Bob and Carol in one three-member channel."""
    alice_headers, alice, alice_keys = register_verified(client, f"alice_{suffix}")
    bob_headers, bob, bob_keys = register_verified(client, f"bob_{suffix}")
    carol_headers, carol, carol_keys = register_verified(client, f"carol_{suffix}")

    server = client.post(
        "/api/v2/servers", headers=alice_headers, json={"name": f"Group {suffix}"}
    ).json()
    for name in (f"bob_{suffix}", f"carol_{suffix}"):
        added = client.post(
            f"/api/v2/servers/{server['id']}/members",
            headers=alice_headers,
            json={"username": name},
        )
        assert added.status_code == 200, added.text

    created = client.post(
        "/api/v2/channels",
        headers=alice_headers,
        json={
            "server_id": server["id"],
            "name": "operations",
            "member_usernames": [f"bob_{suffix}", f"carol_{suffix}"],
        },
    )
    assert created.status_code == 200, created.text
    channel_id = created.json()["id"]

    people = {
        "alice": (alice_headers, alice, alice_keys),
        "bob": (bob_headers, bob, bob_keys),
        "carol": (carol_headers, carol, carol_keys),
    }
    return server, channel_id, people


def test_every_member_derives_the_same_group_key_and_can_read_the_channel():
    with TestClient(app) as client:
        server, channel_id, people = make_group(client, "grp")
        alice_headers, alice, alice_keys = people["alice"]
        bob_headers, bob, bob_keys = people["bob"]
        carol_headers, carol, carol_keys = people["carol"]

        channel = client.get(f"/api/v2/channels/{channel_id}", headers=carol_headers).json()
        assert channel["group"] is True
        assert len(channel["members"]) == 3
        # Deterministic, so every client agrees who seals without another round trip.
        assert channel["session_initiator_id"] == alice["id"]

        group_key = os.urandom(32)
        offers = [
            build_offer(alice_keys, channel_id, 0, alice["id"], alice_keys, group_key),
            build_offer(alice_keys, channel_id, 0, bob["id"], bob_keys, group_key),
            build_offer(alice_keys, channel_id, 0, carol["id"], carol_keys, group_key),
        ]
        posted = client.post(
            "/api/v2/sessions/offers/batch",
            headers=alice_headers,
            json={"channel_id": channel_id, "key_epoch": 0, "offers": offers},
        )
        assert posted.status_code == 200, posted.text
        assert len(posted.json()["offers"]) == 3

        # Each member fetches only their own copy and must reach the identical key.
        for headers, person, keys in (
            (bob_headers, bob, bob_keys),
            (carol_headers, carol, carol_keys),
            (alice_headers, alice, alice_keys),
        ):
            offer = client.get(
                f"/api/v2/sessions/offers/{channel_id}?epoch=0", headers=headers
            )
            assert offer.status_code == 200, offer.text
            body = offer.json()
            assert body["responder_id"] == person["id"]

            import base64

            ciphertext = hybrid.HybridCiphertext(
                base64.b64decode(body["x25519_ephemeral_public"]),
                base64.b64decode(body["ml_kem_ciphertext"]),
            )
            wrapping_key = hybrid.respond(private_bundle(keys), public_bundle(keys), ciphertext)
            recovered = unseal(
                wrapping_key,
                base64.b64decode(body["wrapped_group_key"]),
                channel_id,
                0,
                person["id"],
            )
            assert recovered == group_key

        # Bob writes with the shared key; Carol, who never handshook with Bob, reads it.
        plaintext = b"all stations, this is a group broadcast"
        aad = aead.build_aad(sender_id=bob["id"], channel_id=channel_id, epoch=0)
        envelope = aead.encrypt(group_key, plaintext, aad).to_wire()
        assert plaintext not in envelope

        sent = client.post(
            "/api/v2/messages",
            headers=bob_headers,
            json={
                "client_message_id": str(uuid.uuid4()),
                "channel_id": channel_id,
                "key_epoch": 0,
                "envelope_b64": b64(envelope),
            },
        )
        assert sent.status_code == 200, sent.text

        rows = client.get(f"/api/v2/channels/{channel_id}/messages", headers=carol_headers).json()
        assert len(rows) == 1
        import base64 as b64mod

        stored = aead.Envelope.from_wire(b64mod.b64decode(rows[0]["envelope_b64"]))
        assert aead.decrypt(group_key, stored, aad) == plaintext


def test_batch_must_cover_every_member():
    """A partial batch would leave someone silently unable to read the channel."""
    with TestClient(app) as client:
        server, channel_id, people = make_group(client, "partial")
        alice_headers, alice, alice_keys = people["alice"]
        _, bob, bob_keys = people["bob"]

        group_key = os.urandom(32)
        response = client.post(
            "/api/v2/sessions/offers/batch",
            headers=alice_headers,
            json={
                "channel_id": channel_id,
                "key_epoch": 0,
                # Carol omitted.
                "offers": [
                    build_offer(alice_keys, channel_id, 0, alice["id"], alice_keys, group_key),
                    build_offer(alice_keys, channel_id, 0, bob["id"], bob_keys, group_key),
                ],
            },
        )
        assert response.status_code == 400
        assert "exactly the other channel members" in response.text


def test_forged_offer_signature_is_rejected():
    with TestClient(app) as client:
        server, channel_id, people = make_group(client, "forged")
        alice_headers, alice, alice_keys = people["alice"]
        _, bob, bob_keys = people["bob"]
        _, carol, carol_keys = people["carol"]

        group_key = os.urandom(32)
        offers = [
            build_offer(alice_keys, channel_id, 0, alice["id"], alice_keys, group_key),
            build_offer(alice_keys, channel_id, 0, bob["id"], bob_keys, group_key),
            build_offer(alice_keys, channel_id, 0, carol["id"], carol_keys, group_key),
        ]
        offers[1]["offer_signature"] = b64(b"x" * 64)

        response = client.post(
            "/api/v2/sessions/offers/batch",
            headers=alice_headers,
            json={"channel_id": channel_id, "key_epoch": 0, "offers": offers},
        )
        assert response.status_code == 400
        assert "signature failed" in response.text


def test_wrapped_key_is_bound_to_its_recipient():
    """Bob must not be able to open the copy sealed for Carol.

    This is the property that stops the relay from handing everyone the same blob and
    stops one member from claiming another's slot.
    """
    with TestClient(app) as client:
        server, channel_id, people = make_group(client, "bound")
        _, bob, bob_keys = people["bob"]
        _, carol, carol_keys = people["carol"]
        _, alice, alice_keys = people["alice"]

        group_key = os.urandom(32)
        ciphertext, wrapping_key = hybrid.initiate(public_bundle(carol_keys))
        sealed_for_carol = seal(wrapping_key, group_key, channel_id, 0, carol["id"])

        # Carol's own key material opens it; the same bytes under Bob's id do not.
        assert unseal(wrapping_key, sealed_for_carol, channel_id, 0, carol["id"]) == group_key
        with pytest.raises(Exception):
            unseal(wrapping_key, sealed_for_carol, channel_id, 0, bob["id"])


def test_two_party_channels_still_use_the_ratchet_path():
    """Groups must not quietly change how a DM is encrypted."""
    with TestClient(app) as client:
        alice_headers, alice, _ = register_verified(client, "alice_dm")
        bob_headers, bob, _ = register_verified(client, "bob_dm")

        server = client.post(
            "/api/v2/servers", headers=alice_headers, json={"name": "DM"}
        ).json()
        client.post(
            f"/api/v2/servers/{server['id']}/members",
            headers=alice_headers,
            json={"username": "bob_dm"},
        )
        channel_id = server["channels"][0]["id"]

        channel = client.get(f"/api/v2/channels/{channel_id}", headers=bob_headers).json()
        assert channel["group"] is False
        assert len(channel["members"]) == 2

        # The batch endpoint refuses a two-party channel outright.
        refused = client.post(
            "/api/v2/sessions/offers/batch",
            headers=alice_headers,
            json={"channel_id": channel_id, "key_epoch": 0, "offers": []},
        )
        assert refused.status_code == 409
        assert "ratchet" in refused.text


def test_adding_a_member_rotates_the_epoch():
    """A new arrival holds no copy of the current key, so membership change must re-key."""
    with TestClient(app) as client:
        server, channel_id, people = make_group(client, "grow")
        alice_headers, alice, _ = people["alice"]
        _, _, _ = register_verified(client, "dave_grow")

        before = client.get(f"/api/v2/channels/{channel_id}", headers=alice_headers).json()
        assert before["key_epoch"] == 0

        added = client.post(
            f"/api/v2/channels/{channel_id}/members",
            headers=alice_headers,
            json={"username": "dave_grow"},
        )
        assert added.status_code == 200, added.text
        assert added.json()["key_epoch"] == 1

        after = client.get(f"/api/v2/channels/{channel_id}", headers=alice_headers).json()
        assert after["key_epoch"] == 1
        assert len(after["members"]) == 4
