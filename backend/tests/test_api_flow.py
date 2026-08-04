import pytest
pytest.importorskip("aiosqlite")
pytest.importorskip("kyber_py")

import base64
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from fastapi.testclient import TestClient

from app.crypto import aead, hybrid, pqc
from app.main import app
from app.security import bundle_signing_payload, session_offer_signing_payload


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode()


def raw_x25519_private(key: X25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def register_verified(client: TestClient, username: str):
    ed_private = Ed25519PrivateKey.generate()
    ed_public = ed_private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    response = client.post(
        "/api/v2/auth/register",
        json={
            "username": username,
            "password": "correct-horse-battery-staple",
            "ed25519_public_key": b64(ed_public),
        },
    )
    assert response.status_code == 200, response.text
    token = response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    challenge = client.post("/api/v2/auth/challenge", headers=headers).json()["challenge"]

    x_private = X25519PrivateKey.generate()
    x_public = x_private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    kem = pqc.get_backend().keygen()
    bundle_payload = bundle_signing_payload(
        x25519_public_key=x_public,
        ml_kem_encapsulation_key=kem.encapsulation_key,
    )
    publish = client.post(
        "/api/v2/keys/publish",
        headers=headers,
        json={
            "x25519_public_key": b64(x_public),
            "ml_kem_encapsulation_key": b64(kem.encapsulation_key),
            "challenge_signature": b64(ed_private.sign(challenge.encode())),
            "bundle_signature": b64(ed_private.sign(bundle_payload)),
        },
    )
    assert publish.status_code == 200, publish.text
    me = client.get("/api/v2/auth/me", headers=headers).json()
    return headers, me, {
        "ed_private": ed_private,
        "x_private": x_private,
        "x_public": x_public,
        "kem": kem,
    }


def test_two_user_real_hybrid_ciphertext_flow_and_epoch_rejection():
    with TestClient(app) as client:
        alice_headers, alice, alice_keys = register_verified(client, "alice_api")
        bob_headers, bob, bob_keys = register_verified(client, "bob_api")

        server_response = client.post(
            "/api/v2/servers", headers=alice_headers, json={"name": "Demo"}
        )
        assert server_response.status_code == 200, server_response.text
        server = server_response.json()
        channel_id = server["channels"][0]["id"]

        added = client.post(
            f"/api/v2/servers/{server['id']}/members",
            headers=alice_headers,
            json={"username": "bob_api"},
        )
        assert added.status_code == 200, added.text

        channel_response = client.get(f"/api/v2/channels/{channel_id}", headers=bob_headers)
        assert channel_response.status_code == 200
        channel = channel_response.json()
        assert len(channel["members"]) == 2
        assert channel["session_initiator_id"] == alice["id"]

        # Alice establishes the public hybrid offer to Bob and derives her key.
        bob_public = hybrid.HybridPublicBundle(
            bob_keys["x_public"], bob_keys["kem"].encapsulation_key
        )
        hybrid_ct, alice_session_key = hybrid.initiate(bob_public)
        offer_payload = session_offer_signing_payload(
            channel_id=channel_id,
            key_epoch=0,
            responder_id=bob["id"],
            x25519_ephemeral_public=hybrid_ct.x25519_ephemeral_public,
            ml_kem_ciphertext=hybrid_ct.ml_kem_ciphertext,
        )

        # A forged identity signature is rejected before the valid offer is accepted.
        forged = client.post(
            "/api/v2/sessions/offers",
            headers=alice_headers,
            json={
                "channel_id": channel_id,
                "key_epoch": 0,
                "responder_id": bob["id"],
                "x25519_ephemeral_public": b64(hybrid_ct.x25519_ephemeral_public),
                "ml_kem_ciphertext": b64(hybrid_ct.ml_kem_ciphertext),
                "offer_signature": b64(b"x" * 64),
            },
        )
        assert forged.status_code == 400

        posted_offer = client.post(
            "/api/v2/sessions/offers",
            headers=alice_headers,
            json={
                "channel_id": channel_id,
                "key_epoch": 0,
                "responder_id": bob["id"],
                "x25519_ephemeral_public": b64(hybrid_ct.x25519_ephemeral_public),
                "ml_kem_ciphertext": b64(hybrid_ct.ml_kem_ciphertext),
                "offer_signature": b64(alice_keys["ed_private"].sign(offer_payload)),
            },
        )
        assert posted_offer.status_code == 200, posted_offer.text

        fetched_offer = client.get(
            f"/api/v2/sessions/offers/{channel_id}?epoch=0", headers=bob_headers
        )
        assert fetched_offer.status_code == 200

        # Bob decapsulates the same public offer and must derive the identical key.
        bob_private = hybrid.HybridPrivateBundle(
            raw_x25519_private(bob_keys["x_private"]),
            bob_keys["kem"].decapsulation_key,
        )
        bob_session_key = hybrid.respond(bob_private, bob_public, hybrid_ct)
        assert bob_session_key == alice_session_key

        plaintext = b"Post-quantum encrypted hello!"
        aad = aead.build_aad(sender_id=alice["id"], channel_id=channel_id, epoch=0)
        envelope = aead.encrypt(alice_session_key, plaintext, aad).to_wire()
        assert plaintext not in envelope

        client_message_id = str(uuid.uuid4())
        sent = client.post(
            "/api/v2/messages",
            headers=alice_headers,
            json={
                "client_message_id": client_message_id,
                "channel_id": channel_id,
                "key_epoch": 0,
                "envelope_b64": b64(envelope),
            },
        )
        assert sent.status_code == 200, sent.text
        assert "plaintext" not in sent.text.lower()

        duplicate = client.post(
            "/api/v2/messages",
            headers=alice_headers,
            json={
                "client_message_id": client_message_id,
                "channel_id": channel_id,
                "key_epoch": 0,
                "envelope_b64": b64(envelope),
            },
        )
        assert duplicate.status_code == 409

        wrong_epoch = client.post(
            "/api/v2/messages",
            headers=alice_headers,
            json={
                "client_message_id": str(uuid.uuid4()),
                "channel_id": channel_id,
                "key_epoch": 1,
                "envelope_b64": b64(envelope),
            },
        )
        assert wrong_epoch.status_code == 409

        listed = client.get(
            f"/api/v2/channels/{channel_id}/messages", headers=bob_headers
        ).json()
        assert len(listed) == 1
        stored_wire = base64.b64decode(listed[0]["envelope_b64"])
        opened = aead.decrypt(
            bob_session_key,
            aead.Envelope.from_wire(stored_wire),
            aead.build_aad(sender_id=alice["id"], channel_id=channel_id, epoch=0),
        )
        assert opened == plaintext
