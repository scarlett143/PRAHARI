"""Fleet provisioning, enrolment, and the GCS <-> UAV encrypted link.

The point of these tests is parity: an aircraft must reach an identical session key
through an identical protocol to a human peer, with the server holding only ciphertext.
"""
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

from test_api_flow import b64, raw_x25519_private, register_verified


def _unique(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


def enroll_aircraft(client: TestClient, callsign: str, enrollment_token: str):
    """Everything the on-aircraft agent does: keygen, enrol, publish a signed bundle."""
    ed_private = Ed25519PrivateKey.generate()
    ed_public = ed_private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    enrolled = client.post(
        "/api/v2/fleet/enroll",
        json={
            "callsign": callsign,
            "enrollment_token": enrollment_token,
            "ed25519_public_key": b64(ed_public),
        },
    )
    assert enrolled.status_code == 200, enrolled.text
    headers = {"Authorization": f"Bearer {enrolled.json()['access_token']}"}

    challenge = client.post("/api/v2/auth/challenge", headers=headers).json()["challenge"]
    x_private = X25519PrivateKey.generate()
    x_public = x_private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    kem = pqc.get_backend().keygen()
    published = client.post(
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
    assert published.status_code == 200, published.text
    return headers, enrolled.json(), {
        "ed_private": ed_private,
        "x_private": x_private,
        "x_public": x_public,
        "kem": kem,
    }


def test_uav_link_uses_the_same_hybrid_session_as_a_human_peer():
    with TestClient(app) as client:
        operator_headers, operator, operator_keys = register_verified(client, _unique("gcs"))
        callsign = _unique("UAV")

        provisioned = client.post(
            "/api/v2/fleet/uavs",
            headers=operator_headers,
            json={"callsign": callsign, "airframe": "quad-x", "fleet": "alpha"},
        )
        assert provisioned.status_code == 200, provisioned.text
        token = provisioned.json()["enrollment_token"]
        assert provisioned.json()["status"] == "pending_enrollment"

        uav_headers, uav, uav_keys = enroll_aircraft(client, callsign, token)

        # The enrolment token is single use.
        replay = client.post(
            "/api/v2/fleet/enroll",
            json={
                "callsign": callsign,
                "enrollment_token": token,
                "ed25519_public_key": b64(bytes(range(32))),
            },
        )
        assert replay.status_code == 401

        link = client.post(f"/api/v2/fleet/uavs/{callsign}/link", headers=operator_headers)
        assert link.status_code == 200, link.text
        channel_id = link.json()["channel_id"]
        assert link.json()["created"] is True

        # Re-linking is idempotent.
        again = client.post(f"/api/v2/fleet/uavs/{callsign}/link", headers=operator_headers)
        assert again.json()["channel_id"] == channel_id
        assert again.json()["created"] is False

        channel = client.get(f"/api/v2/channels/{channel_id}", headers=operator_headers).json()
        assert channel["hybrid_session_supported"] is True
        assert len(channel["members"]) == 2
        assert {member["kind"] for member in channel["members"]} == {"human", "uav"}

        # Whichever side sorts first is the deterministic initiator -- identical rule to
        # a human-to-human channel, with no special case for the aircraft.
        initiator_is_uav = channel["session_initiator_id"] == uav["user_id"]
        if initiator_is_uav:
            initiator_headers, initiator_keys = uav_headers, uav_keys
            responder_id, responder_keys = operator["id"], operator_keys
        else:
            initiator_headers, initiator_keys = operator_headers, operator_keys
            responder_id, responder_keys = uav["user_id"], uav_keys

        responder_public = hybrid.HybridPublicBundle(
            responder_keys["x_public"], responder_keys["kem"].encapsulation_key
        )
        ciphertext, initiator_key = hybrid.initiate(responder_public)
        offer_payload = session_offer_signing_payload(
            channel_id=channel_id,
            key_epoch=0,
            responder_id=responder_id,
            x25519_ephemeral_public=ciphertext.x25519_ephemeral_public,
            ml_kem_ciphertext=ciphertext.ml_kem_ciphertext,
        )
        posted = client.post(
            "/api/v2/sessions/offers",
            headers=initiator_headers,
            json={
                "channel_id": channel_id,
                "key_epoch": 0,
                "responder_id": responder_id,
                "x25519_ephemeral_public": b64(ciphertext.x25519_ephemeral_public),
                "ml_kem_ciphertext": b64(ciphertext.ml_kem_ciphertext),
                "offer_signature": b64(initiator_keys["ed_private"].sign(offer_payload)),
            },
        )
        assert posted.status_code == 200, posted.text

        responder_key = hybrid.respond(
            hybrid.HybridPrivateBundle(
                raw_x25519_private(responder_keys["x_private"]),
                responder_keys["kem"].decapsulation_key,
            ),
            responder_public,
            ciphertext,
        )
        assert responder_key == initiator_key

        # A MAVLink frame travels as an ordinary opaque envelope.
        mavlink_frame = bytes([0xFD, 0x09, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00])
        sender_id = uav["user_id"] if initiator_is_uav else operator["id"]
        aad = aead.build_aad(sender_id=sender_id, channel_id=channel_id, epoch=0)
        envelope = aead.encrypt(initiator_key, mavlink_frame, aad).to_wire()
        assert mavlink_frame not in envelope

        sent = client.post(
            "/api/v2/messages",
            headers=initiator_headers,
            json={
                "client_message_id": str(uuid.uuid4()),
                "channel_id": channel_id,
                "key_epoch": 0,
                "envelope_b64": b64(envelope),
            },
        )
        assert sent.status_code == 200, sent.text

        stored = client.get(
            f"/api/v2/channels/{channel_id}/messages", headers=operator_headers
        ).json()
        assert len(stored) == 1
        recovered = aead.decrypt(
            responder_key,
            aead.Envelope.from_wire(base64.b64decode(stored[0]["envelope_b64"])),
            aad,
        )
        assert recovered == mavlink_frame


def test_enrollment_rejects_a_wrong_token_without_leaking_callsign_existence():
    with TestClient(app) as client:
        operator_headers, _, _ = register_verified(client, _unique("gcs"))
        callsign = _unique("UAV")
        client.post(
            "/api/v2/fleet/uavs", headers=operator_headers, json={"callsign": callsign}
        )

        wrong = client.post(
            "/api/v2/fleet/enroll",
            json={
                "callsign": callsign,
                "enrollment_token": "not-the-right-token",
                "ed25519_public_key": b64(bytes(range(32))),
            },
        )
        unknown = client.post(
            "/api/v2/fleet/enroll",
            json={
                "callsign": "does-not-exist",
                "enrollment_token": "not-the-right-token",
                "ed25519_public_key": b64(bytes(range(32))),
            },
        )
        assert wrong.status_code == unknown.status_code == 401
        assert wrong.json()["detail"] == unknown.json()["detail"]


def test_unenrolled_aircraft_cannot_be_linked():
    with TestClient(app) as client:
        operator_headers, _, _ = register_verified(client, _unique("gcs"))
        callsign = _unique("UAV")
        client.post(
            "/api/v2/fleet/uavs", headers=operator_headers, json={"callsign": callsign}
        )
        link = client.post(f"/api/v2/fleet/uavs/{callsign}/link", headers=operator_headers)
        assert link.status_code == 409


def test_bulk_provisioning_issues_distinct_single_use_tokens():
    with TestClient(app) as client:
        operator_headers, _, _ = register_verified(client, _unique("gcs"))
        prefix = _unique("FLEET")
        response = client.post(
            "/api/v2/fleet/uavs/bulk",
            headers=operator_headers,
            json={"callsign_prefix": prefix, "count": 25, "fleet": "bravo"},
        )
        assert response.status_code == 200, response.text
        endpoints = response.json()["endpoints"]
        assert len(endpoints) == 25
        assert len({item["enrollment_token"] for item in endpoints}) == 25
        assert len({item["callsign"] for item in endpoints}) == 25

        listed = client.get("/api/v2/fleet/uavs?fleet=bravo", headers=operator_headers).json()
        assert listed["total"] >= 25


def test_uav_accounts_are_hidden_from_human_user_search():
    with TestClient(app) as client:
        operator_headers, _, _ = register_verified(client, _unique("gcs"))
        callsign = _unique("UAV")
        provisioned = client.post(
            "/api/v2/fleet/uavs", headers=operator_headers, json={"callsign": callsign}
        ).json()
        enroll_aircraft(client, callsign, provisioned["enrollment_token"])

        results = client.get(f"/api/v2/users?query={callsign}", headers=operator_headers).json()
        assert results == []
