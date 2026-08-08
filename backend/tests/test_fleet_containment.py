"""Cutting a compromised endpoint off the relay.

Before this existed a provisioned aircraft held a valid identity forever: there was no
revoke, no disable, no quarantine anywhere in the fleet API. These tests hold the new kill
switch to the standard that makes it worth having -- that it closes *every* door, not the
most obvious one. A containment that leaves a live token working, or lets whoever holds
the enrolment token walk the endpoint straight back into service, is theatre.
"""
import pytest

pytest.importorskip("aiosqlite")
pytest.importorskip("kyber_py")

import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from app.main import app

from test_api_flow import b64, register_verified
from test_fleet import _unique, enroll_aircraft


def _provision(client: TestClient, operator_headers, callsign: str) -> str:
    response = client.post(
        "/api/v2/fleet/uavs",
        headers=operator_headers,
        json={"callsign": callsign, "airframe": "quad-x", "fleet": "alpha"},
    )
    assert response.status_code == 200, response.text
    return response.json()["enrollment_token"]


def _row(client: TestClient, operator_headers, callsign: str) -> dict:
    listing = client.get(
        f"/api/v2/fleet/uavs?query={callsign}", headers=operator_headers
    ).json()
    return next(row for row in listing["endpoints"] if row["callsign"] == callsign)


def test_quarantine_revokes_live_tokens_rather_than_waiting_for_them_to_expire():
    with TestClient(app) as client:
        operator_headers, _, _ = register_verified(client, _unique("gcs"))
        callsign = _unique("UAV")
        uav_headers, _, _ = enroll_aircraft(client, callsign, _provision(client, operator_headers, callsign))

        # The aircraft holds a working token before containment.
        assert client.get("/api/v2/auth/me", headers=uav_headers).status_code == 200

        contained = client.post(
            f"/api/v2/fleet/uavs/{callsign}/quarantine",
            headers=operator_headers,
            json={"reason": "off the air for 40 minutes"},
        )
        assert contained.status_code == 200, contained.text
        # Containment is two independent layers, and this is the second one: every
        # recorded session is revoked, so the token fails even if the account status were
        # somehow flipped back.
        assert contained.json()["sessions_revoked"] >= 1

        # That same token stops working immediately, rather than at its expiry. The code
        # is 403 rather than 401 because `current_user` checks account status before it
        # checks the session -- either refusal is correct, this pins which arrives.
        refused = client.get("/api/v2/auth/me", headers=uav_headers)
        assert refused.status_code == 403, refused.text

        row = _row(client, operator_headers, callsign)
        assert row["security_state"] == "quarantined"
        assert row["security_state_reason"] == "off the air for 40 minutes"


def test_a_contained_endpoint_cannot_reauthenticate_with_its_identity_key():
    with TestClient(app) as client:
        operator_headers, _, _ = register_verified(client, _unique("gcs"))
        callsign = _unique("UAV")
        _, _, keys = enroll_aircraft(client, callsign, _provision(client, operator_headers, callsign))

        client.post(
            f"/api/v2/fleet/uavs/{callsign}/quarantine",
            headers=operator_headers,
            json={"reason": "suspected clone"},
        )

        # The challenge endpoint still answers -- refusing here would tell an attacker
        # exactly which aircraft have been quarantined -- but the nonce is never recorded,
        # so the signature cannot be redeemed.
        challenge = client.post(
            "/api/v2/fleet/auth/challenge", json={"callsign": callsign}
        )
        assert challenge.status_code == 200
        signature = keys["ed_private"].sign(challenge.json()["challenge"].encode())
        token = client.post(
            "/api/v2/fleet/auth/token",
            json={"callsign": callsign, "challenge_signature": b64(signature)},
        )
        assert token.status_code == 401


def test_quarantine_before_enrolment_cannot_be_undone_by_redeeming_the_token():
    """The bypass this guards against is subtle: enrolment ends by setting the account
    active, so without a containment check the enrolment token doubles as a way to lift a
    quarantine -- and the token is often the reason the endpoint was quarantined."""
    with TestClient(app) as client:
        operator_headers, _, _ = register_verified(client, _unique("gcs"))
        callsign = _unique("UAV")
        token = _provision(client, operator_headers, callsign)

        client.post(
            f"/api/v2/fleet/uavs/{callsign}/quarantine",
            headers=operator_headers,
            json={"reason": "provisioning token may have leaked"},
        )

        ed_private = Ed25519PrivateKey.generate()
        ed_public = ed_private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        enrolled = client.post(
            "/api/v2/fleet/enroll",
            json={
                "callsign": callsign,
                "enrollment_token": token,
                "ed25519_public_key": b64(ed_public),
            },
        )
        assert enrolled.status_code == 401
        assert _row(client, operator_headers, callsign)["security_state"] == "quarantined"


def test_restore_returns_a_quarantined_endpoint_to_service():
    with TestClient(app) as client:
        operator_headers, _, _ = register_verified(client, _unique("gcs"))
        callsign = _unique("UAV")
        _, _, keys = enroll_aircraft(client, callsign, _provision(client, operator_headers, callsign))

        client.post(
            f"/api/v2/fleet/uavs/{callsign}/quarantine",
            headers=operator_headers,
            json={"reason": "precautionary"},
        )
        restored = client.post(f"/api/v2/fleet/uavs/{callsign}/restore", headers=operator_headers)
        assert restored.status_code == 200, restored.text
        assert _row(client, operator_headers, callsign)["security_state"] == "active"

        # Restoring does not hand back the revoked sessions; the aircraft re-authenticates.
        challenge = client.post("/api/v2/fleet/auth/challenge", json={"callsign": callsign})
        signature = keys["ed_private"].sign(challenge.json()["challenge"].encode())
        token = client.post(
            "/api/v2/fleet/auth/token",
            json={"callsign": callsign, "challenge_signature": b64(signature)},
        )
        assert token.status_code == 200, token.text


def test_revocation_is_final_and_destroys_the_enrolment_path():
    with TestClient(app) as client:
        operator_headers, _, _ = register_verified(client, _unique("gcs"))
        callsign = _unique("UAV")
        token = _provision(client, operator_headers, callsign)
        enroll_aircraft(client, callsign, token)

        revoked = client.post(
            f"/api/v2/fleet/uavs/{callsign}/revoke",
            headers=operator_headers,
            json={"reason": "airframe captured"},
        )
        assert revoked.status_code == 200, revoked.text

        row = _row(client, operator_headers, callsign)
        assert row["security_state"] == "revoked"
        assert row["key_verified"] is False, "the link path must refuse it too"

        # Neither route back is open.
        assert client.post(
            f"/api/v2/fleet/uavs/{callsign}/restore", headers=operator_headers
        ).status_code == 409
        assert client.post(
            f"/api/v2/fleet/uavs/{callsign}/quarantine",
            headers=operator_headers,
            json={"reason": "downgrade attempt"},
        ).status_code == 409


def test_containment_is_limited_to_the_operator_who_owns_the_endpoint():
    with TestClient(app) as client:
        owner_headers, _, _ = register_verified(client, _unique("gcs"))
        stranger_headers, _, _ = register_verified(client, _unique("other"))
        callsign = _unique("UAV")
        enroll_aircraft(client, callsign, _provision(client, owner_headers, callsign))

        refused = client.post(
            f"/api/v2/fleet/uavs/{callsign}/revoke",
            headers=stranger_headers,
            json={"reason": "not mine to revoke"},
        )
        assert refused.status_code == 404
        assert _row(client, owner_headers, callsign)["security_state"] == "active"
