"""Signed firmware releases.

The trust anchor is the operator's Ed25519 signature, not this server, so the tests that
matter are the ones proving a release cannot be forged, replayed across fleets, or
silently redefined after endpoints have already verified it.
"""
import pytest

pytest.importorskip("aiosqlite")
pytest.importorskip("kyber_py")

import hashlib

from fastapi.testclient import TestClient

from app.crypto.identity import firmware_release_signing_payload
from app.main import app

from test_api_flow import b64, register_verified
from test_fleet import _unique, enroll_aircraft
from test_fleet_containment import _provision

IMAGE_V1 = hashlib.sha256(b"firmware-image-v1").digest()
IMAGE_V2 = hashlib.sha256(b"firmware-image-v2").digest()


def _sign(keys, fleet: str, version: str, measurement: bytes) -> str:
    return b64(
        keys["ed_private"].sign(
            firmware_release_signing_payload(
                fleet=fleet, version=version, measurement=measurement
            )
        )
    )


def _publish(client, headers, keys, fleet, version, measurement, **overrides):
    body = {
        "fleet": fleet,
        "version": version,
        "measurement_b64": b64(measurement),
        "signature_b64": overrides.pop("signature", _sign(keys, fleet, version, measurement)),
        "image_url": overrides.pop("image_url", "https://mirror.example/fw.bin"),
    }
    return client.post("/api/v2/firmware/releases", headers=headers, json=body)


def test_a_signed_release_is_published_and_listed():
    with TestClient(app) as client:
        headers, _, keys = register_verified(client, _unique("op"))
        fleet = _unique("alpha")

        published = _publish(client, headers, keys, fleet, "4.2.0", IMAGE_V1)
        assert published.status_code == 200, published.text
        assert published.json()["measurement"] == IMAGE_V1.hex()
        assert published.json()["operator_public_key"]

        listed = client.get(f"/api/v2/firmware/releases?fleet={fleet}", headers=headers).json()
        assert [row["version"] for row in listed] == ["4.2.0"]


def test_an_unsigned_or_forged_release_is_refused():
    with TestClient(app) as client:
        headers, _, keys = register_verified(client, _unique("op"))
        impostor_headers, _, impostor_keys = register_verified(client, _unique("other"))
        fleet = _unique("alpha")

        # Signature made by someone else's identity key.
        forged = _publish(
            client,
            headers,
            keys,
            fleet,
            "4.2.0",
            IMAGE_V1,
            signature=_sign(impostor_keys, fleet, "4.2.0", IMAGE_V1),
        )
        assert forged.status_code == 400


def test_a_signature_cannot_be_replayed_onto_another_fleet_or_version():
    """The reason fleet and version are inside the signed payload, not just the digest."""
    with TestClient(app) as client:
        headers, _, keys = register_verified(client, _unique("op"))
        test_fleet = _unique("test")
        prod_fleet = _unique("prod")

        approved = _sign(keys, test_fleet, "4.2.0", IMAGE_V1)

        # Same digest, same signature, different fleet.
        cross_fleet = _publish(
            client, headers, keys, prod_fleet, "4.2.0", IMAGE_V1, signature=approved
        )
        assert cross_fleet.status_code == 400

        # Same digest, same signature, different version.
        cross_version = _publish(
            client, headers, keys, test_fleet, "9.9.9", IMAGE_V1, signature=approved
        )
        assert cross_version.status_code == 400


def test_a_version_cannot_be_redefined_after_publication():
    """An endpoint that verified "4.2.0" must be able to rely on what that name means."""
    with TestClient(app) as client:
        headers, _, keys = register_verified(client, _unique("op"))
        fleet = _unique("alpha")

        assert _publish(client, headers, keys, fleet, "4.2.0", IMAGE_V1).status_code == 200
        again = _publish(client, headers, keys, fleet, "4.2.0", IMAGE_V2)
        assert again.status_code == 409


def test_withdrawing_a_release_removes_it_from_what_endpoints_are_offered():
    with TestClient(app) as client:
        headers, _, keys = register_verified(client, _unique("op"))
        fleet = _unique("alpha")
        release = _publish(client, headers, keys, fleet, "4.2.0", IMAGE_V1).json()

        withdrawn = client.post(
            f"/api/v2/firmware/releases/{release['id']}/withdraw",
            headers=headers,
            json={"reason": "bad build"},
        )
        assert withdrawn.status_code == 200, withdrawn.text
        assert withdrawn.json()["withdrawn_at"] is not None

        assert client.get(f"/api/v2/firmware/releases?fleet={fleet}", headers=headers).json() == []
        with_withdrawn = client.get(
            f"/api/v2/firmware/releases?fleet={fleet}&include_withdrawn=true", headers=headers
        ).json()
        assert len(with_withdrawn) == 1


def test_an_endpoint_is_told_whether_it_needs_the_update():
    """Closes the loop with attestation: approved digest and reported digest are the same
    kind of value, so the comparison is exact rather than advisory."""
    with TestClient(app) as client:
        operator_headers, _, keys = register_verified(client, _unique("op"))
        callsign = _unique("UAV")
        uav_headers, _, _ = enroll_aircraft(
            client, callsign, _provision(client, operator_headers, callsign)
        )
        # `_provision` puts the endpoint in fleet "alpha".
        _publish(client, operator_headers, keys, "alpha", _unique("v"), IMAGE_V1)

        # Nothing reported yet, so it cannot be known to match.
        before = client.get("/api/v2/firmware/available", headers=uav_headers).json()
        assert before["update_available"] is True
        assert before["current_matches"] is False

        # Report the approved image as the running measurement.
        client.post(
            "/api/v2/fleet/heartbeat", headers=uav_headers, json={"measurement_b64": b64(IMAGE_V1)}
        )
        after = client.get("/api/v2/firmware/available", headers=uav_headers).json()
        assert after["current_matches"] is True
        assert after["update_available"] is False


def test_a_release_carries_what_an_endpoint_needs_to_verify_it_alone():
    with TestClient(app) as client:
        headers, _, keys = register_verified(client, _unique("op"))
        fleet = _unique("alpha")
        release = _publish(client, headers, keys, fleet, "4.2.0", IMAGE_V1).json()

        # Everything required to check the signature offline, without trusting this server.
        assert release["measurement"] == IMAGE_V1.hex()
        assert release["signature"]
        assert release["operator_public_key"]
        # And the image itself is elsewhere: this service stores a pointer, not bytes.
        assert release["image_url"].startswith("https://")


def test_only_unmanned_endpoints_ask_for_their_own_firmware():
    with TestClient(app) as client:
        headers, _, _ = register_verified(client, _unique("op"))
        assert client.get("/api/v2/firmware/available", headers=headers).status_code == 403


def test_a_stranger_cannot_withdraw_another_operators_release():
    with TestClient(app) as client:
        headers, _, keys = register_verified(client, _unique("op"))
        stranger_headers, _, _ = register_verified(client, _unique("other"))
        fleet = _unique("alpha")
        release = _publish(client, headers, keys, fleet, "4.2.0", IMAGE_V1).json()

        refused = client.post(
            f"/api/v2/firmware/releases/{release['id']}/withdraw",
            headers=stranger_headers,
            json={},
        )
        assert refused.status_code == 404
