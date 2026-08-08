"""Firmware attestation: pinning an approved digest and noticing when it changes.

The honest scope is narrow and these tests keep it that way. A measurement is self-reported
over an authenticated channel, so it proves the endpoint holds its enrolment key -- not
that it is running the software it names. What is being tested is that drift from a pinned
value is detected, recorded once, and surfaced; not that a hostile airframe can be caught
lying, which without a hardware root of trust it cannot.
"""
import pytest

pytest.importorskip("aiosqlite")
pytest.importorskip("kyber_py")

import hashlib

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.main import app
from app.models import AuditLog

from test_api_flow import b64, register_verified
from test_fleet import _unique, enroll_aircraft
from test_fleet_containment import _provision, _row

GOOD = hashlib.sha256(b"approved-firmware-v4.2").digest()
TAMPERED = hashlib.sha256(b"something-else-entirely").digest()


def _heartbeat(client: TestClient, uav_headers, measurement: bytes | None = None):
    body = {"measurement_b64": b64(measurement)} if measurement else {}
    return client.post("/api/v2/fleet/heartbeat", headers=uav_headers, json=body)


def test_a_matching_measurement_reads_as_trusted():
    with TestClient(app) as client:
        operator_headers, _, _ = register_verified(client, _unique("gcs"))
        callsign = _unique("UAV")
        uav_headers, _, _ = enroll_aircraft(client, callsign, _provision(client, operator_headers, callsign))

        # Nothing pinned yet, so there is nothing to compare against.
        assert _row(client, operator_headers, callsign)["attestation_state"] == "unpinned"

        pinned = client.post(
            f"/api/v2/fleet/uavs/{callsign}/attestation",
            headers=operator_headers,
            json={"measurement_b64": b64(GOOD)},
        )
        assert pinned.status_code == 200, pinned.text
        assert pinned.json()["attestation_state"] == "unreported"

        beat = _heartbeat(client, uav_headers, GOOD)
        assert beat.status_code == 200, beat.text
        assert beat.json()["attestation_state"] == "trusted"
        assert _row(client, operator_headers, callsign)["attestation_state"] == "trusted"


def test_a_different_measurement_reads_as_drift_and_is_audited_once():
    with TestClient(app) as client:
        operator_headers, _, _ = register_verified(client, _unique("gcs"))
        callsign = _unique("UAV")
        uav_headers, _, _ = enroll_aircraft(client, callsign, _provision(client, operator_headers, callsign))

        client.post(
            f"/api/v2/fleet/uavs/{callsign}/attestation",
            headers=operator_headers,
            json={"measurement_b64": b64(GOOD)},
        )
        _heartbeat(client, uav_headers, GOOD)

        assert _heartbeat(client, uav_headers, TAMPERED).json()["attestation_state"] == "drifted"
        # Three more heartbeats in the same drifted state.
        for _ in range(3):
            _heartbeat(client, uav_headers, TAMPERED)

        row = _row(client, operator_headers, callsign)
        assert row["attestation_state"] == "drifted"
        assert row["expected_measurement"] == GOOD.hex()[:16]
        assert row["last_measurement"] == TAMPERED.hex()[:16]

        from app.database import get_session_factory
        import anyio

        async def drift_rows():
            async with get_session_factory()() as session:
                rows = (
                    await session.execute(
                        select(AuditLog).where(AuditLog.event == "fleet.attestation_drift")
                    )
                ).scalars().all()
                return [row for row in rows if callsign in (row.detail or "")]

        entries = anyio.run(drift_rows)
        assert len(entries) == 1, (
            "drift must be audited on the transition, not on every heartbeat -- otherwise "
            "the moment it happened is buried under identical rows on a shared disk"
        )


def test_recovering_to_the_pinned_firmware_clears_the_drift():
    with TestClient(app) as client:
        operator_headers, _, _ = register_verified(client, _unique("gcs"))
        callsign = _unique("UAV")
        uav_headers, _, _ = enroll_aircraft(client, callsign, _provision(client, operator_headers, callsign))

        client.post(
            f"/api/v2/fleet/uavs/{callsign}/attestation",
            headers=operator_headers,
            json={"measurement_b64": b64(GOOD)},
        )
        _heartbeat(client, uav_headers, TAMPERED)
        assert _row(client, operator_headers, callsign)["attestation_state"] == "drifted"

        # Reflashing the approved image is a normal recovery, not a permanent mark.
        _heartbeat(client, uav_headers, GOOD)
        assert _row(client, operator_headers, callsign)["attestation_state"] == "trusted"


def test_a_heartbeat_without_a_measurement_still_reports_liveness():
    """Older firmware must keep working; attestation is additive, not a new requirement."""
    with TestClient(app) as client:
        operator_headers, _, _ = register_verified(client, _unique("gcs"))
        callsign = _unique("UAV")
        uav_headers, _, _ = enroll_aircraft(client, callsign, _provision(client, operator_headers, callsign))

        beat = _heartbeat(client, uav_headers)
        assert beat.status_code == 200, beat.text
        assert beat.json()["last_seen_at"] is not None
        assert _row(client, operator_headers, callsign)["last_seen_at"] is not None


def test_clearing_the_pin_returns_the_endpoint_to_unpinned():
    with TestClient(app) as client:
        operator_headers, _, _ = register_verified(client, _unique("gcs"))
        callsign = _unique("UAV")
        uav_headers, _, _ = enroll_aircraft(client, callsign, _provision(client, operator_headers, callsign))

        client.post(
            f"/api/v2/fleet/uavs/{callsign}/attestation",
            headers=operator_headers,
            json={"measurement_b64": b64(GOOD)},
        )
        _heartbeat(client, uav_headers, TAMPERED)

        cleared = client.post(
            f"/api/v2/fleet/uavs/{callsign}/attestation",
            headers=operator_headers,
            json={"measurement_b64": ""},
        )
        assert cleared.status_code == 200, cleared.text
        assert cleared.json()["attestation_state"] == "unpinned"


def test_only_the_owning_operator_can_pin_a_measurement():
    with TestClient(app) as client:
        owner_headers, _, _ = register_verified(client, _unique("gcs"))
        stranger_headers, _, _ = register_verified(client, _unique("other"))
        callsign = _unique("UAV")
        enroll_aircraft(client, callsign, _provision(client, owner_headers, callsign))

        refused = client.post(
            f"/api/v2/fleet/uavs/{callsign}/attestation",
            headers=stranger_headers,
            json={"measurement_b64": b64(TAMPERED)},
        )
        assert refused.status_code == 404
        assert _row(client, owner_headers, callsign)["attestation_state"] == "unpinned"


def test_a_malformed_measurement_is_refused():
    with TestClient(app) as client:
        operator_headers, _, _ = register_verified(client, _unique("gcs"))
        callsign = _unique("UAV")
        enroll_aircraft(client, callsign, _provision(client, operator_headers, callsign))

        # Not 32 bytes: a digest of the wrong length is a bug at the caller, not a pin.
        refused = client.post(
            f"/api/v2/fleet/uavs/{callsign}/attestation",
            headers=operator_headers,
            json={"measurement_b64": b64(b"too-short")},
        )
        assert refused.status_code == 400
