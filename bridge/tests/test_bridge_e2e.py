"""End-to-end proof that the GCS <-> UAV link is genuinely end-to-end encrypted.

The bridge runs against the real FastAPI application in-process. What is asserted:

* the aircraft enrols, publishes a signed bundle, and re-authenticates without a password;
* telemetry reaches the ground station decrypted and intact;
* the *stored* bytes on the server contain no plaintext telemetry;
* uplink commands travel the same encrypted path in reverse;
* epoch rotation re-establishes the session without losing the link.
"""
from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path

import pytest

pytest.importorskip("aiosqlite")
pytest.importorskip("kyber_py")
pytest.importorskip("httpx")

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "backend"))
sys.path.insert(0, str(REPO_ROOT / "bridge"))

import socket  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402

import uvicorn  # noqa: E402

from app.main import app  # noqa: E402
from prahari_bridge.agent import AgentConfig, BridgeAgent  # noqa: E402
from prahari_bridge.api import PrahariClient, b64e  # noqa: E402
from prahari_bridge.crypto import identity as identity_proto  # noqa: E402
from prahari_bridge.keystore import Keystore, generate_identity  # noqa: E402
from prahari_bridge.link import SecureLink  # noqa: E402
from prahari_bridge.sources import SyntheticSource  # noqa: E402


def _unique(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="session")
def api_url():
    """A real uvicorn server on an ephemeral port.

    The bridge talks plain HTTP over a socket exactly as it would to a ground station,
    so nothing about the transport is special-cased for tests.
    """
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    deadline = time.monotonic() + 30
    while not server.started:
        if time.monotonic() > deadline:
            raise RuntimeError("API server did not start")
        time.sleep(0.05)

    yield f"http://127.0.0.1:{port}"

    server.should_exit = True
    thread.join(timeout=10)


def register_operator(client: PrahariClient, username: str):
    """Register a human operator holding a bridge-style Identity object."""
    identity = generate_identity()
    auth = client.request(
        "POST",
        "/api/v2/auth/register",
        json={
            "username": username,
            "password": "correct-horse-battery-staple",
            "ed25519_public_key": b64e(identity.ed25519_public),
        },
    )
    client.token = auth["access_token"]
    challenge = client.challenge()
    client.publish_keys(
        x25519_public_key=identity.x25519_public,
        ml_kem_encapsulation_key=identity.ml_kem_encapsulation_key,
        challenge_signature=identity.sign(challenge.encode()),
        bundle_signature=identity.sign(
            identity_proto.bundle_signing_payload(
                x25519_public_key=identity.x25519_public,
                ml_kem_encapsulation_key=identity.ml_kem_encapsulation_key,
            )
        ),
    )
    return identity, auth["user_id"], auth["access_token"]


@pytest.fixture
def platform(tmp_path, api_url):
    """Operator + provisioned aircraft + a bootstrapped agent sharing one link."""
    operator_client = PrahariClient(api_url)
    callsign = _unique("UAV")
    operator_identity, operator_id, operator_token = register_operator(
        operator_client, _unique("gcs")
    )

    provisioned = operator_client.request(
        "POST",
        "/api/v2/fleet/uavs",
        json={"callsign": callsign, "airframe": "quad-x", "fleet": "test"},
    )

    uav_client = PrahariClient(api_url)
    source = SyntheticSource(rate_hz=200.0)
    agent = BridgeAgent(
        AgentConfig(
            base_url=api_url,
            callsign=callsign,
            keystore_path=str(tmp_path / "uav-keystore.json"),
            enrollment_token=provisioned["enrollment_token"],
        ),
        source,
        uav_client,
    )
    agent.ensure_identity()

    link = operator_client.request("POST", f"/api/v2/fleet/uavs/{callsign}/link")
    agent.config.channel_id = link["channel_id"]
    agent.bootstrap()

    gcs_link = SecureLink(
        operator_client,
        operator_identity,
        user_id=operator_id,
        channel_id=link["channel_id"],
    )
    # The link channel names the aircraft as initiator, because the aircraft speaks first
    # and a ratchet responder cannot send until it has received. So the aircraft publishes
    # its signed offer, and only then can the ground station derive anything -- the
    # reverse of the plain username ordering used for operator-to-operator channels.
    agent.link.establish()
    gcs_link.establish()

    yield {
        "callsign": callsign,
        "channel_id": link["channel_id"],
        "agent": agent,
        "source": source,
        "operator_client": operator_client,
        "operator_id": operator_id,
        "operator_token": operator_token,
        "gcs_link": gcs_link,
    }

    agent.stop()
    operator_client.close()
    uav_client.close()


def test_telemetry_reaches_the_gcs_decrypted_and_is_opaque_on_the_server(platform):
    agent, gcs_link = platform["agent"], platform["gcs_link"]

    frames = []
    for frame in agent.source.frames():
        agent.link.send(json.dumps(frame, separators=(",", ":")).encode())
        frames.append(frame)
        if len(frames) == 5:
            break

    stored = platform["operator_client"].list_messages(platform["channel_id"], limit=50)
    uplink = [row for row in stored if row["sender_id"] != platform["operator_id"]]
    assert len(uplink) == 5

    decrypted = [
        json.loads(
            gcs_link.decrypt(
                row["envelope_b64"], sender_id=row["sender_id"], epoch=row["key_epoch"]
            )
        )
        for row in uplink
    ]
    assert [item["seq"] for item in decrypted] == [item["seq"] for item in frames]
    assert decrypted[0]["lat"] == pytest.approx(frames[0]["lat"])
    assert decrypted[0]["mode"] == "AUTO"

    # The server holds ciphertext only: no field name or coordinate is recoverable.
    import base64

    for row in uplink:
        raw = base64.b64decode(row["envelope_b64"])
        assert b"lat" not in raw
        assert b"AUTO" not in raw
        assert b"telemetry" not in raw


def test_uplink_commands_are_decrypted_on_the_aircraft(platform):
    agent, gcs_link = platform["agent"], platform["gcs_link"]
    agent.link.establish()

    # One telemetry frame first, because the ratchet gives the ground station no sending
    # chain until it has received. This mirrors flight: the aircraft is already streaming
    # long before an operator issues a command.
    telemetry = agent.client.list_messages(platform["channel_id"], limit=1)
    if not telemetry:
        agent.link.send(b'{"type":"telemetry","seq":0}')
        telemetry = agent.client.list_messages(platform["channel_id"], limit=50)
    uplink_seed = [row for row in telemetry if row["sender_id"] != platform["operator_id"]][0]
    gcs_link.decrypt(
        uplink_seed["envelope_b64"],
        sender_id=uplink_seed["sender_id"],
        epoch=uplink_seed["key_epoch"],
    )

    command = {"type": "command", "command": "SET_MODE", "mode": "GUIDED"}
    gcs_link.send(json.dumps(command).encode())

    messages = agent.client.list_messages(platform["channel_id"], limit=50)
    downlink = [row for row in messages if row["sender_id"] == platform["operator_id"]]
    assert len(downlink) == 1

    plaintext = agent.link.decrypt(
        downlink[0]["envelope_b64"],
        sender_id=downlink[0]["sender_id"],
        epoch=downlink[0]["key_epoch"],
    )
    received = json.loads(plaintext)
    assert received == command
    assert agent.source.send_command(received) is True
    assert agent.source.accepted_commands[-1]["mode"] == "GUIDED"


def test_both_sides_derive_the_same_session_key(platform):
    """Parity check: the aircraft and the ground station agree on one 256-bit key."""
    uav_session = platform["agent"].link.establish()
    gcs_session = platform["gcs_link"].establish()
    assert uav_session.key == gcs_session.key
    assert len(uav_session.key) == 32
    assert uav_session.key_epoch == gcs_session.key_epoch


def test_epoch_rotation_re_establishes_the_link(platform):
    agent, gcs_link = platform["agent"], platform["gcs_link"]
    first = agent.link.establish()
    agent.link.send(b'{"type":"telemetry","seq":0}')

    platform["operator_client"].rotate_epoch(platform["channel_id"])

    # The initiator publishes the offer for the new epoch before the responder can
    # derive anything, same ordering as the initial handshake -- and on this channel the
    # aircraft is the initiator, so it goes first.
    second = agent.link.establish(force=True)
    rotated = gcs_link.establish(force=True)

    assert second.key_epoch == first.key_epoch + 1
    assert second.key != first.key
    assert rotated.key == second.key

    agent.link.send(b'{"type":"telemetry","seq":1}')

    messages = platform["operator_client"].list_messages(platform["channel_id"], limit=50)
    epochs = {row["key_epoch"] for row in messages}
    assert epochs == {first.key_epoch, second.key_epoch}


def test_aircraft_reauthenticates_without_a_password(platform, tmp_path):
    """A UAV holds no password; it renews credentials by signing a device challenge."""
    agent = platform["agent"]
    agent.client.token = None

    challenge = agent.client.device_challenge(platform["callsign"])
    renewed = agent.client.device_token(
        callsign=platform["callsign"],
        challenge_signature=agent.identity.sign(challenge.encode()),
    )
    assert renewed["user_id"] == agent.user_id
    assert agent.client.me()["kind"] == "uav"

    # The signed challenge is single use.
    replay = agent.client.request
    with pytest.raises(Exception):
        replay(
            "POST",
            "/api/v2/fleet/auth/token",
            json={
                "callsign": platform["callsign"],
                "challenge_signature": b64e(agent.identity.sign(challenge.encode())),
            },
        )


def test_keystore_never_writes_key_material_to_the_server(platform, tmp_path):
    """Private keys exist only in the local keystore file."""
    keystore = Keystore(platform["agent"].config.keystore_path)
    identity, meta = keystore.load()
    assert meta["enrolled"] is True

    # Nothing the server can return contains the private halves.
    bundle = platform["operator_client"].key_bundle(platform["callsign"])
    served = json.dumps(bundle).encode()
    assert b64e(identity.x25519_private).encode() not in served
    assert b64e(identity.ml_kem_decapsulation_key).encode() not in served
    assert b64e(identity.ed25519_private).encode() not in served

    # ...but the public halves it serves are exactly the ones we hold.
    assert bundle["x25519_public_key"] == b64e(identity.x25519_public)
    assert bundle["ml_kem_encapsulation_key"] == b64e(identity.ml_kem_encapsulation_key)
