# PRAHARI bridge

The on-aircraft (or companion-computer) agent. It turns a MAVLink stream into
PRAHARI envelopes and back.

It reuses the backend's audited `app.crypto` package rather than reimplementing
the handshake, so an aircraft cannot drift away from the protocol the rest of the
platform speaks. Only the crypto primitives ship on the airframe — no API, no
database, no server code.

## What it does

1. Generates Ed25519, X25519 and ML-KEM-768 keys into a local keystore file.
   **These never leave the aircraft.**
2. Enrols once with a single-use token; afterwards renews credentials by signing
   a server challenge (an aircraft has no password).
3. Publishes its signed public bundle.
4. Establishes the two-party hybrid session with the ground station — the same
   deterministic initiator rule a browser follows.
5. Encrypts every telemetry frame locally and uploads only opaque envelopes.
6. Decrypts uplink commands locally and injects them toward the autopilot.

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt          # runtime
pip install -r requirements-dev.txt      # runtime + backend deps, for the tests
```

The agent locates the backend crypto package via, in order: an importable
`app.crypto`, `$PRAHARI_BACKEND_PATH`, then `../backend`.

## Run

```bash
# No autopilot required
python -m prahari_bridge --callsign UAV-001 --enrollment-token <token> \
  --channel-id <channel> --source synthetic

# Real MAVLink 2 from ArduPilot/PX4 SITL or a serial radio
python -m prahari_bridge --callsign UAV-001 --channel-id <channel> \
  --source sitl --device udpin:127.0.0.1:14550
```

Every flag has an environment-variable equivalent (`PRAHARI_CALLSIGN`,
`PRAHARI_CHANNEL_ID`, `PRAHARI_SOURCE`, …) — see `--help`.

## Keystore

Written to `./uav-keystore.json` by default, `0600`, via an atomic replace so the
keys are never briefly world-readable. **Losing it means re-provisioning the
aircraft**; the server cannot recover the private half of anything.

It is covered by `.gitignore`. Do not commit it.

## Tests

```bash
export PYTHONPATH=../backend
export DATABASE_URL="sqlite+aiosqlite:////tmp/prahari_bridge_test.db"
export JWT_SECRET="test-only-secret-long-enough-for-tests"
pytest -q
```

The suite boots the real API on a loopback port and asserts that the ground
station and the aircraft derive an identical 256-bit key, that telemetry arrives
intact, that the stored envelopes contain no plaintext, that uplink commands
decrypt on the aircraft, and that epoch rotation re-establishes the link.

## Latency note

The command path polls at 2 Hz by default (`--command-poll-interval`, via
`AgentConfig`). That is fine for SITL and for demonstration, but it is not the
sub-100 ms C2 path the hardware programme targets — that belongs on the radio
link itself, not on an HTTP round trip. Lowering latency here means moving the
downlink onto the WebSocket rather than polling.
