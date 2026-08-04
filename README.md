# PRAHARI

**Hybrid post-quantum end-to-end encrypted communications — for people and for aircraft.**

PRAHARI runs one cryptographic protocol in two deployments:

| Mode | Peers | What travels |
|---|---|---|
| **Secure messaging** | operator ↔ operator | chat messages |
| **Encrypted UAV link** | ground station ↔ aircraft | MAVLink telemetry and C2 commands |

Both use the **identical** two-party session: Ed25519 identity → signed X25519 +
ML-KEM-768 bundle → HKDF-SHA256 → AES-256-GCM. There is no weaker path for the
drone link, and no special case in the server for it.

The core rule: **plaintext and decryption keys never exist on the server.** The
backend authenticates peers, publishes verified public-key bundles, relays
opaque envelopes, and records metadata-only audit events.

```
Operator browser                                     Aircraft (bridge)
Ed25519 / X25519 / ML-KEM private                    Ed25519 / X25519 / ML-KEM private
AES-256-GCM session key                              AES-256-GCM session key
        │                                                     ▲
        │   signed public bundles · signed session offer      │
        │   opaque AES-GCM envelopes                          │
        ▼                                                     │
              FastAPI + PostgreSQL  (cannot decrypt anything)
```

---

## Contents

- [Prerequisites](#prerequisites)
- [Quickstart with Docker](#quickstart-with-docker) — recommended
- [Quickstart without Docker](#quickstart-without-docker) — per OS
- [Two-operator messaging demo](#two-operator-messaging-demo)
- [Encrypted UAV link](#encrypted-uav-link)
- [Running the tests](#running-the-tests)
- [Scale](#scale)
- [Repository layout](#repository-layout)
- [What this does and does not claim](#what-this-does-and-does-not-claim)

---

## Prerequisites

| Tool | Version | Needed for |
|---|---|---|
| **Docker + Compose** | 24.0+ | the Docker quickstart (nothing else required) |
| **Python** | 3.11+ (3.12 / 3.13 tested) | backend and bridge without Docker |
| **Node.js** | **≥ 20.19** | frontend without Docker — Vite 7 will not start on Node 18 |
| **PostgreSQL** | 16 | backend without Docker (SQLite works for local runs) |
| ArduPilot or PX4 SITL | latest | *optional* — real MAVLink instead of synthetic telemetry |

Check what you have:

```bash
docker --version && docker compose version
python3 --version
node --version      # must be >= 20.19
```

---

## Quickstart with Docker

Identical on Linux, macOS and Windows.

**Linux / macOS**

```bash
git clone https://github.com/scarlett143/PRAHARI.git
cd PRAHARI
cp .env.example .env
python3 -c "import secrets; print('JWT_SECRET=' + secrets.token_urlsafe(48))" >> .env
docker compose up --build
```

**Windows (PowerShell)**

```powershell
git clone https://github.com/scarlett143/PRAHARI.git
cd PRAHARI
Copy-Item .env.example .env
python -c "import secrets; print('JWT_SECRET=' + secrets.token_urlsafe(48))" | Add-Content .env
docker compose up --build
```

Then open:

| | |
|---|---|
| Console | <http://localhost:5173> |
| API | <http://localhost:8000> |
| API docs | <http://localhost:8000/docs> |
| Health | <http://localhost:8000/health> |

The health endpoint states the invariant the whole design rests on:

```json
{ "status": "ok", "server_can_read_messages": false, "message_crypto_location": "client" }
```

Stop with `docker compose down`, or `docker compose down -v` to also drop the
database volume and the aircraft keystore.

---

## Quickstart without Docker

Run the backend and frontend in **two terminals**.

### Linux (Debian / Ubuntu)

```bash
sudo apt update && sudo apt install -y python3-venv python3-pip

# Terminal 1 — backend
cd PRAHARI/backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export DATABASE_URL="sqlite+aiosqlite:///./prahari.db"
export JWT_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
uvicorn app.main:app --reload --port 8000
```

```bash
# Terminal 2 — frontend
cd PRAHARI/frontend
npm install
npm run dev
```

### macOS

```bash
brew install python@3.12 node   # node must be >= 20.19

# Terminal 1 — backend
cd PRAHARI/backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export DATABASE_URL="sqlite+aiosqlite:///./prahari.db"
export JWT_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
uvicorn app.main:app --reload --port 8000
```

```bash
# Terminal 2 — frontend
cd PRAHARI/frontend
npm install
npm run dev
```

### Windows (PowerShell)

```powershell
# Terminal 1 — backend
cd PRAHARI\backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:DATABASE_URL = "sqlite+aiosqlite:///./prahari.db"
$env:JWT_SECRET = (python -c "import secrets; print(secrets.token_urlsafe(48))")
uvicorn app.main:app --reload --port 8000
```

```powershell
# Terminal 2 — frontend
cd PRAHARI\frontend
npm install
npm run dev
```

> If PowerShell blocks the activate script:
> `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`

To use PostgreSQL instead of SQLite, set
`DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/prahari`.

---

## Two-operator messaging demo

Private keys live in one browser profile, so a second peer needs a genuinely
separate profile (or a different browser).

1. Open <http://localhost:5173>, choose **Create identity**, register `alice`.
   Ed25519, X25519 and ML-KEM-768 private keys are generated in that browser.
2. In a **separate browser profile**, register `bob` the same way.
3. As Alice: create a workspace, then **Add a peer** → `bob`.
4. Open the `general` channel in both. One side is chosen deterministically (by
   username order) to publish the signed hybrid session offer; both derive the
   same 256-bit key locally.
5. Send a message. PostgreSQL receives only the AES-GCM envelope.
6. Try **Rotate epoch**, then **Proofs → Anchor pending batch** to build a Merkle
   batch and inclusion proofs.

A channel holds exactly **two** peers, because the hybrid session is two-party.
Adding a third person to a workspace creates a separate channel rather than
silently breaking encryption in an existing one.

---

## Encrypted UAV link

The aircraft is an ordinary cryptographic peer: it holds its own private keys and
runs the same handshake as a human. The bridge never transmits key material.

### 1. Provision the aircraft

In the console: **Fleet → Provision**. Copy the enrolment token — the server
stores only its hash and will not show it again.

Or via the API:

```bash
TOKEN=<operator JWT>
curl -X POST http://localhost:8000/api/v2/fleet/uavs \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"callsign":"UAV-001","airframe":"quad-x","fleet":"alpha"}'
```

### 2. Start the bridge

Synthetic telemetry — no autopilot needed:

```bash
cd PRAHARI/bridge
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python -m prahari_bridge \
  --api http://localhost:8000 \
  --callsign UAV-001 \
  --enrollment-token <token from step 1> \
  --source synthetic
```

It will report that no link channel is configured yet — that is expected.

### 3. Establish the link, then reconnect

Once the aircraft has published its key bundle, click **Establish link** in the
Fleet table (or `POST /api/v2/fleet/uavs/UAV-001/link`), then restart the bridge
with the returned channel id:

```bash
python -m prahari_bridge --callsign UAV-001 --channel-id <channel id> --source synthetic
```

Open the aircraft's console from the Fleet table. Telemetry appears on the track
display and the charts — **decrypted in your browser**, from envelopes the server
could not read.

### 4. Real MAVLink from SITL

```bash
# ArduPilot SITL
sim_vehicle.py -v ArduCopter --out=udp:127.0.0.1:14550

# or PX4
make px4_sitl gazebo

python -m prahari_bridge --callsign UAV-001 --channel-id <id> \
  --source sitl --device udpin:127.0.0.1:14550
```

Every MAVLink frame is wrapped in an AES-256-GCM envelope, carrying the raw wire
frame — a genuine encrypted MAVLink tunnel, not a re-encoding of decoded fields.
Commands sent from the console travel the same path in reverse and are decrypted
on the aircraft before reaching the autopilot.

### Aircraft credentials

An aircraft has no password. It enrols once with a single-use token, then renews
its access token by signing a server challenge with the Ed25519 key bound at
enrolment. Losing the keystore file means re-provisioning.

---

## Running the tests

```bash
# Backend — 31 tests
cd backend
pip install -r requirements.txt
pytest -q
```

```bash
# Bridge end-to-end — 6 tests. Boots the real API on a loopback port, so it
# needs the backend's dependencies as well as the bridge's.
cd bridge
pip install -r requirements-dev.txt
export PYTHONPATH=../backend
export DATABASE_URL="sqlite+aiosqlite:////tmp/prahari_bridge_test.db"
export JWT_SECRET="test-only-secret-long-enough-for-tests"
pytest -q
```

```bash
# Frontend build
cd frontend
npm install && npm run build
```

**Windows (PowerShell)** — same commands, with `$env:PYTHONPATH = "..\backend"`
in place of each `export`.

The heavy load test is opt-in, because pure-Python ML-KEM makes it slow:

```bash
cd backend
PRAHARI_LOAD_TEST=1 pytest tests/test_scale.py -k full_fleet -s
```

What the suites actually assert:

- both peers derive an identical 256-bit key, and stored bytes contain no plaintext;
- browser and backend HKDF derivations agree byte-for-byte;
- a conflicting session offer is rejected rather than silently swapped;
- epoch rotation re-establishes the link without losing it;
- an aircraft re-authenticates without a password, and its challenge is single-use;
- 1000 endpoints provision and paginate within bounded time.

---

## Scale

Measured on a development laptop, not a server:

| Operation | Result |
|---|---|
| Provision 1000 endpoints | ~1 s (single transaction) |
| 1000 full X25519 + ML-KEM-768 handshakes | 14.4 s — **14.4 ms each** (`kyber-py`, pure Python) |
| Fan-out to 1000 WebSocket clients | concurrent; one stalled socket cannot block the rest |

Design choices behind those numbers:

- Enrolment tokens are hashed with SHA-256, not Argon2. They are 256-bit CSPRNG
  values used once, so there is no guessing attack to slow down — and Argon2 at
  64 MiB per token would cost ~64 GiB of work to provision a 1000-aircraft fleet.
- `(channel_id, created_at)` and `(anchor_batch_id, created_at, id)` indices cover
  the hot read paths.
- The backend runs **one uvicorn worker**: the WebSocket registry is per-process,
  so a second worker could not reach clients attached to the first. Scaling out
  needs a shared broker (Redis pub/sub) first — see `docker-compose.yml`.
- `liboqs` (`PQC_BACKEND=liboqs`) is far faster than `kyber-py` and is the
  constant-time implementation. Use it for anything deployed.

---

## Repository layout

```text
PRAHARI/
├── backend/                 FastAPI + PostgreSQL
│   ├── app/
│   │   ├── api/             auth, servers, channels, sessions, messages,
│   │   │                    fleet, anchors, quantum, admin, websocket
│   │   ├── crypto/          AES-GCM, ML-KEM, hybrid KDF, entropy ← reused by the bridge
│   │   ├── blockchain/      Merkle tree + optional Polygon anchor
│   │   └── quantum/         QRNG / BB84 research demo
│   └── tests/               31 tests incl. regression + scale suites
├── bridge/                  on-aircraft agent
│   ├── prahari_bridge/      keystore, API client, session, MAVLink sources
│   └── tests/               6 end-to-end encrypted-link tests
├── frontend/                React 19 + Vite console
│   └── src/
│       ├── crypto/          browser-side handshake and AEAD
│       ├── components/      design-system primitives, charts, track display
│       ├── routes/          messaging, fleet, link console, proofs, quantum
│       └── styles/          design tokens, base, components
├── contracts/               MerkleAnchor.sol
├── docs/                    architecture, threat model, design system
└── docker-compose.yml
```

---

## What this does and does not claim

**Implemented and tested**

- Browser- and aircraft-held Ed25519 identities with signed ownership proofs
- Signed X25519 + ML-KEM-768 bundles; deterministic two-party session offers
- AES-256-GCM with sender/channel/epoch associated data
- Epoch rotation (100 messages / 15 minutes by default), replay rejection
- Merkle-batched proofs; Polygon anchoring optional and **fail-closed** — no
  transaction hash is ever fabricated
- Fleet provisioning, single-use enrolment, passwordless device re-authentication

**Explicitly not claimed**

- Not Signal Protocol, PQXDH, Double Ratchet, or ML-KEM Braid. Epoch rotation is
  not per-message forward secrecy or break-in recovery.
- **Two-party sessions only.** Group messaging needs a real group-key protocol,
  not one two-party key shared around.
- IndexedDB keeps private keys off the server, not away from XSS in this origin.
- Metadata — accounts, membership, timestamps, ciphertext sizes — is visible to
  the server. End-to-end encryption protects content, not traffic analysis.
- `kyber-py` is not constant-time. Neither is the browser ML-KEM.
- The quantum module is a research demo: QRNG output is an entropy-diversity
  input only, and BB84 here is a simulation, not a deployed quantum channel.

See [`docs/threat-model.md`](docs/threat-model.md) and
[`docs/architecture.md`](docs/architecture.md).
