# PRAHARI

PRAHARI is a demonstrable **hybrid post-quantum end-to-end encrypted messenger** built around one React + FastAPI + PostgreSQL stack.

The core design rule is simple: **message plaintext and message decryption keys never belong on the server**. The backend authenticates users, distributes verified public-key bundles, stores public session offers, routes encrypted envelopes, records metadata-only audit events, and optionally batches message hashes into Merkle roots.

## What is implemented

- Ed25519 browser identity generation and signed ownership challenge
- Signed X25519 + ML-KEM-768 public-key bundles
- Ed25519-signed public hybrid session offers bound to channel, epoch, and responder
- Argon2id password hashing and verified JWT access tokens
- Deterministic two-party hybrid session establishment in the browser
- X25519 + ML-KEM-768 -> HKDF-SHA256 -> 256-bit session key
- AES-256-GCM client-side encryption/decryption with sender/channel/epoch AAD
- PostgreSQL stores opaque encrypted envelopes only
- Authenticated WebSocket delivery notifications
- Epoch rotation with 100-message / 15-minute enforcement defaults
- Duplicate client-message replay rejection and fail-closed verification paths
- Merkle-batched message-hash proof layer with optional Polygon anchoring
- Optional Qiskit Aer QRNG experiment + BB84 protocol simulation/QBER metrics
- Docker Compose, automated tests, CI, architecture/threat-model/demo documentation

## Repository layout

```text
PRAHARI/
├── backend/
│   ├── app/
│   │   ├── api/            # auth, servers, channels, sessions, messages, ws, admin, anchors, quantum
│   │   ├── blockchain/     # Merkle tree + optional Polygon anchor
│   │   ├── crypto/         # AES-GCM, ML-KEM, hybrid KDF, entropy
│   │   ├── quantum/        # QRNG/BB84 research demo
│   │   ├── config.py
│   │   ├── database.py
│   │   ├── models.py
│   │   ├── realtime.py
│   │   └── security.py
│   ├── tests/
│   └── Dockerfile
├── frontend/
│   └── src/
│       ├── api/
│       ├── crypto/
│       ├── storage/
│       └── pages/
├── contracts/MerkleAnchor.sol
├── docs/
├── docker-compose.yml
└── .env.example
```

## Run locally

```bash
cp .env.example .env
# Set JWT_SECRET before sharing the environment.
docker compose up --build
```

Open:

- Frontend: `http://localhost:5173`
- API: `http://localhost:8000`
- Swagger: `http://localhost:8000/docs`
- Health: `http://localhost:8000/health`

Expected health invariant:

```json
{
  "status": "ok",
  "server_can_read_messages": false,
  "message_crypto_location": "client"
}
```

## Two-user demo

1. Register **Alice** in one browser profile.
2. Register **Bob** in another browser/profile.
3. Alice creates a workspace and adds Bob by username.
4. Open the `general` channel in both browsers.
5. PRAHARI deterministically chooses one side to publish an Ed25519-signed public hybrid session offer bound to the channel, epoch, and intended responder.
6. Both clients derive the same 256-bit session key locally.
7. Alice sends `Post-quantum encrypted hello!`.
8. Bob decrypts it locally; PostgreSQL receives only the AES-GCM wire envelope.
9. Rotate the channel to the next key epoch and send again.
10. Build a Merkle batch and run the Quantum Security Lab demo.

## Tests

```bash
cd backend
pip install -r requirements.txt
pytest -q
```

The hybrid test performs 100 randomized X25519 + ML-KEM-768 agreements. API tests exercise registration, verified key publication, two-user channel membership, ciphertext-only storage behavior, and wrong-epoch rejection.

## Optional quantum demo

The default backend stays lightweight. To include Qiskit Aer:

```bash
INSTALL_QUANTUM=1 docker compose build backend
docker compose up
```

Or locally:

```bash
pip install -r backend/requirements-quantum.txt
```

The QRNG experiment is supplementary. PRAHARI never treats network-delivered quantum bits as the sole secret key source.

## Optional Polygon anchor

```bash
INSTALL_BLOCKCHAIN=1 docker compose build backend
```

Then configure `POLYGON_RPC_URL`, `ANCHOR_CONTRACT_ADDRESS`, and `ANCHOR_PRIVATE_KEY`. If they are absent or anchoring fails, PRAHARI **does not fabricate a transaction hash**; batches remain locally verifiable and are explicitly marked as such.

## Scope / claim discipline

PRAHARI does **not** claim to implement Signal Protocol, PQXDH, Double Ratchet, or ML-KEM Braid. The current design is an epoch-based hybrid post-quantum E2EE demonstrator. See `docs/threat-model.md` and `docs/architecture.md`. Local verification details and environment-gated checks are recorded in `docs/validation.md`.
