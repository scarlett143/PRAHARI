# Day 1 — Clean Architecture and Bootstrapping

## Completed

- Created one canonical `backend/app` Python package.
- Reused the stronger AES-256-GCM, ML-KEM-768, hybrid X25519 + ML-KEM, configuration, database, model, and security foundations from `Cryptographic_Communication/Backend_Updated`.
- Kept fake Kyber, pseudo-Signal branding, duplicate Node/Mongo backends, simulated MPC/ZKP, and Base64-as-encryption out of the active path.
- Added async PostgreSQL through SQLAlchemy + asyncpg.
- Added a minimal React/Vite frontend with a live backend health check.
- Added Docker Compose for frontend + backend + PostgreSQL.
- Added a safe `.env.example` and `.gitignore`.
- Added AES-GCM tests and hybrid tests.
- Added `/health` with `server_can_read_messages: false`.

## Structure

```text
PRAHARI/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── crypto/
│   │   │   ├── aead.py
│   │   │   ├── hybrid.py
│   │   │   └── pqc.py
│   │   ├── config.py
│   │   ├── database.py
│   │   ├── main.py
│   │   ├── models.py
│   │   └── security.py
│   ├── tests/
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── src/api/
│   ├── src/crypto/
│   ├── src/components/
│   └── src/pages/
├── contracts/
├── docs/
├── .env.example
└── docker-compose.yml
```

## Run

```bash
cp .env.example .env
# Set JWT_SECRET to a generated value for shared environments.
docker compose up --build
```

Open:
- Frontend: http://localhost:5173
- API docs: http://localhost:8000/docs
- Health: http://localhost:8000/health

Expected health invariant:

```json
{
  "status": "ok",
  "server_can_read_messages": false
}
```

## Day 2 handoff

Implement registration/login, Argon2id password flow, JWT verification, browser-generated Ed25519 identity keys, challenge-response ownership proof, and verified X25519 + ML-KEM public key publication.
