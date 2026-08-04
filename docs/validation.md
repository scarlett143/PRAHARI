# Validation Status

## Completed in the build environment

- `cd backend && pytest -q` -> **12 passed, 2 skipped**.
- `python -m compileall -q backend/app backend/tests` -> passed.
- `node --check` on all non-JSX frontend JavaScript modules -> passed.
- The API test module contains a real two-user X25519 + ML-KEM-768 agreement, Ed25519-signed session offer, AES-256-GCM send/store/retrieve/decrypt round trip, duplicate-message rejection, and wrong-epoch rejection.

## Environment-gated checks

The current execution environment cannot download packages from the Python/npm registries and does not provide Docker. Therefore:

- the two skipped Python modules are gated by `kyber-py` / `aiosqlite`, both pinned in `backend/requirements.txt`;
- a fresh `npm install && npm run build` could not be executed locally because `frontend/node_modules` is absent;
- `docker compose up --build` could not be launched locally because Docker is unavailable.

`.github/workflows/ci.yml` installs the declared backend and frontend dependencies before running the full backend suite and Vite production build. Docker Compose remains the documented fresh-environment deployment path.
