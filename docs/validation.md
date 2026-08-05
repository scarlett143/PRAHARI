# Validation Status

Last run: 2026-08-05, macOS 15 (arm64), Python 3.13.5, Node 20.20.2.

## Executed in this environment

- `cd backend && pytest -q` -> **52 passed, 1 skipped**.
- `cd frontend && npm ci && npm run build` -> Vite production build succeeds (71 modules).
- `npm audit` -> **0 vulnerabilities**.
- Live end-to-end run against a real `uvicorn` server with real WebSocket clients ->
  **24 checks passed**, covering invite issue/preview/redeem, direct peer link request and
  consent, push message delivery, typing relay, presence transitions in both directions,
  and read receipts returning to the sender.

The API test module contains a real two-user X25519 + ML-KEM-768 agreement, Ed25519-signed
session offer, AES-256-GCM send/store/retrieve/decrypt round trip, duplicate-message
rejection, and wrong-epoch rejection.

The single skip is deliberate: `test_scale.py` gates 1000 full ML-KEM handshakes behind
`PRAHARI_LOAD_TEST=1` so the default suite stays fast.

## Fixed during validation

- **Realtime fan-out silently disconnected every recipient.** `message.created` carries a
  `created_at` datetime, which `WebSocket.send_json` cannot serialise. The exception was
  caught by the per-socket handler in `ConnectionManager.notify_users`, which treats a
  failed send as a dead peer -- so every socket in the fan-out was pruned while the
  originating request still returned 200. This is why the console previously had to
  refetch the whole channel on each event instead of using the pushed frame.

  `notify_users` now renders the payload once with `jsonable_encoder` *before* touching
  any socket, so a serialisation error raises at the source instead of masquerading as a
  room full of unreachable clients. Regression coverage is in
  `tests/test_realtime_fanout.py`.

- **Vite 7.0.6 -> 7.3.6**, clearing seven advisories including path traversal and
  arbitrary file read via the dev-server WebSocket.

## Known environment gaps

- `docker compose up --build` has **not** been executed here: Docker is not installed on
  this machine. It remains the documented fresh-environment deployment path, and it is
  exercised by `.github/workflows/ci.yml`, but it is unverified locally.
- The disconnect-side presence announcement is asserted at the `ConnectionManager` level
  rather than through `TestClient`. Closing a `TestClient` WebSocket races the server's
  disconnect handler, which makes the frame's arrival non-deterministic; the live-server
  run above confirms the behaviour end to end.
