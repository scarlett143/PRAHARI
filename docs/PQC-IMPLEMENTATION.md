# PRAHARI — Post-Quantum Cryptography Implementation Report

**Status as of 2026-08-08** · Deployed and live at `https://vishal.kovaihost.cloud`
**Repository:** `github.com/scarlett143/PRAHARI` (branch `main`)
**Tests:** 200 backend (1 skipped) · 106 frontend · all passing
**API surface:** 93 routes across 16 groups · OpenAPI at `/docs` and `/openapi.json`

---

## 0. How to read this document

Every claim below is either **implemented and tested**, **partially implemented**, or
**not implemented**. Those three labels are used literally and are not softened. A section
marked *not implemented* means there is no code for it, regardless of how adjacent the
surrounding work is.

Measured numbers come from `backend/scripts/benchmark_crypto.py` executed on the actual
deployment host (2 vCPU shared VM) under a 45% CPU cap, not from a developer laptop and not
from vendor documentation.

---

## 1. Requirements coverage at a glance

### 1.1 Functional requirements

| # | Requirement | Status | Where |
|---|---|---|---|
| 1 | Hybrid key exchange | **Implemented** | `backend/app/crypto/hybrid.py`, `frontend/src/crypto/hybrid.js` |
| 2 | Secure messaging | **Implemented** | `crypto/aead.py`, `crypto/ratchet.py`, `api/messages.py` |
| 3 | Digital signatures | **Implemented** | `crypto/identity.py` (Ed25519), `crypto/pqsign.py` (ML-DSA-65) |
| 4 | Key lifecycle management | **Implemented** | epochs, rotation, `transparency.py`, `api/servers.py` |
| 5 | Certificate validation | **Implemented** | `app/pki.py`, `api/pki.py` |
| 6 | Secure session establishment | **Implemented** | `crypto/channelCrypto.js`, `api/channels.py` |
| 7 | Performance benchmarking | **Partial** | script exists; **no dashboard** |
| 8 | Cryptographic audit reporting | **Implemented** | `audit_chain.py` + this document |

### 1.2 Technical expectations

| # | Expectation | Status | Note |
|---|---|---|---|
| 1 | ML-KEM (Kyber) | **Implemented** | ML-KEM-768, FIPS 203, two backends |
| 2 | ML-DSA (Dilithium) | **Implemented** | ML-DSA-65, FIPS 204, via liboqs |
| 3 | Hybrid TLS handshakes | **Not implemented** | See §7 — this is the largest gap |
| 4 | Secure key rotation | **Implemented** | epoch model + automatic rotation |
| 5 | Forward secrecy | **Implemented** | Double Ratchet (2-party); per-epoch (group) |
| 6 | Hardware acceleration | **Partial** | liboqs AVX2 where the CPU offers it; not tuned |
| 7 | Side-channel considerations | **Partial** | constant-time backend enforced in production |
| 8 | Cryptographic benchmarking | **Implemented** | `scripts/benchmark_crypto.py`, results in §6 |

### 1.3 Deliverables

| # | Deliverable | Status |
|---|---|---|
| 1 | Secure client/server application | **Implemented** — React SPA + FastAPI, deployed |
| 2 | PQC proxy | **Not implemented** — see §7 |
| 3 | Benchmark dashboard | **Not implemented** — CLI script only |
| 4 | Cryptographic analysis report | **This document** |
| 5 | API documentation | **Implemented** — auto-generated OpenAPI, live |

### 1.4 Bonus innovation

| # | Item | Status |
|---|---|---|
| 1 | Quantum VPN | **Implemented as a control plane** — see §8.1 |
| 2 | PQC-enabled IoT | **Implemented** — UAV endpoints use the identical stack, §8.2 |
| 3 | Hybrid PKI | **Implemented** — dual-signature certificates, §8.3 |
| 4 | Secure firmware updates | **Implemented** — signed digests, §8.4 |
| 5 | Quantum-safe blockchain integration | **Partial** — ML-DSA-signed Merkle anchors, §8.5 |

---

## 2. Cryptographic primitives in use

| Purpose | Algorithm | Parameters | Implementation |
|---|---|---|---|
| PQ key encapsulation | **ML-KEM-768** | ek 1184 B, ct 1088 B, ss 32 B | liboqs (prod) / kyber-py (dev) |
| Classical key agreement | **X25519** | 32 B keys | `cryptography` (OpenSSL) |
| Combiner | **HKDF-SHA256** | → 32 B AES key | `cryptography` |
| Bulk encryption | **AES-256-GCM** | 12 B nonce, 128-bit tag | `cryptography` (AES-NI) |
| Classical signature | **Ed25519** | 64 B signature | `cryptography` |
| PQ signature | **ML-DSA-65** | pk 1952 B, sig 3309 B | liboqs |
| Ratchet KDF | **HKDF-SHA256 + HMAC-SHA256** | root/chain separation | `crypto/ratchet.py` |
| Password hashing | **Argon2id** | t=2, m=19 MiB, p=1 | `argon2-cffi` |
| Second factor | **TOTP (RFC 6238)** | HMAC-SHA1, 6 digits | hand-rolled, `crypto/totp.py` |
| Hardware factor | **WebAuthn** | ES256 / RS256 / Ed25519 | `crypto/webauthn.py`, no dependency |

### 2.1 Why ML-KEM-768 and ML-DSA-65

Both sit at **NIST security category 3**. Matching the levels is deliberate: mixing a
category-1 KEM with a category-3 signature means the effective strength is category 1, and
the weakest link should be a decision rather than an accident. ML-DSA-44 would have been
smaller and ML-DSA-87 stronger; 65 is the one that matches the KEM already in use.

---

## 3. Functional requirement detail

### 3.1 Hybrid key exchange — *implemented*

`backend/app/crypto/hybrid.py` · `frontend/src/crypto/hybrid.js`

The shared secret is derived from **both** an X25519 exchange and an ML-KEM-768
encapsulation, concatenated and passed through HKDF-SHA256:

```
shared_secret = HKDF-SHA256(
    ikm  = X25519_shared || ML-KEM_shared,
    info = "prahari/hybrid-kem/v1/aes256gcm" || SHA256(transcript),
    L    = 32
)
```

Properties that follow from this construction:

- **Breaking one algorithm is not enough.** An attacker needs both the elliptic-curve
  problem and the lattice problem. Classical attackers face X25519; a future quantum
  attacker faces ML-KEM.
- **The transcript is bound into the derivation.** `transcript_digest()` covers the
  responder's public bundle *and* the ciphertext, so a swapped or replayed ciphertext
  produces a different key rather than a working session.
- **The transcript is hashed before use as HKDF `info`.** The raw transcript is 2336 bytes
  because ML-KEM keys are large, and OpenSSL-backed HKDF rejects `info` longer than 1024
  bytes. Hashing to 32 bytes preserves the binding and keeps the construction portable to
  Node, Deno, browsers, and an embedded reimplementation.

Key derivation functions:

| Function | Role |
|---|---|
| `generate_bundle()` | Produce a paired X25519 + ML-KEM keypair |
| `initiate(responder)` | Encapsulate to a peer; returns ciphertext + derived key |
| `respond(private, public, ct)` | Decapsulate; returns the same derived key |
| `transcript_digest(...)` | Bind responder identity and ciphertext into the KDF |

### 3.2 Secure messaging — *implemented*

Every message is an **AES-256-GCM envelope** sealed in the browser. The server stores
opaque bytes and holds no key capable of opening them.

Wire format (`crypto/aead.py`):

```
version(1) ‖ nonce_len(1) ‖ nonce(12) ‖ ciphertext ‖ tag(16)
```

Associated data binds `sender_id`, `channel_id` and `key_epoch`. This is what makes
client-side authority decisions sound: a forged "edit" claiming another sender fails
authentication before any application logic sees it.

**Two channel modes**, forced by the storage model (one envelope per message, so an
N-party channel needs one key every member can read):

| Members | Mode | Forward secrecy |
|---|---|---|
| Exactly 2 | Double Ratchet | **Per message** |
| 3 or more | Shared epoch key, sealed per member via hybrid KEM | **Per epoch** |

**Typed payloads.** Reply, edit, retract, react and pin are all the *same sealed envelope*
with a different payload inside, so the relay cannot distinguish a reaction from a message.
A NUL marker separates structured payloads from pre-existing plain strings — without it, a
user typing JSON would have it interpreted as a command.

### 3.3 Digital signatures — *implemented*

| Signed object | Algorithm | Domain separator |
|---|---|---|
| Key bundle | Ed25519 | `PRAHARI-KEY-BUNDLE-V1\0` |
| Session offer | Ed25519 | `PRAHARI-SESSION-OFFER-V1\0` |
| Password reset | Ed25519 | `PRAHARI-PASSWORD-RESET-V1\0` |
| Firmware release | Ed25519 | `PRAHARI-FIRMWARE-RELEASE-V1\0` |
| Anchor root | **ML-DSA-65** | `PRAHARI-ANCHOR-ROOT-V1\0` |
| Certificate | **Ed25519 + ML-DSA-65** | `PRAHARI-HYBRID-CERT-V1\0` |

Every signed message space carries its own label. Without domain separation, a signature
captured from key publication would be a valid password reset for the same account — the
two would be the same bytes.

All variable-length fields are **length-prefixed** before hashing or signing. Without
prefixes, a fleet named `ab` at version `c` and one named `a` at version `bc` produce
identical input, and one release's signature would verify against the other.

### 3.4 Key lifecycle management — *implemented*

| Stage | Mechanism |
|---|---|
| Generation | Client-side only; private keys never transmitted |
| Publication | Ed25519-signed bundle + challenge-response proof of possession |
| Distribution | Server serves public bundles; inclusion in a per-user hash chain |
| Rotation | Epoch counter; automatic on message-count or time limit |
| Revocation | Endpoint containment, certificate revocation, session revocation |
| Recovery | Identity key resets the password; encrypted backup file |
| At rest | Argon2id + AES-GCM wrapping (`crypto/keylock.js`) |

**Rotation thresholds:** 100 messages or 60 minutes per epoch. Rotation is automatic — a
`rekey_required` response triggers a rotate-and-resend, so forward secrecy advances without
operator action. The current epoch is displayed in the UI so the property stays observable.

**Key transparency.** Every published bundle appends to a per-user hash chain:

```
entry_hash = SHA256(
    "prahari-key-transparency-v1" ‖ prev_hash ‖
    len(user_id)‖user_id ‖ len(ed25519)‖ed25519 ‖
    len(x25519)‖x25519 ‖ len(ml_kem)‖ml_kem ‖ seq
)
```

Editing, reordering or dropping an entry breaks every hash after it. The chain is
**recomputed in the browser**; the server's own `chain_ok` field is ignored, because a log
grading its own homework is not evidence. Chained *per user* rather than globally so two
people publishing simultaneously never contend for one tail.

### 3.5 Certificate validation — *implemented*

`app/pki.py` — see §8.3 for the dual-signature design. Validation checks, in order:

1. Validity window (`not_before` ≤ now < `not_after`)
2. Revocation status of every link
3. Chain contiguity (each certificate's issuer is the next in the chain)
4. `is_ca` on every issuer — a leaf may not sign
5. Self-issued certificates only at the end of a chain
6. Termination at an explicitly **pinned** trust root
7. **Both** signatures on every link

Depth is capped (`MAX_CHAIN_DEPTH = 8`) and loops are detected — a certificate naming an
issuer that eventually names it back is otherwise a denial of service with two rows.

### 3.6 Secure session establishment — *implemented*

```
1. Both parties publish signed X25519 + ML-KEM bundles
2. Initiator verifies the responder's bundle signature (Ed25519)
3. Initiator runs hybrid.initiate() → ciphertext + shared secret
4. Session offer is Ed25519-signed and uploaded
5. Responder verifies, runs hybrid.respond() → same shared secret
6. Two-party: secret seeds a Double Ratchet
   Group:     secret wraps a per-epoch group key, sealed to each member
```

The aircraft link uses **the identical protocol** — no weaker path exists for machine
peers. The only difference is `Channel.initiator_id`, which names the aircraft explicitly:
a Double Ratchet responder cannot send before receiving, and an aircraft's first action is
to transmit telemetry.

### 3.7 Performance benchmarking — *partial*

`backend/scripts/benchmark_crypto.py` measures every operation the system performs, with
medians over repeated rounds and one untimed warm-up call. Results in §6.

**Not implemented:** a benchmark *dashboard*. Output is a CLI table. Building a UI for it
was traded against the deployment constraint in §9.

### 3.8 Cryptographic audit reporting — *implemented*

`app/audit_chain.py`. Audit rows are hash-chained by an explicit **sealing pass**, not on
write.

The reason is a design decision worth stating: chaining on write means two simultaneous
requests read the same chain tail, both claim the next sequence, and one fails — so a
request would fail *because of its own audit write*. That is worse than the tampering it
defends against. Sealing afterwards keeps writes a bare insert.

`AuditCheckpoint` records head hash and entry count, which catches a log that was truncated
**and resealed from scratch** — the one case the chain alone verifies as perfect.

**Stated limit:** rows written since the last seal carry no protection. `verify` returns
`unsealed_entries` so an "ok" is never mistaken for full coverage.

---

## 4. Architecture

```
┌──────────────────────── Browser (all cryptography) ─────────────────────────┐
│  identity.js   ratchet.js   hybrid.js   aead.js   keylock.js   pqsign(JS n/a)│
│  Private keys in IndexedDB, optionally Argon2id-wrapped                      │
└────────────────────────────────┬─────────────────────────────────────────────┘
                                 │  sealed envelopes only
┌────────────────────────────────▼─────────────────────────────────────────────┐
│  nginx  ·  TLS termination, gzip_static, immutable asset caching             │
└────────────────────────────────┬─────────────────────────────────────────────┘
┌────────────────────────────────▼─────────────────────────────────────────────┐
│  FastAPI / uvicorn (1 worker)                                                │
│  hybrid.py  pqc.py  pqsign.py  ratchet.py  pki.py  transparency.py           │
│  audit_chain.py  webauthn.py                                                 │
│  Holds: ciphertext, public keys, metadata. Holds no message key.             │
└────────────────────────────────┬─────────────────────────────────────────────┘
                    PostgreSQL   ·   Redis   ·   liboqs (/opt/prahari/_oqs)
```

**The governing invariant:** the relay is blind. Every feature is designed by asking what
it would leak to the server and arranging for the answer to be "nothing beyond metadata".
This is why reactions are indistinguishable envelopes rather than typed columns, why
preferences live in IndexedDB rather than a table, and why the VPN control plane stores a
sealed blob it cannot open.

---

## 5. Security properties and their limits

Stated as prominently as the guarantees, and mirrored in the product UI.

| Property | Status | Limit |
|---|---|---|
| Server cannot read messages | Enforced by architecture | Metadata is visible: accounts, membership, timestamps, sizes |
| Forward secrecy (2-party) | Per message | — |
| Forward secrecy (group) | Per epoch | A compromised epoch key exposes that epoch |
| Key transparency | Tamper-evident | Catches a *changed* answer, never a *first* one |
| Hybrid PKI | Both signatures required | This server cannot issue; key custody is external |
| Attestation | Drift detection | **Self-reported** — no hardware root of trust |
| VPN keying | PSK sealed with PQC | Does **not** make WireGuard post-quantum |
| Endpoint revocation | Immediate | Does not reach the airframe or recover captured keys |
| Duress passcode | Wipes this browser | Not the server, other devices, or exported backups |
| At-rest key lock | Defeats a stolen laptop | Not XSS in an unlocked session |
| Audit chain | Detects edits/deletion | Unsealed rows are unprotected |
| ML-KEM side channels | Constant-time in prod | kyber-py in dev is **not** constant-time |

---

## 6. Benchmark results

Measured on the deployment host — 2 vCPU shared VM, under `CPUQuota=45%`, `nice -n 19`.
Medians over 25–50 rounds after a warm-up call.

### 6.1 liboqs (production configuration)

| Operation | Median | Min |
|---|---:|---:|
| ML-KEM-768 keygen | 0.104 ms | 0.098 ms |
| ML-KEM-768 encapsulate | 0.104 ms | 0.099 ms |
| ML-KEM-768 decapsulate | 0.102 ms | 0.090 ms |
| X25519 keygen | 0.060 ms | 0.055 ms |
| X25519 shared secret | 0.063 ms | 0.058 ms |
| **Hybrid bundle keygen** | **0.218 ms** | 0.192 ms |
| **Hybrid initiate (encap + HKDF)** | **0.367 ms** | 0.329 ms |
| **Hybrid respond (decap + HKDF)** | **0.337 ms** | 0.290 ms |
| Ed25519 sign | 0.052 ms | 0.052 ms |
| Ed25519 verify | 0.207 ms | 0.168 ms |
| ML-DSA-65 keygen | 0.304 ms | 0.262 ms |
| ML-DSA-65 sign | 1.784 ms | 0.418 ms |
| ML-DSA-65 verify | 0.267 ms | 0.229 ms |
| AES-256-GCM encrypt 1 KiB | 0.018 ms | 0.017 ms |
| Argon2id (t=2, m=19 MiB) | 249.7 ms | 132.5 ms |

### 6.2 Backend comparison — the cost of constant-time

| Operation | kyber-py (pure Python) | liboqs (native) | Speed-up |
|---|---:|---:|---:|
| ML-KEM-768 keygen | 5.875 ms | 0.104 ms | **56×** |
| ML-KEM-768 encapsulate | 8.088 ms | 0.104 ms | **78×** |
| ML-KEM-768 decapsulate | 10.809 ms | 0.102 ms | **106×** |
| Hybrid respond | 10.861 ms | 0.337 ms | **32×** |

This is why production **refuses to start** on the pure-Python backend. It is not only
~78× slower; it is documented as research grade and not constant-time.

### 6.3 Performance overhead of going post-quantum

| Metric | Classical only | Hybrid (X25519 + ML-KEM-768) | Overhead |
|---|---:|---:|---:|
| Key agreement, initiator | 0.063 ms | 0.367 ms | **+0.30 ms** |
| Public key on the wire | 32 B | 1216 B | **+1184 B** |
| Ciphertext on the wire | 32 B | 1120 B | **+1088 B** |

**Interpretation.** The computational overhead is ~0.3 ms per session establishment —
negligible against the ~250 ms Argon2id already spent on a single login. The real cost is
**bandwidth**: a handshake grows from ~64 bytes to ~2.3 KB. For a messaging system where
sessions are long-lived and rotate hourly, this is paid rarely. For a protocol
renegotiating per request it would matter considerably.

**Argon2id dominates everything.** At 250 ms it is ~700× the cost of a full hybrid
handshake. Any performance work should start there, not at the PQC layer.

### 6.4 Object sizes

| Object | Size |
|---|---:|
| ML-KEM-768 encapsulation key | 1184 B |
| ML-KEM-768 ciphertext | 1088 B |
| ML-DSA-65 public key | 1952 B |
| ML-DSA-65 signature | 3309 B |
| X25519 public key | 32 B |
| Ed25519 signature | 64 B |

A hybrid certificate therefore costs ~5.3 KB against ~100 B for a classical one — the
reason certificates are fetched by serial rather than listed in bulk.

---

## 7. Gaps — what is not implemented

Stated plainly because a report that omits them is not an analysis.

### 7.1 Hybrid TLS handshakes — **not implemented**

This is the largest divergence from the brief.

PRAHARI performs its hybrid key exchange at the **application layer**: envelopes are sealed
in the browser and remain sealed through TLS, nginx and the database. TLS itself is
terminated by Cloudflare and nginx using **classical** X25519/ECDSA.

The practical consequence is narrower than it sounds. Message confidentiality does not
depend on TLS — a recorded TLS session yields only ciphertext the recorded traffic cannot
open. What TLS protects is metadata and session tokens, and those *would* be exposed to a
future quantum adversary who recorded traffic today.

Closing it properly means terminating TLS with a hybrid group (`X25519MLKEM768`, now
supported by BoringSSL/OpenSSL 3.5 and enabled by default in current Chrome and Firefox).
That is an infrastructure change at the nginx/Cloudflare layer, not an application change.

### 7.2 PQC proxy — **not implemented**

No standalone proxy terminating PQC on behalf of legacy backends exists. The architecture
made it redundant — PQC is native to the application rather than bolted on — but as a
discrete deliverable it is absent.

### 7.3 Benchmark dashboard — **not implemented**

`scripts/benchmark_crypto.py` produces the numbers in §6 as a CLI table. There is no UI.

### 7.4 Hardware acceleration — **partial**

liboqs selects AVX2 implementations where the CPU provides them, and AES-256-GCM uses
AES-NI through OpenSSL. Neither is explicitly configured, measured per-instruction-set, or
compared against a baseline build.

### 7.5 Side-channel analysis — **partial**

Production is *forced* onto the constant-time liboqs backend, and constant-time comparison
(`hmac.compare_digest`) is used for attestation digests and WebAuthn challenges. No timing
analysis, power analysis, or cache-timing measurement has been performed. Claiming
side-channel resistance on that basis would be unfounded.

### 7.6 A latent fault found while writing this report

`pqc.get_backend()` read `os.getenv("PQC_BACKEND")` directly, while that variable is only
populated as a side effect of `get_settings()`. Any code path that reached the KEM *before*
settings loaded silently received the **pure-Python, non-constant-time** backend, with
nothing logged.

Production was unaffected — `main.py` loads settings at import, and `config.py` refuses to
start in production on a non-liboqs backend — but the benchmark script hit it, which is how
it surfaced. `get_backend()` now resolves through the settings object. Fixed and deployed.

---

## 8. Bonus innovation detail

### 8.1 Quantum VPN — *control plane*

`api/vpn.py` · `frontend/src/crypto/vpnPsk.js`

WireGuard's handshake is X25519 and falls to a quantum adversary. It also mixes in an
optional **32-byte pre-shared key**, and a tunnel whose PSK an attacker never obtained stays
secure even when the X25519 half does not.

So the PSK is generated **in the browser**, sealed to the gateway's published
X25519 + ML-KEM-768 bundle using the same hybrid KEM as messaging, and handed to the control
plane as ciphertext. Rendered configs leave `PrivateKey` and `PresharedKey` as placeholders.

**Deliberately not a data plane.** Terminating tunnels is a sustained CPU and interrupt cost
on a host shared with other production services. PRAHARI decides who may join, allocates
addresses (O(1) counter-based), carries sealed keys and revokes access; WireGuard runs
elsewhere.

**Precise claim:** this does not make WireGuard post-quantum. It distributes the one input
that gives WireGuard post-quantum resistance, over a channel that already has it, without
the control plane learning that input.

### 8.2 PQC-enabled IoT — *implemented*

UAV endpoints are **not a special case**. Each aircraft holds its own Ed25519 identity,
publishes a signed X25519 + ML-KEM-768 bundle, and establishes the same two-party hybrid
session as a human peer. Telemetry travels as AES-256-GCM envelopes the server cannot open.

Added on top: containment (quarantine / revoke / restore, tearing down sessions *and* live
WebSockets), and firmware attestation.

### 8.3 Hybrid PKI — *implemented*

Every certificate is signed **twice over identical bytes** — Ed25519 and ML-DSA-65 — and
**both must verify**.

That "both" is the entire design. Accepting either would leave the chain as strong as
whichever algorithm breaks first, since an attacker chooses which to forge. `verify_certificate`
has no early-success path, and there are mirror tests for each half failing alone.

This server **cannot issue** a certificate. It stores, verifies and serves ones signed
elsewhere; trusting a root is an administrator action, never something a submission claims.

### 8.4 Secure firmware updates — *implemented*

The image never touches the server. What is published is a **SHA-256 digest plus an Ed25519
signature over it**, bound to fleet *and* version — so an approval for a test fleet cannot
be replayed as approval for production. Versions are immutable, so an endpoint that verified
`4.2.0` can rely on what that name means.

Closes the loop with attestation: the approved digest and the reported measurement are the
same value, so `/firmware/available` answers "do I need to update?" exactly.

### 8.5 Quantum-safe blockchain integration — *partial*

Merkle anchor roots are signed with **ML-DSA-65** over the root *and* its leaf count, so a
one-leaf batch and a thousand-leaf batch are not interchangeable in an attestation.

A Merkle root is a hash and already survives Grover at 128-bit security. What does not
survive is the *signature* attesting who produced it — and anchors are checked years later,
which is exactly the forgery window.

**Partial** because Polygon publication remains optional and unconfigured, and the on-chain
transaction itself would use the chain's classical signature scheme, which is outside this
system's control.

---

## 9. Evaluation against the stated metrics

### Security strength
Category-3 PQC throughout (ML-KEM-768, ML-DSA-65), hybrid so a single algorithmic break is
insufficient, constant-time implementation enforced in production, per-message forward
secrecy for two-party channels. Weakest points are documented in §5 and §7 rather than
omitted.

### Performance overhead
+0.30 ms per session establishment, +2.2 KB per handshake. Argon2id costs ~700× more than
the entire hybrid exchange. Post-quantum cryptography is **not** the bottleneck in this
system.

### Compatibility
Runs unmodified in current browsers with no plugin. Two interchangeable KEM backends. Node
and Python implementations verified byte-compatible via shared test vectors
(`ratchet_py_vectors.json`, `key_transparency_vectors.json`). Falls back gracefully where
liboqs is unavailable.

### Scalability
Designed for 1000 endpoints. Pagination on every list endpoint, O(1) address allocation,
WebSocket fan-out rather than polling, connection cap, DB pool sized for the host. CPU-bound
work moved off the event loop behind a capacity limiter — measured 4.1× on concurrent
password hashing.

### Architecture quality
One hybrid handshake reused by messaging, aircraft links and VPN keying rather than three
implementations. One envelope format for every conversation verb. Single choke point for
channel authorisation. 306 tests. Every non-obvious decision carries a comment explaining
the constraint that forced it.

### Documentation
This report, auto-generated OpenAPI for all 93 routes, module-level docstrings stating what
each component cannot do, and in-product security claims listing limits as prominently as
guarantees.

---

## 10. Reproducing the measurements

```bash
# Local (development backend)
cd backend && PYTHONPATH=. ./.venv/bin/python scripts/benchmark_crypto.py

# Deployment host — always under a CPU cap; the box is shared
ssh <host> 'export LD_LIBRARY_PATH=/opt/prahari/_oqs/lib OQS_INSTALL_PATH=/opt/prahari/_oqs
  systemd-run --scope -q -p CPUQuota=45% -- nice -n 19 \
    bash -c "cd /opt/prahari/app/backend && PYTHONPATH=. ./.venv/bin/python scripts/benchmark_crypto.py"'

# Test suites
cd backend  && ./.venv/bin/python -m pytest -q     # 200 passed, 1 skipped
cd frontend && npm test                            # 106 passed
```

---

## 11. Source map

| Concern | Backend | Frontend |
|---|---|---|
| Hybrid KEM | `app/crypto/hybrid.py` | `src/crypto/hybrid.js` |
| ML-KEM backends | `app/crypto/pqc.py` | via `@noble/post-quantum` |
| ML-DSA | `app/crypto/pqsign.py` | — |
| AEAD | `app/crypto/aead.py` | `src/crypto/aead.js` |
| Double Ratchet | `app/crypto/ratchet.py` | `src/crypto/ratchet.js` |
| Identity / signatures | `app/crypto/identity.py` | `src/crypto/identity.js` |
| Key transparency | `app/transparency.py` | `src/crypto/transparency.js` |
| Hybrid PKI | `app/pki.py`, `app/api/pki.py` | — |
| Audit chain | `app/audit_chain.py` | — |
| WebAuthn | `app/crypto/webauthn.py` | `src/crypto/passkey.js` |
| VPN keying | `app/api/vpn.py` | `src/crypto/vpnPsk.js` |
| Firmware | `app/api/firmware.py` | — |
| Benchmarks | `scripts/benchmark_crypto.py` | — |
