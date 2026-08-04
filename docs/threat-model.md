# Threat Model

## Security goals

- Network/server observers should not learn message plaintext from stored message records.
- A modified AES-GCM envelope must fail authentication in the recipient browser.
- A ciphertext replayed into another channel or epoch must fail AAD authentication.
- The server must reject wrong key epochs, duplicate client message IDs, invalid/expired JWTs, suspended accounts, invalid Ed25519 ownership proofs, and invalid signed public-key bundles.
- Private identity and session keys must never be transmitted to FastAPI.
- Merkle batch listing/proof operations must be scoped to channels visible to the authenticated user.

## Trusted components

The current MVP trusts the browser origin, the JavaScript bundle served to the user, the user's endpoint, WebCrypto, and the selected JavaScript cryptographic libraries. Backend account/auth code and database integrity are trusted for availability, identity-directory correctness after verification, and membership authorization, but not for message confidentiality.

## Explicit limitations

### Browser/XSS compromise

Private keys are stored in IndexedDB so they remain off-server. IndexedDB does **not** protect them from malicious JavaScript executing in the PRAHARI origin. CSP, dependency pinning, provenance verification, frontend integrity controls, and eventually hardware-backed/non-extractable key strategies are important deployment work.

### No Double Ratchet

Epoch rotation provides fresh hybrid sessions but does not provide Signal-style per-message forward secrecy, skipped-message keys, break-in recovery, PQXDH, or ML-KEM Braid. Do not describe the MVP as Signal Protocol.

### Two-party channel sessions

The hybrid session layer currently supports exactly two channel members. Extending to secure groups requires a real group-key protocol rather than reusing one two-party key for arbitrary membership.

### Metadata

The backend necessarily sees user accounts, membership, channel IDs, timestamps, ciphertext sizes, and delivery events. E2EE protects content, not all metadata.

### JavaScript ML-KEM side channels

The browser ML-KEM implementation is not claimed constant-time. The reference backend also treats pure-Python ML-KEM as research/demo grade and recommends a native reviewed implementation for deployment.

### Quantum module

The QRNG/BB84 screens are research demonstrations. Cloud-delivered quantum random bits are visible to the provider and are not secret merely because they originated from quantum measurement.

## Out of scope for this deadline

- production-grade key backup/recovery
- device linking
- group E2EE
- full Signal/PQXDH/Double Ratchet/ML-KEM Braid
- real MPC
- production ZKP circuits
- traffic-analysis resistance
- HSM/mobile secure-enclave integration

## Unmanned endpoints

### What is protected

An aircraft holds its own Ed25519, X25519 and ML-KEM-768 private keys and derives
the session key locally. Telemetry and commands are AES-256-GCM envelopes bound to
sender, channel and epoch. A compromised server can deny service, reorder or drop
frames, and observe metadata — it cannot read position, attitude or commands, and
it cannot forge a frame that will authenticate.

### Provisioning trust

The enrolment token is a bearer credential for exactly one provisioned record. It
is single-use, hashed at rest, and grants nothing beyond binding an identity key
to that callsign. An attacker who intercepts a token before the aircraft redeems
it can enrol an impostor under that callsign — so tokens must be delivered over a
trusted channel, and an unexpected `fleet.uav_enrolled` audit event is a signal
worth alerting on.

### Keystore compromise

The keystore file is the aircraft's entire identity. Physical capture of the
airframe yields it, and with it the ability to impersonate that aircraft and to
decrypt sessions it holds keys for. Epoch rotation limits the window but does not
close it: there is no per-message forward secrecy. Hardware-backed key storage on
the airframe is the real mitigation and is not implemented here.

### Not addressed

Nothing in this repository addresses the RF layer: jamming, meaconing, direction
finding, or traffic analysis of the physical link. Those are properties of the
radio and waveform, not of the application protocol. Encrypting the payload does
not make a link hard to find or hard to disrupt.
