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
