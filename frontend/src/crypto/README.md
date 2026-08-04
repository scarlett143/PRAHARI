# Browser cryptography

This directory is the E2EE trust boundary for PRAHARI:

- `identity.js` — Ed25519 identity, signed public bundles, signed session offers
- `hybrid.js` — X25519 + ML-KEM-768 hybrid agreement and HKDF-SHA256
- `aead.js` — WebCrypto AES-256-GCM envelope encryption/decryption
- `session.js` — deterministic two-party session establishment and local session-key persistence
- `bytes.js` — raw-byte/base64 helpers; transcript inputs never pass through arbitrary UTF-8 conversions

Private keys are persisted in browser IndexedDB by `src/storage/keys.js` and are never uploaded to the backend.
