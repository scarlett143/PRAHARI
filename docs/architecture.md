# PRAHARI Architecture

## Trust boundary

The browser is the cryptographic endpoint. FastAPI is an authenticated routing/storage service and never receives Ed25519, X25519, ML-KEM, or session private keys.

```text
Alice browser                                  Bob browser
Ed25519 private                               Ed25519 private
X25519 private                                X25519 private
ML-KEM secret                                 ML-KEM secret
session key                                   session key
      |                                              ^
      | signed public bundles / public offer         |
      v                                              |
                 FastAPI + PostgreSQL
        users / public keys / memberships
        public hybrid session offer
        opaque AES-GCM message envelopes
        audit metadata / Merkle batch metadata
```

## Identity publication

Registration uploads only the Ed25519 public key. After JWT authentication, the server returns a random challenge. The browser signs that challenge and separately signs a canonical X25519 + ML-KEM public bundle. The server verifies both signatures before setting `key_verified=true`.

This separates account authentication from confidential session establishment and cryptographically binds the published KEM material to the identity key.

## Hybrid session

For a two-member channel, members are sorted by username so one deterministic initiator is selected. This avoids two simultaneous, incompatible offers.

The initiator:

1. verifies the peer's Ed25519-signed public bundle;
2. generates an ephemeral X25519 keypair;
3. computes X25519(ephemeral_private, responder_static_public);
4. ML-KEM-768 encapsulates to the responder's public KEM key;
5. concatenates the two shared secrets;
6. derives a 32-byte session key with HKDF-SHA256;
7. binds responder public keys + X25519 ephemeral public + ML-KEM ciphertext into HKDF `info`;
8. signs the public session offer with Ed25519 and uploads only that signed public offer.

The responder uses its local X25519 and ML-KEM private material to derive the same key.

## Message envelope

AES-256-GCM is performed with WebCrypto in the frontend. Associated data is:

```text
prahari-v1 | sender_id | channel_id | key_epoch
```

The backend receives a versioned wire envelope containing only nonce + ciphertext/tag. It stores a SHA-256 content hash for proof batching, but has no session key.

## Epoch rotation

The current MVP is an epoch model rather than a Double Ratchet. An epoch expires after 100 accepted messages or 15 minutes by default. Once a threshold is reached, the backend rejects new messages until a channel member rotates to the next epoch and a fresh hybrid offer is established.

## Merkle proof layer

Unanchored message content hashes are domain-separated into leaves and combined into a binary SHA-256 Merkle tree. One root represents up to 100 messages by default. Polygon submission is optional and fails closed; local proofs remain usable without pretending that a transaction occurred.

## Quantum demo layer

The optional QRNG path uses Qiskit Aer when installed. BB84 is presented as a protocol simulation with QBER metrics. Quantum output is mixed with local system entropy only for experiments; it never replaces local CSPRNG secrecy.

## Unmanned endpoints

An aircraft is not a special case of the protocol. It is an ordinary peer:

- it generates Ed25519, X25519 and ML-KEM-768 private keys locally, in a keystore
  file that never leaves the airframe;
- it publishes a signed public bundle through the same `/keys/publish` path a
  browser uses;
- it joins a two-member channel with its operator and runs the same deterministic
  initiator rule, the same signed session offer, and the same HKDF derivation;
- its telemetry and the operator's commands travel as the same AES-256-GCM
  envelopes, with the same `prahari-v1 | sender | channel | epoch` associated data.

Nothing downstream of identity knows whether it is talking to a person or an
airframe, which is the point: there is one protocol to review, one to test, and
one to get right.

### Provisioning and credentials

An aircraft holds no password, so the credential chain is:

1. **Provision** — the operator creates the record; the server returns a 256-bit
   enrolment token once and stores only its SHA-256 hash.
2. **Enrol** — the aircraft redeems that token and binds its real Ed25519 public
   key. The token is cleared on use.
3. **Re-authenticate** — thereafter the aircraft requests a nonce and signs it
   with the enrolment-bound Ed25519 key to obtain a fresh access token. The nonce
   is single-use, so a captured signature cannot be replayed.

The device-authentication nonce is stored separately from `User.pending_challenge`
so that token renewal and key publication cannot clobber one another.

### What the server learns

The same class of metadata it already learns about human accounts: a callsign, an
owner, a fleet label, liveness, ciphertext sizes, and timestamps. Position,
attitude, battery state and commands are inside the envelope and are decrypted
only in the operator's browser — the ground console renders telemetry the backend
could not have rendered for it.

## Handshake transcript binding

The HKDF `info` is `KDF_LABEL || SHA-256(KDF_LABEL || responder bundle || ciphertext)`.

The raw transcript is 2336 bytes because ML-KEM-768 keys and ciphertexts are
large, and OpenSSL-backed HKDF implementations reject an `info` longer than 1024
bytes. Hashing first preserves the binding while keeping the derivation portable
to Node, Deno, Bun, React Native and any embedded or FPGA-side reimplementation —
which matters directly for the aircraft side of the link.
