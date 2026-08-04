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
