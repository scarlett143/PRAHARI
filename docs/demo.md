# Final Demo Script

## 1. Identity

Open two browser profiles. Register `alice` and `bob`. Show that each browser locally generates Ed25519, X25519, and ML-KEM-768 private material, while `/api/v2/keys/{username}` exposes public material only.

## 2. Verified public keys

Show registration followed by the signed challenge and signed bundle publication. Point out `key_verified=true`.

## 3. Hybrid session

Alice creates `Secure Demo`, adds Bob, and both open `#general`. Show the session state indicating X25519 + ML-KEM-768 and Epoch 0.

## 4. Real encrypted message

Send:

```text
Post-quantum encrypted hello!
```

Bob sees plaintext locally. Inspect the API/DB message record and show that it contains an opaque `envelope`, epoch, hash, sender/channel IDs, and timestamps — not the sentence.

## 5. Tamper proof

Use the backend AES-GCM test or browser devtools to alter one ciphertext byte. Decryption must display `MESSAGE AUTHENTICATION FAILED`.

## 6. Epoch rotation

Click **Rotate epoch**. Confirm Epoch 1 appears and a new hybrid offer/session key is established. Send another message.

## 7. Merkle batch

Open **Proofs**, create a batch, and show leaf count, Merkle root, and explicit local/chain status. If Polygon is configured, show the real transaction hash. If not, explicitly state that no transaction is claimed.

## 8. Quantum Security Lab

Run the lab with intercept rate 0%, then 100%. Show backend name, QRNG bias when Aer is installed, BB84 QBER, and PASS/FAIL. Explain that the module is supplementary and does not supply the sole secret key.

## 9. Encrypted UAV link

Open **Fleet**. Provision `UAV-001` and copy the one-time enrolment token; point
out that the server keeps only its SHA-256 hash.

Start the bridge:

```bash
python -m prahari_bridge --callsign UAV-001 --enrollment-token <token> --source synthetic
```

Show that the aircraft generates its own Ed25519 / X25519 / ML-KEM-768 keys into
a local keystore and publishes only public material — the same `/keys/publish`
path Alice and Bob used.

Click **Establish link**, restart the bridge with `--channel-id`, then open the
aircraft's console. Telemetry populates the track display and the charts.

The point to land: **this is the same protocol as the Alice/Bob channel.** Same
deterministic initiator rule, same signed offer, same AES-256-GCM envelopes. Show
a stored envelope in the database and confirm no coordinate or field name is
recoverable from it — the console decrypted it, the server never could.

Send **Return to launch** from the console and show the command arriving decrypted
at the aircraft. Rotate the epoch and show the link re-establishing.

For real MAVLink, run ArduPilot SITL and restart with
`--source sitl --device udpin:127.0.0.1:14550`; the raw wire frames are carried
inside the envelopes, so it is a true encrypted MAVLink tunnel.
