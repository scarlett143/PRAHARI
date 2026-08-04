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

Open **Merkle Proofs**, create a batch, and show leaf count, Merkle root, and explicit local/chain status. If Polygon is configured, show the real transaction hash. If not, explicitly state that no transaction is claimed.

## 8. Quantum Security Lab

Run the lab with intercept rate 0%, then 100%. Show backend name, QRNG bias when Aer is installed, BB84 QBER, and PASS/FAIL. Explain that the module is supplementary and does not supply the sole secret key.
