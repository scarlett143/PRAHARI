/**
 * The other half of the cross-implementation check.
 *
 * `backend/tests/test_ratchet_interop.py` replays a browser-recorded conversation in
 * Python; this replays a Python-recorded one here. Both directions are tested because a
 * bug in one implementation's *encoder* would go unnoticed if that side only ever
 * produced the vectors and never consumed them.
 *
 * Regenerate with:
 *   cd backend && python scripts/generate_ratchet_vectors.py \
 *       > ../frontend/src/crypto/vectors/ratchet_py_vectors.json
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { x25519 } from "@noble/curves/ed25519.js";

import { base64ToBytes } from "./bytes.js";
import { initReceiver, initSender, ratchetDecrypt } from "./ratchet.js";

const vectors = JSON.parse(
  readFileSync(fileURLToPath(new URL("./vectors/ratchet_py_vectors.json", import.meta.url)), "utf8"),
);

/** Hand back the exact ephemerals the recorded session used, in order. */
function queuedKeygen(secrets) {
  const remaining = [...secrets];
  return () => {
    const encoded = remaining.shift();
    assert.ok(encoded, "ratchet asked for more keypairs than the vector recorded");
    const secretKey = base64ToBytes(encoded);
    return { secretKey, publicKey: x25519.getPublicKey(secretKey) };
  };
}

async function buildPair() {
  const shared = base64ToBytes(vectors.shared_secret);
  const bobIdentity = {
    secretKey: base64ToBytes(vectors.bob_identity_secret),
    publicKey: base64ToBytes(vectors.bob_identity_public),
  };
  const alice = await initSender(
    shared,
    bobIdentity.publicKey,
    queuedKeygen(vectors.alice_keygen_queue),
  );
  const bob = initReceiver(shared, bobIdentity, queuedKeygen(vectors.bob_keygen_queue));
  return { alice, bob };
}

test("the browser decrypts a conversation recorded by the Python implementation", async () => {
  const { alice, bob } = await buildPair();

  for (const message of vectors.messages) {
    const receiver = message.from === "alice" ? bob : alice;
    const plaintext = await ratchetDecrypt(receiver, message.envelope, {
      senderId: message.sender_id,
      channelId: vectors.channel_id,
      epoch: message.epoch,
    });
    assert.equal(plaintext, message.plaintext);
  }
});

test("the vectors actually exercise both directions", () => {
  const senders = new Set(vectors.messages.map((message) => message.from));
  assert.equal(senders.size, 2, "a one-sided script would never test a DH ratchet step");
  assert.equal(vectors.produced_by, "python");
});

test("a Python-produced envelope will not decrypt under another channel", async () => {
  const { bob } = await buildPair();
  const first = vectors.messages[0];

  await assert.rejects(() =>
    ratchetDecrypt(bob, first.envelope, {
      senderId: first.sender_id,
      channelId: "a-different-channel",
      epoch: first.epoch,
    }),
  );
});
