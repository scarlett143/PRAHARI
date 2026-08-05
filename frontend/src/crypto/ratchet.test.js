/**
 * Double Ratchet behaviour, run under `node --test`.
 *
 * These are the tests that decide whether the ratchet can be trusted, so they assert the
 * security properties directly -- key uniqueness, forward secrecy, break-in recovery,
 * header authentication -- and not merely that a message round-trips.
 */
import assert from "node:assert/strict";
import test from "node:test";

import { x25519 } from "@noble/curves/ed25519.js";

import { base64ToBytes, bytesToBase64 } from "./bytes.js";
import {
  HEADER_BYTES,
  MAX_SKIP,
  RatchetError,
  decodeHeader,
  deserializeState,
  initReceiver,
  initSender,
  ratchetDecrypt,
  ratchetEncrypt,
  serializeState,
} from "./ratchet.js";

const CONTEXT = { senderId: "alice", channelId: "chan-1", epoch: 0 };
const SHARED = new Uint8Array(32).fill(7);

/** Alice sends first; Bob's long-term X25519 key bootstraps the ratchet. */
async function pair() {
  const bobKeys = x25519.keygen();
  const alice = await initSender(SHARED, bobKeys.publicKey);
  const bob = initReceiver(SHARED, bobKeys);
  return { alice, bob };
}

const headerOf = (envelopeB64) =>
  decodeHeader(base64ToBytes(envelopeB64).slice(1, 1 + HEADER_BYTES));

test("a message round-trips from sender to receiver", async () => {
  const { alice, bob } = await pair();
  const envelope = await ratchetEncrypt(alice, "hello aircraft", CONTEXT);
  assert.equal(await ratchetDecrypt(bob, envelope, CONTEXT), "hello aircraft");
});

test("the receiver cannot send until it has received", async () => {
  const { bob } = await pair();
  await assert.rejects(() => ratchetEncrypt(bob, "too early", CONTEXT), {
    code: "no_sending_chain",
  });
});

test("every message uses a different key", async () => {
  const { alice, bob } = await pair();
  const first = await ratchetEncrypt(alice, "same text", CONTEXT);
  const second = await ratchetEncrypt(alice, "same text", CONTEXT);

  // Identical plaintext under a per-epoch key would differ only by nonce; under a
  // ratchet the whole ciphertext is unrelated.
  assert.notEqual(first, second);
  assert.equal(headerOf(first).messageNumber, 0);
  assert.equal(headerOf(second).messageNumber, 1);
  assert.equal(await ratchetDecrypt(bob, first, CONTEXT), "same text");
  assert.equal(await ratchetDecrypt(bob, second, CONTEXT), "same text");
});

test("a message key does not survive its own use (forward secrecy)", async () => {
  const { alice, bob } = await pair();
  const envelope = await ratchetEncrypt(alice, "burn after reading", CONTEXT);
  assert.equal(await ratchetDecrypt(bob, envelope, CONTEXT), "burn after reading");

  // Replaying it finds no key: the chain has moved on and nothing was retained.
  await assert.rejects(() => ratchetDecrypt(bob, envelope, CONTEXT));
});

test("conversation flips direction and both sides follow", async () => {
  const { alice, bob } = await pair();
  await ratchetDecrypt(bob, await ratchetEncrypt(alice, "ping", CONTEXT), CONTEXT);

  const reply = await ratchetEncrypt(bob, "pong", CONTEXT);
  assert.equal(await ratchetDecrypt(alice, reply, CONTEXT), "pong");

  const again = await ratchetEncrypt(alice, "ping 2", CONTEXT);
  assert.equal(await ratchetDecrypt(bob, again, CONTEXT), "ping 2");
});

test("a direction flip changes the ratchet public key", async () => {
  const { alice, bob } = await pair();
  const first = await ratchetEncrypt(alice, "one", CONTEXT);
  await ratchetDecrypt(bob, first, CONTEXT);
  const reply = await ratchetEncrypt(bob, "two", CONTEXT);
  await ratchetDecrypt(alice, reply, CONTEXT);
  const third = await ratchetEncrypt(alice, "three", CONTEXT);

  assert.notEqual(
    bytesToBase64(headerOf(first).ratchetPublic),
    bytesToBase64(headerOf(third).ratchetPublic),
    "alice must ratchet to a new keypair after receiving",
  );
});

test("the root key keeps changing across flips (break-in recovery)", async () => {
  const { alice, bob } = await pair();
  const roots = new Set([bytesToBase64(alice.rootKey)]);

  for (let round = 0; round < 3; round += 1) {
    await ratchetDecrypt(bob, await ratchetEncrypt(alice, `a${round}`, CONTEXT), CONTEXT);
    await ratchetDecrypt(alice, await ratchetEncrypt(bob, `b${round}`, CONTEXT), CONTEXT);
    roots.add(bytesToBase64(alice.rootKey));
  }
  assert.equal(roots.size, 4, "each flip must advance the root key");
});

test("out-of-order messages within a chain still decrypt", async () => {
  const { alice, bob } = await pair();
  const first = await ratchetEncrypt(alice, "first", CONTEXT);
  const second = await ratchetEncrypt(alice, "second", CONTEXT);
  const third = await ratchetEncrypt(alice, "third", CONTEXT);

  assert.equal(await ratchetDecrypt(bob, third, CONTEXT), "third");
  assert.equal(await ratchetDecrypt(bob, first, CONTEXT), "first");
  assert.equal(await ratchetDecrypt(bob, second, CONTEXT), "second");
});

test("a message from a previous chain arrives after the flip", async () => {
  const { alice, bob } = await pair();
  const stale = await ratchetEncrypt(alice, "sent before the flip", CONTEXT);
  await ratchetDecrypt(bob, await ratchetEncrypt(alice, "delivered first", CONTEXT), CONTEXT);

  // Bob replies, flipping the ratchet, and only then does the older message land.
  await ratchetDecrypt(alice, await ratchetEncrypt(bob, "reply", CONTEXT), CONTEXT);
  await ratchetDecrypt(bob, await ratchetEncrypt(alice, "after", CONTEXT), CONTEXT);

  assert.equal(await ratchetDecrypt(bob, stale, CONTEXT), "sent before the flip");
});

test("a gap larger than MAX_SKIP is refused rather than derived", async () => {
  const { alice, bob } = await pair();
  for (let i = 0; i < MAX_SKIP + 2; i += 1) await ratchetEncrypt(alice, `m${i}`, CONTEXT);
  const far = await ratchetEncrypt(alice, "far future", CONTEXT);

  await assert.rejects(() => ratchetDecrypt(bob, far, CONTEXT), {
    code: "too_many_skipped",
  });
});

test("tampering with the message number is detected", async () => {
  const { alice, bob } = await pair();
  await ratchetDecrypt(bob, await ratchetEncrypt(alice, "one", CONTEXT), CONTEXT);
  const envelope = await ratchetEncrypt(alice, "two", CONTEXT);

  const wire = base64ToBytes(envelope);
  wire[1 + 32 + 7] ^= 0x01; // last byte of the message number
  await assert.rejects(() => ratchetDecrypt(bob, bytesToBase64(wire), CONTEXT));
});

test("tampering with the ratchet public key is detected", async () => {
  const { alice, bob } = await pair();
  const envelope = await ratchetEncrypt(alice, "one", CONTEXT);
  const wire = base64ToBytes(envelope);
  wire[1] ^= 0x01; // first byte of the ratchet public key
  await assert.rejects(() => ratchetDecrypt(bob, bytesToBase64(wire), CONTEXT));
});

test("a message bound to another channel does not decrypt", async () => {
  const { alice, bob } = await pair();
  const envelope = await ratchetEncrypt(alice, "for channel one", CONTEXT);
  await assert.rejects(() =>
    ratchetDecrypt(bob, envelope, { ...CONTEXT, channelId: "chan-2" }),
  );
});

test("a message bound to another sender does not decrypt", async () => {
  const { alice, bob } = await pair();
  const envelope = await ratchetEncrypt(alice, "from alice", CONTEXT);
  await assert.rejects(() => ratchetDecrypt(bob, envelope, { ...CONTEXT, senderId: "mallory" }));
});

test("a forged message does not strand the legitimate one behind it", async () => {
  const { alice, bob } = await pair();
  const real = await ratchetEncrypt(alice, "the real message", CONTEXT);

  const forged = base64ToBytes(real);
  forged[forged.length - 1] ^= 0xff; // break the tag, keep the header intact
  await assert.rejects(() => ratchetDecrypt(bob, bytesToBase64(forged), CONTEXT));

  // The chain must not have advanced past the message that never authenticated.
  assert.equal(await ratchetDecrypt(bob, real, CONTEXT), "the real message");
});

test("state survives a round trip through storage", async () => {
  const { alice, bob } = await pair();
  await ratchetDecrypt(bob, await ratchetEncrypt(alice, "before reload", CONTEXT), CONTEXT);

  const revived = deserializeState(JSON.parse(JSON.stringify(serializeState(bob))));
  const reply = await ratchetEncrypt(revived, "after reload", CONTEXT);
  assert.equal(await ratchetDecrypt(alice, reply, CONTEXT), "after reload");
});

test("skipped keys survive a round trip through storage", async () => {
  const { alice, bob } = await pair();
  const first = await ratchetEncrypt(alice, "one", CONTEXT);
  const second = await ratchetEncrypt(alice, "two", CONTEXT);

  await ratchetDecrypt(bob, second, CONTEXT); // derives and stores the key for "one"
  const revived = deserializeState(JSON.parse(JSON.stringify(serializeState(bob))));
  assert.equal(await ratchetDecrypt(revived, first, CONTEXT), "one");
});

test("two peers starting from different secrets cannot talk", async () => {
  const bobKeys = x25519.keygen();
  const alice = await initSender(new Uint8Array(32).fill(1), bobKeys.publicKey);
  const bob = initReceiver(new Uint8Array(32).fill(2), bobKeys);

  const envelope = await ratchetEncrypt(alice, "hi", CONTEXT);
  await assert.rejects(() => ratchetDecrypt(bob, envelope, CONTEXT));
});

test("a long alternating conversation stays in sync", async () => {
  const { alice, bob } = await pair();
  for (let i = 0; i < 25; i += 1) {
    assert.equal(
      await ratchetDecrypt(bob, await ratchetEncrypt(alice, `a${i}`, CONTEXT), CONTEXT),
      `a${i}`,
    );
    assert.equal(
      await ratchetDecrypt(alice, await ratchetEncrypt(bob, `b${i}`, CONTEXT), CONTEXT),
      `b${i}`,
    );
  }
});

test("a long one-sided burst stays in sync", async () => {
  const { alice, bob } = await pair();
  const envelopes = [];
  for (let i = 0; i < 50; i += 1) envelopes.push(await ratchetEncrypt(alice, `m${i}`, CONTEXT));
  for (let i = 0; i < 50; i += 1) {
    assert.equal(await ratchetDecrypt(bob, envelopes[i], CONTEXT), `m${i}`);
  }
});

test("RatchetError carries a machine-readable code", async () => {
  const { bob } = await pair();
  await assert.rejects(
    () => ratchetEncrypt(bob, "x", CONTEXT),
    (error) => error instanceof RatchetError && error.code === "no_sending_chain",
  );
});
