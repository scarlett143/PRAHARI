/**
 * The browser's chain verification, and its agreement with the server's.
 *
 * The cross-language vectors matter more than they look. If the two implementations
 * disagree by a single byte -- a different domain separator, a field in another order, a
 * length prefix of the wrong width -- then every history fails to verify here, the console
 * shows a tamper warning on every honest peer, and the warning becomes noise that people
 * learn to click past. A transparency log nobody believes is worse than none.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describeHeadChange, verifyKeyHistory } from "./transparency.js";

const vectors = JSON.parse(
  readFileSync(fileURLToPath(new URL("./vectors/key_transparency_vectors.json", import.meta.url))),
);

const byName = (name) => vectors.find((item) => item.name === name);

/** Shape one vector the way the history endpoint returns it. */
const asEntry = (vector) => ({
  seq: vector.seq,
  ed25519_public_key: vector.ed25519_public_key,
  x25519_public_key: vector.x25519_public_key,
  ml_kem_encapsulation_key: vector.ml_kem_encapsulation_key,
  prev_hash: vector.prev_hash,
  entry_hash: vector.entry_hash,
});

test("the browser reproduces the server's entry hashes", async () => {
  const first = byName("first");
  const second = byName("second");

  const result = await verifyKeyHistory({
    user_id: first.user_id,
    entries: [asEntry(first), asEntry(second)],
  });

  assert.equal(result.ok, true, result.reason ?? "");
  assert.equal(result.head, second.entry_hash);
  assert.equal(result.changes, 1, "two entries is one key change");
});

test("the hash binds field boundaries, matching the server", async () => {
  // Same bytes, different split between the fields. Concatenation alone would collide.
  assert.notEqual(byName("boundary-a").entry_hash, byName("boundary-b").entry_hash);
});

test("an altered entry is rejected", async () => {
  const first = byName("first");
  const tampered = { ...asEntry(first), x25519_public_key: btoa("\0".repeat(32)) };

  const result = await verifyKeyHistory({ user_id: first.user_id, entries: [tampered] });
  assert.equal(result.ok, false);
  assert.match(result.reason, /altered/);
});

test("a broken link between entries is rejected", async () => {
  const first = byName("first");
  const second = { ...asEntry(byName("second")), prev_hash: "00".repeat(32) };

  const result = await verifyKeyHistory({
    user_id: first.user_id,
    entries: [asEntry(first), second],
  });
  assert.equal(result.ok, false);
  assert.match(result.reason, /does not follow/);
});

test("a missing entry is rejected rather than silently accepted", async () => {
  const second = byName("second");
  // Serving entry 2 alone is what removing entry 1 looks like from here.
  const result = await verifyKeyHistory({ user_id: second.user_id, entries: [asEntry(second)] });

  assert.equal(result.ok, false);
  assert.match(result.reason, /missing/);
});

test("an account that never published a key is not treated as verified", async () => {
  const result = await verifyKeyHistory({ user_id: "u1", entries: [] });
  assert.equal(result.ok, false);
  assert.equal(result.head, null);
});

test("the server's own verdict is never consulted", async () => {
  const first = byName("first");
  // A hostile relay claiming everything is fine, over a chain that is not.
  const result = await verifyKeyHistory({
    user_id: first.user_id,
    chain_ok: true,
    chain_error: null,
    entries: [{ ...asEntry(first), entry_hash: "ff".repeat(32) }],
  });
  assert.equal(result.ok, false, "chain_ok must carry no weight");
});

test("a moved head is reported, and a first sighting is not", () => {
  assert.deepEqual(describeHeadChange(null, "abc"), { changed: false, first: true });
  assert.deepEqual(describeHeadChange("abc", "abc"), { changed: false, first: false });
  assert.deepEqual(describeHeadChange("abc", "def"), { changed: true, first: false });
});
