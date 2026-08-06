import test from "node:test";
import assert from "node:assert/strict";

import { isLocked, lockIdentity, unlockIdentity } from "./keylock.js";
import { generateIdentity } from "./identity.js";

const TIMEOUT = 120_000;
const PASSCODE = "a-device-passcode";

test("a locked identity round-trips", { timeout: TIMEOUT }, async () => {
  const identity = generateIdentity();
  const record = await lockIdentity(identity, "alice", PASSCODE);
  const opened = await unlockIdentity(record, PASSCODE);

  assert.deepEqual(opened, identity);
});

test("the stored record holds no key material in the clear", { timeout: TIMEOUT }, async () => {
  const identity = generateIdentity();
  const record = await lockIdentity(identity, "alice", PASSCODE);
  const serialised = JSON.stringify(record);

  for (const secret of [identity.ed25519Secret, identity.x25519Secret, identity.mlKemSecret]) {
    assert.ok(!serialised.includes(secret), "a private key survived into the locked record");
  }
  // Public halves must not leak either: they identify the account to anyone reading
  // storage, even though they are not secret.
  assert.ok(!serialised.includes(identity.ed25519Public));
});

test("the wrong passcode does not open it", { timeout: TIMEOUT }, async () => {
  const record = await lockIdentity(generateIdentity(), "alice", PASSCODE);
  await assert.rejects(() => unlockIdentity(record, "not the passcode"), /Wrong passcode/);
});

test("a record cannot be retargeted at another account", { timeout: TIMEOUT }, async () => {
  const record = await lockIdentity(generateIdentity(), "alice", PASSCODE);
  const tampered = { ...record, username: "mallory" };

  await assert.rejects(() => unlockIdentity(tampered, PASSCODE), /Wrong passcode/);
});

test("the KDF cost cannot be downgraded", { timeout: TIMEOUT }, async () => {
  const record = await lockIdentity(generateIdentity(), "alice", PASSCODE);
  const tampered = { ...record, kdf: { ...record.kdf, t: 1, m: 8 } };

  await assert.rejects(() => unlockIdentity(tampered, PASSCODE));
});

test("altered ciphertext is rejected", { timeout: TIMEOUT }, async () => {
  const record = await lockIdentity(generateIdentity(), "alice", PASSCODE);
  const bytes = Buffer.from(record.ciphertext, "base64");
  bytes[3] ^= 0xff;

  await assert.rejects(
    () => unlockIdentity({ ...record, ciphertext: bytes.toString("base64") }, PASSCODE),
    /Wrong passcode/,
  );
});

test("locked and unlocked records are told apart", { timeout: TIMEOUT }, async () => {
  const identity = generateIdentity();
  assert.equal(isLocked(identity), false, "a bare identity is not locked");
  assert.equal(isLocked(null), false);
  assert.equal(isLocked(undefined), false);
  assert.equal(isLocked(await lockIdentity(identity, "alice", PASSCODE)), true);
});

test("a short passcode is refused", { timeout: TIMEOUT }, async () => {
  await assert.rejects(
    () => lockIdentity(generateIdentity(), "alice", "short"),
    /at least 8 characters/,
  );
});

test("unlocking something that is not locked is an error", { timeout: TIMEOUT }, async () => {
  await assert.rejects(() => unlockIdentity(generateIdentity(), PASSCODE), /not locked/);
});
