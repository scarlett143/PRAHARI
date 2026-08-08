import test from "node:test";
import assert from "node:assert/strict";

import { isLocked, lockIdentity, unlockIdentity } from "./keylock.js";
import { generateIdentity } from "./identity.js";

const TIMEOUT = 120_000;
const PASSCODE = "a-device-passcode";

const DURESS = "the-other-passcode";

test("a locked identity round-trips", { timeout: TIMEOUT }, async () => {
  const identity = generateIdentity();
  const record = await lockIdentity(identity, "alice", PASSCODE);
  const opened = await unlockIdentity(record, PASSCODE);

  assert.deepEqual(opened.identity, identity);
  assert.equal(opened.duress, false);
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

/* -- duress ------------------------------------------------------------------ */

test("the duress passcode reports duress and yields no identity", { timeout: TIMEOUT }, async () => {
  const identity = generateIdentity();
  const record = await lockIdentity(identity, "alice", PASSCODE, DURESS);

  const real = await unlockIdentity(record, PASSCODE);
  assert.deepEqual(real.identity, identity);
  assert.equal(real.duress, false);

  const coerced = await unlockIdentity(record, DURESS);
  assert.equal(coerced.duress, true);
  assert.equal(coerced.identity, null, "the duress slot must never hand back the identity");
});

test("a record does not reveal whether a duress passcode exists", { timeout: TIMEOUT }, async () => {
  // The whole feature rests on this. If the presence of a duress slot were observable,
  // someone compelling the owner to unlock would just demand the other passcode.
  const withDuress = await lockIdentity(generateIdentity(), "alice", PASSCODE, DURESS);
  const without = await lockIdentity(generateIdentity(), "alice", PASSCODE);

  assert.deepEqual(
    Object.keys(withDuress).sort(),
    Object.keys(without).sort(),
    "the two records must have the same shape",
  );
  assert.equal(
    Buffer.from(withDuress.duress_ciphertext, "base64").length,
    Buffer.from(without.duress_ciphertext, "base64").length,
    "and the filler must be the same length as a real duress slot",
  );
});

test("with no duress passcode set, nothing opens the duress slot", { timeout: TIMEOUT }, async () => {
  const record = await lockIdentity(generateIdentity(), "alice", PASSCODE);
  await assert.rejects(() => unlockIdentity(record, DURESS), /Wrong passcode/);
});

test("the two slots cannot be swapped to invert the passcodes", { timeout: TIMEOUT }, async () => {
  // Without the slot label in the AAD, moving the duress ciphertext into the primary
  // position would make the real passcode the one that wipes the device.
  const record = await lockIdentity(generateIdentity(), "alice", PASSCODE, DURESS);
  const swapped = {
    ...record,
    nonce: record.duress_nonce,
    ciphertext: record.duress_ciphertext,
    duress_nonce: record.nonce,
    duress_ciphertext: record.ciphertext,
  };

  await assert.rejects(() => unlockIdentity(swapped, PASSCODE), /Wrong passcode/);
  await assert.rejects(() => unlockIdentity(swapped, DURESS), /Wrong passcode/);
});

test("a duress passcode equal to the unlock passcode is refused", { timeout: TIMEOUT }, async () => {
  await assert.rejects(
    () => lockIdentity(generateIdentity(), "alice", PASSCODE, PASSCODE),
    /must be different/,
  );
});

test("a short duress passcode is refused", { timeout: TIMEOUT }, async () => {
  await assert.rejects(
    () => lockIdentity(generateIdentity(), "alice", PASSCODE, "short"),
    /at least 8 characters/,
  );
});
