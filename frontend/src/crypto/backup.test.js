import test from "node:test";
import assert from "node:assert/strict";

import { exportIdentity, importIdentity, backupFilename } from "./backup.js";
import { generateIdentity } from "./identity.js";

/** Argon2id at 64 MiB is deliberately slow; these tests do a handful of derivations. */
const TIMEOUT = 120_000;
const PASSPHRASE = "correct horse battery staple";

test("a backup round-trips to the identical identity", { timeout: TIMEOUT }, async () => {
  const identity = generateIdentity();
  const file = await exportIdentity(identity, "alice", PASSPHRASE);
  const restored = await importIdentity(file, PASSPHRASE);

  assert.equal(restored.username, "alice");
  for (const field of Object.keys(identity)) {
    assert.equal(restored.identity[field], identity[field], `${field} survived the round trip`);
  }
});

test("the file carries no key material in the clear", { timeout: TIMEOUT }, async () => {
  const identity = generateIdentity();
  const file = await exportIdentity(identity, "alice", PASSPHRASE);

  for (const secret of [identity.ed25519Secret, identity.x25519Secret, identity.mlKemSecret]) {
    assert.ok(!file.includes(secret), "a private key appeared in the backup file");
  }
  // The envelope is still readable enough to be diagnosable.
  const parsed = JSON.parse(file);
  assert.equal(parsed.format, "prahari-identity-backup");
  assert.equal(parsed.username, "alice");
  assert.equal(parsed.kdf.name, "argon2id");
});

test("the wrong passphrase does not open it", { timeout: TIMEOUT }, async () => {
  const file = await exportIdentity(generateIdentity(), "alice", PASSPHRASE);
  await assert.rejects(
    () => importIdentity(file, "not the passphrase"),
    /wrong passphrase, or the file has been altered/,
  );
});

test("retargeting the file at another account breaks authentication", { timeout: TIMEOUT }, async () => {
  // The username is bound into the AEAD's additional data, so editing it in the
  // envelope must invalidate the whole file rather than silently install the identity
  // under a different name.
  const file = await exportIdentity(generateIdentity(), "alice", PASSPHRASE);
  const tampered = JSON.parse(file);
  tampered.username = "mallory";

  await assert.rejects(
    () => importIdentity(JSON.stringify(tampered), PASSPHRASE),
    /wrong passphrase, or the file has been altered/,
  );
});

test("downgrading the KDF cost breaks authentication", { timeout: TIMEOUT }, async () => {
  // Otherwise an attacker could rewrite the cost parameters down and brute-force the
  // passphrase cheaply, then present the original file.
  const file = await exportIdentity(generateIdentity(), "alice", PASSPHRASE);
  const tampered = JSON.parse(file);
  tampered.kdf.t = 1;
  tampered.kdf.m = 8;

  await assert.rejects(() => importIdentity(JSON.stringify(tampered), PASSPHRASE));
});

test("altered ciphertext is rejected", { timeout: TIMEOUT }, async () => {
  const file = await exportIdentity(generateIdentity(), "alice", PASSPHRASE);
  const tampered = JSON.parse(file);
  const bytes = Buffer.from(tampered.ciphertext, "base64");
  bytes[4] ^= 0xff;
  tampered.ciphertext = bytes.toString("base64");

  await assert.rejects(() => importIdentity(JSON.stringify(tampered), PASSPHRASE));
});

test("a mismatched key pair is caught rather than installed", { timeout: TIMEOUT }, async () => {
  // A file that decrypts but whose public key does not belong to its secret would
  // install an identity that fails at the first handshake with nothing to point at.
  const identity = generateIdentity();
  const other = generateIdentity();
  identity.ed25519Public = other.ed25519Public;

  const file = await exportIdentity(identity, "alice", PASSPHRASE);
  await assert.rejects(
    () => importIdentity(file, PASSPHRASE),
    /Ed25519 keys do not belong together/,
  );
});

test("a weak passphrase is refused at export", { timeout: TIMEOUT }, async () => {
  await assert.rejects(
    () => exportIdentity(generateIdentity(), "alice", "short"),
    /at least 12 characters/,
  );
});

test("a foreign file is reported as such", { timeout: TIMEOUT }, async () => {
  await assert.rejects(
    () => importIdentity(JSON.stringify({ format: "something-else" }), PASSPHRASE),
    /not a PRAHARI identity backup/,
  );
  await assert.rejects(() => importIdentity("not json at all", PASSPHRASE), /not a PRAHARI identity backup/);
});

test("the filename names the account and the day", () => {
  const name = backupFilename("alice");
  assert.match(name, /^prahari-identity-alice-\d{4}-\d{2}-\d{2}\.json$/);
});
