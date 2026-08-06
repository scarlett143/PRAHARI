import test from "node:test";
import assert from "node:assert/strict";

import { identityFingerprint, safetyNumber, formatForDisplay } from "./verification.js";
import { generateIdentity } from "./identity.js";

/** Shape a generated identity into the bundle shape the API returns. */
function bundle(identity) {
  return {
    ed25519_public_key: identity.ed25519Public,
    x25519_public_key: identity.x25519Public,
    ml_kem_encapsulation_key: identity.mlKemPublic,
  };
}

test("both sides compute the same safety number regardless of order", () => {
  const alice = bundle(generateIdentity());
  const bob = bundle(generateIdentity());

  // Alice's client passes (self, peer); Bob's passes the reverse. If these differed,
  // every comparison in the product would fail.
  assert.equal(safetyNumber(alice, bob), safetyNumber(bob, alice));
});

test("a substituted key changes the safety number", () => {
  const alice = bundle(generateIdentity());
  const bob = bundle(generateIdentity());
  const relay = bundle(generateIdentity());

  const honest = safetyNumber(alice, bob);
  const intercepted = safetyNumber(alice, relay);
  assert.notEqual(honest, intercepted, "a relay swapping in its own key must be visible");
});

test("changing any one of the three public keys changes the fingerprint", () => {
  const identity = generateIdentity();
  const other = generateIdentity();
  const base = identityFingerprint(bundle(identity));

  assert.notEqual(
    base,
    identityFingerprint({ ...bundle(identity), ed25519_public_key: other.ed25519Public }),
  );
  assert.notEqual(
    base,
    identityFingerprint({ ...bundle(identity), x25519_public_key: other.x25519Public }),
  );
  assert.notEqual(
    base,
    identityFingerprint({ ...bundle(identity), ml_kem_encapsulation_key: other.mlKemPublic }),
  );
});

test("fingerprints and safety numbers are stable across calls", () => {
  const alice = bundle(generateIdentity());
  const bob = bundle(generateIdentity());

  assert.equal(identityFingerprint(alice), identityFingerprint(alice));
  assert.equal(safetyNumber(alice, bob), safetyNumber(alice, bob));
});

test("the rendered form is readable aloud", () => {
  const alice = bundle(generateIdentity());
  const bob = bundle(generateIdentity());

  const number = safetyNumber(alice, bob);
  const groups = number.split(" ");
  assert.equal(groups.length, 12);
  for (const group of groups) assert.match(group, /^\d{5}$/);

  const [top, bottom] = formatForDisplay(number);
  assert.equal(top.split(" ").length, 6);
  assert.equal(bottom.split(" ").length, 6);
});

test("a fingerprint is six groups of five digits", () => {
  const groups = identityFingerprint(bundle(generateIdentity())).split(" ");
  assert.equal(groups.length, 6);
  for (const group of groups) assert.match(group, /^\d{5}$/);
});
