/**
 * Contact verification — Stage 1, capability 23.
 *
 * Everything in this system rests on one unchecked assumption: that the key bundle the
 * server handed you for a contact really is theirs. Bundles are signed, but signed by
 * the very key whose authenticity is in question, so the signature proves internal
 * consistency and nothing about identity. A relay that substituted its own bundle would
 * be able to read every message to that contact, and nothing in the app would look
 * wrong.
 *
 * Two mechanisms close that, and they work together:
 *
 *   1. A SAFETY NUMBER both sides can read aloud or scan. It is derived from both
 *      identities, so it matches only if each side sees the other's real key.
 *   2. KEY-CHANGE DETECTION. The fingerprint seen on first contact is remembered, and a
 *      later change is surfaced loudly rather than accepted in silence. This is what
 *      catches a substitution that happens *after* you started talking, which is the
 *      case a one-time verification would miss.
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { base64ToBytes, concatBytes, encoder } from "./bytes.js";

const FINGERPRINT_LABEL = encoder.encode("PRAHARI-IDENTITY-FINGERPRINT-V1\0");
const SAFETY_LABEL = encoder.encode("PRAHARI-SAFETY-NUMBER-V1\0");

/**
 * Iterated hashing, as in Signal's fingerprint construction. The repetition is not for
 * secrecy -- these are public keys -- but to make grinding for a colliding *display*
 * string expensive, since users compare a truncated rendering rather than a full digest.
 */
const ITERATIONS = 2048;

function iterate(seed) {
  let digest = seed;
  for (let round = 0; round < ITERATIONS; round += 1) {
    digest = sha256(concatBytes(digest, seed));
  }
  return digest;
}

/** All three public keys, so swapping any one of them changes the fingerprint. */
function identityMaterial(bundle) {
  return concatBytes(
    base64ToBytes(bundle.ed25519_public_key),
    base64ToBytes(bundle.x25519_public_key ?? ""),
    base64ToBytes(bundle.ml_kem_encapsulation_key ?? ""),
  );
}

/**
 * Stretch a 32-byte digest into as many bytes as the display needs.
 *
 * A safety number is twelve groups, which wants 48 bytes -- more than SHA-256 emits, so
 * reading straight from one digest would run off the end and render the tail as
 * gibberish. Hashing with a counter is the standard way to expand it and keeps every
 * group backed by real digest material.
 */
function expand(seed, bytesNeeded) {
  const blocks = [];
  let produced = 0;
  for (let counter = 0; produced < bytesNeeded; counter += 1) {
    const block = sha256(concatBytes(seed, new Uint8Array([counter])));
    blocks.push(block);
    produced += block.length;
  }
  const out = new Uint8Array(produced);
  blocks.forEach((block, index) => out.set(block, index * 32));
  return out.slice(0, bytesNeeded);
}

/** Digits, five at a time, because that is what people can read to each other over a
 *  phone line without losing their place. */
function toDigits(digest, groups) {
  const material = expand(digest, groups * 4);
  const out = [];
  for (let index = 0; index < groups; index += 1) {
    const at = index * 4;
    const value =
      material[at] * 0x1000000 + material[at + 1] * 0x10000 + material[at + 2] * 0x100 + material[at + 3];
    out.push(String(value % 100000).padStart(5, "0"));
  }
  return out;
}

/**
 * A per-account fingerprint. Used for change detection, where only one side is involved.
 * @returns {string} e.g. "48219 03772 ..."
 */
export function identityFingerprint(bundle) {
  const digest = iterate(concatBytes(FINGERPRINT_LABEL, identityMaterial(bundle)));
  return toDigits(digest, 6).join(" ");
}

/**
 * The number both people compare.
 *
 * Sorted before hashing so each side computes the same value without needing to agree
 * who is "first" -- an ordering rule that depended on who initiated would produce two
 * different numbers and make every comparison fail.
 *
 * @returns {string} 12 groups of five digits
 */
export function safetyNumber(localBundle, remoteBundle) {
  const local = identityMaterial(localBundle);
  const remote = identityMaterial(remoteBundle);
  const [first, second] = compareBytes(local, remote) <= 0 ? [local, remote] : [remote, local];
  const digest = iterate(concatBytes(SAFETY_LABEL, first, second));
  return toDigits(digest, 12).join(" ");
}

function compareBytes(left, right) {
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return left.length - right.length;
}

/** Split for display: two rows of six groups reads far better than one long line. */
export function formatForDisplay(number) {
  const groups = number.split(" ");
  const half = Math.ceil(groups.length / 2);
  return [groups.slice(0, half).join(" "), groups.slice(half).join(" ")];
}
