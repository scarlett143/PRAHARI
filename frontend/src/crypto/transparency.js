/**
 * Recompute a peer's key history here, in the browser.
 *
 * The server returns a `chain_ok` of its own, and it is worth being explicit about why
 * that field is ignored: a relay reporting on whether it has tampered with its own log is
 * not evidence of anything. The hashes are the evidence, and they only mean something once
 * this side has recomputed them.
 *
 * The chain gives one property, precisely. Each entry commits to the entry before it, so
 * the sequence cannot be shortened, reordered or edited after the fact without every
 * following hash failing. A relay can still stay silent -- decline to show an entry, or
 * serve an older head -- and no log fixes that. What it can no longer do is substitute a
 * key and produce a history in which that key was always there.
 *
 * And it says nothing about first contact. With no earlier state to compare against there
 * is nothing to detect, which is why the safety-number comparison in verification.js
 * remains the thing that establishes who you are talking to. This makes a *change*
 * visible; it does not make an introduction trustworthy.
 *
 * Kept byte-compatible with `backend/app/transparency.py::entry_hash` — the domain
 * separator, the field order and the 4-byte length prefixes all have to match, or every
 * chain fails to verify here and the warning means nothing.
 */
import { base64ToBytes, concatBytes, encoder } from "./bytes.js";

const DOMAIN = encoder.encode("prahari-key-transparency-v1");
const ZERO32 = new Uint8Array(32);

const hex = (bytes) =>
  [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");

/** Big-endian, matching Python's `int.to_bytes(width, "big")`. */
function intBytes(value, width) {
  const out = new Uint8Array(width);
  let remaining = BigInt(value);
  for (let index = width - 1; index >= 0; index -= 1) {
    out[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return out;
}

/**
 * Lengths precede the variable-length fields. Without them, moving bytes from the end of
 * one key to the start of the next would leave the concatenation — and so the hash —
 * unchanged, letting two different bundles share a digest.
 */
async function entryHash(entry, previousHash) {
  const parts = [DOMAIN, previousHash ?? ZERO32];
  const fields = [
    encoder.encode(entry.user_id),
    base64ToBytes(entry.ed25519_public_key),
    base64ToBytes(entry.x25519_public_key),
    base64ToBytes(entry.ml_kem_encapsulation_key),
  ];
  for (const field of fields) {
    parts.push(intBytes(field.length, 4), field);
  }
  parts.push(intBytes(entry.seq, 8));
  return new Uint8Array(await crypto.subtle.digest("SHA-256", concatBytes(...parts)));
}

/**
 * @returns {Promise<{ok: boolean, reason: string|null, head: string|null, changes: number}>}
 */
export async function verifyKeyHistory(history) {
  const entries = history?.entries ?? [];
  if (!entries.length) {
    return { ok: false, reason: "This account has never published a key.", head: null, changes: 0 };
  }

  let previousHash = null;
  for (const [index, entry] of entries.entries()) {
    if (entry.seq !== index + 1) {
      return {
        ok: false,
        reason: `The history skips from ${index} to ${entry.seq} — an entry is missing.`,
        head: null,
        changes: 0,
      };
    }
    const expectedPrev = previousHash ? hex(previousHash) : null;
    if ((entry.prev_hash ?? null) !== expectedPrev) {
      return {
        ok: false,
        reason: `Entry ${entry.seq} does not follow the one before it.`,
        head: null,
        changes: 0,
      };
    }
    const recomputed = await entryHash({ ...entry, user_id: history.user_id }, previousHash);
    if (hex(recomputed) !== entry.entry_hash) {
      return {
        ok: false,
        reason: `Entry ${entry.seq} has been altered since it was published.`,
        head: null,
        changes: 0,
      };
    }
    previousHash = recomputed;
  }

  return {
    ok: true,
    reason: null,
    head: hex(previousHash),
    // The first publish is an account existing, not a key changing.
    changes: entries.length - 1,
  };
}

/**
 * Compare a verified head against the one this device recorded last time.
 *
 * A head that moved is not an alarm by itself — people legitimately rotate keys and set up
 * new devices. It is an alarm when nobody told you, which is why this reports the
 * transition rather than a verdict.
 */
export function describeHeadChange(previousHead, currentHead) {
  if (!previousHead) return { changed: false, first: true };
  return { changed: previousHead !== currentHead, first: false };
}
