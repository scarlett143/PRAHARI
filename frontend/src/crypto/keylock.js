/**
 * At-rest key lock — Stage 1, capability 26.
 *
 * Until now the security page admitted this outright: private keys sat in IndexedDB in
 * the clear, so anyone with the unlocked device could read them straight out of devtools.
 * Locking wraps the stored record under a passcode, so possession of the machine is no
 * longer possession of the identity.
 *
 * What it does NOT defend against, and the security page still says so: malicious
 * JavaScript running in this origin while the app is unlocked. Once you type the
 * passcode the keys are in memory, and XSS at that moment reaches them. This raises the
 * cost of a stolen laptop, not of a compromised page.
 *
 * The passcode is deliberately NOT the account password. That password is resettable
 * with the identity key, and if it also wrapped the keys, a reset would need the keys to
 * unwrap the keys — a user who had forgotten it would be locked out permanently by the
 * very feature meant to recover them.
 */
import { base64ToBytes, bytesToBase64, encoder } from "./bytes.js";
import { INTERACTIVE_KDF, deriveWrappingKey, randomNonce, randomSalt } from "./sealed.js";

export const LOCK_FORMAT = "prahari-identity-lock";
export const LOCK_VERSION = 2;
export const MIN_PASSCODE_LENGTH = 8;

/** A stored record is either a bare identity or one of these. */
export function isLocked(record) {
  return record?.format === LOCK_FORMAT;
}

/**
 * The AAD binds a slot to its role.
 *
 * Without the slot label the two ciphertexts below are interchangeable, and anyone who
 * could edit IndexedDB could swap them -- turning the real passcode into the one that
 * wipes the device, which is the exact inversion this feature must not permit.
 */
function lockAad(username, kdf, salt, slot, version = LOCK_VERSION) {
  const base =
    `${LOCK_FORMAT}|v${version}|${username}|${kdf.name}|t=${kdf.t}|m=${kdf.m}|p=${kdf.p}|${bytesToBase64(salt)}`;
  // Version 1 predates slots and has exactly one ciphertext, so its AAD must stay
  // byte-identical or every record written before this change stops opening.
  return encoder.encode(version === 1 ? base : `${base}|slot=${slot}`);
}

async function seal(key, aad, nonce, plaintext) {
  return new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
      key,
      plaintext,
    ),
  );
}

/** What the duress slot contains. Never the identity — see `lockIdentity`. */
const DURESS_MARKER = { t: "duress", v: LOCK_VERSION };

/**
 * Wrap an identity for storage. The result is what goes into IndexedDB.
 *
 * A record always carries two slots, whether or not a duress passcode was set. That is
 * the point: if the duress slot only appeared when the feature was in use, its presence
 * would announce that a wipe passcode exists, and someone compelling the owner to unlock
 * would simply demand the other one. With the slot always present and filled with random
 * bytes when unused, the stored record looks identical either way.
 *
 * Both slots share one salt, so unlocking still runs Argon2id exactly once. Two salts
 * would have meant two derivations per attempt, doubling the cost of every unlock to
 * support a feature most records do not use.
 *
 * The duress slot holds a marker, never the identity. Even someone who eventually breaks
 * that passcode gets a constant out of it.
 */
export async function lockIdentity(identity, username, passcode, duressPasscode = "") {
  if (!identity) throw new Error("No identity to lock");
  if (!passcode || passcode.length < MIN_PASSCODE_LENGTH) {
    throw new Error(`Use a passcode of at least ${MIN_PASSCODE_LENGTH} characters`);
  }
  if (duressPasscode) {
    if (duressPasscode.length < MIN_PASSCODE_LENGTH) {
      throw new Error(`Use a duress passcode of at least ${MIN_PASSCODE_LENGTH} characters`);
    }
    if (duressPasscode === passcode) {
      throw new Error("The duress passcode must be different from the unlock passcode");
    }
  }

  const salt = randomSalt();
  const nonce = randomNonce();
  const duressNonce = randomNonce();
  const key = await deriveWrappingKey(passcode, salt, INTERACTIVE_KDF);

  const ciphertext = await seal(
    key,
    lockAad(username, INTERACTIVE_KDF, salt, "primary"),
    nonce,
    encoder.encode(JSON.stringify(identity)),
  );

  let duressCiphertext;
  if (duressPasscode) {
    const duressKey = await deriveWrappingKey(duressPasscode, salt, INTERACTIVE_KDF);
    duressCiphertext = await seal(
      duressKey,
      lockAad(username, INTERACTIVE_KDF, salt, "duress"),
      duressNonce,
      encoder.encode(JSON.stringify(DURESS_MARKER)),
    );
  } else {
    // Indistinguishable filler. AES-GCM output is a ciphertext plus a 16-byte tag, and
    // random bytes of that length are exactly what an unopenable slot looks like — no
    // key opens this, and nothing about it says so.
    duressCiphertext = crypto.getRandomValues(
      new Uint8Array(encoder.encode(JSON.stringify(DURESS_MARKER)).length + 16),
    );
  }

  return {
    format: LOCK_FORMAT,
    version: LOCK_VERSION,
    username,
    locked_at: new Date().toISOString(),
    kdf: {
      name: INTERACTIVE_KDF.name,
      t: INTERACTIVE_KDF.t,
      m: INTERACTIVE_KDF.m,
      p: INTERACTIVE_KDF.p,
      salt: bytesToBase64(salt),
    },
    nonce: bytesToBase64(nonce),
    ciphertext: bytesToBase64(ciphertext),
    duress_nonce: bytesToBase64(duressNonce),
    duress_ciphertext: bytesToBase64(duressCiphertext),
  };
}

async function openSlot(key, nonce, ciphertext, aad) {
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
      key,
      ciphertext,
    );
    return JSON.parse(new TextDecoder().decode(plaintext));
  } catch {
    return null;
  }
}

/**
 * Open a locked record.
 *
 * Returns `{ identity }` for the real passcode and `{ duress: true }` for the duress one.
 * The caller decides what a duress result means — this module deliberately does not wipe
 * anything itself, so the destructive step stays visible at the call site rather than
 * hidden inside a function named "unlock".
 *
 * Throws on a passcode that opens neither.
 */
export async function unlockIdentity(record, passcode) {
  if (!isLocked(record)) throw new Error("That record is not locked");
  if (record.version > LOCK_VERSION) {
    throw new Error(`Locked with version ${record.version}; this app reads version ${LOCK_VERSION}`);
  }
  const kdf = record.kdf ?? {};
  const salt = base64ToBytes(kdf.salt);
  // One derivation, then two cheap AEAD attempts against it.
  const key = await deriveWrappingKey(passcode, salt, kdf);

  const identity = await openSlot(
    key,
    base64ToBytes(record.nonce),
    base64ToBytes(record.ciphertext),
    lockAad(record.username, kdf, salt, "primary", record.version),
  );
  if (identity) return { identity, duress: false };

  if (record.duress_ciphertext) {
    const marker = await openSlot(
      key,
      base64ToBytes(record.duress_nonce),
      base64ToBytes(record.duress_ciphertext),
      lockAad(record.username, kdf, salt, "duress", record.version),
    );
    if (marker?.t === "duress") return { identity: null, duress: true };
  }

  throw new Error("Wrong passcode");
}
