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
export const LOCK_VERSION = 1;
export const MIN_PASSCODE_LENGTH = 8;

/** A stored record is either a bare identity or one of these. */
export function isLocked(record) {
  return record?.format === LOCK_FORMAT;
}

function lockAad(username, kdf, salt) {
  return encoder.encode(
    `${LOCK_FORMAT}|v${LOCK_VERSION}|${username}|${kdf.name}|t=${kdf.t}|m=${kdf.m}|p=${kdf.p}|${bytesToBase64(salt)}`,
  );
}

/** Wrap an identity for storage. The result is what goes into IndexedDB. */
export async function lockIdentity(identity, username, passcode) {
  if (!identity) throw new Error("No identity to lock");
  if (!passcode || passcode.length < MIN_PASSCODE_LENGTH) {
    throw new Error(`Use a passcode of at least ${MIN_PASSCODE_LENGTH} characters`);
  }
  const salt = randomSalt();
  const nonce = randomNonce();
  const key = await deriveWrappingKey(passcode, salt, INTERACTIVE_KDF);

  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: nonce,
        additionalData: lockAad(username, INTERACTIVE_KDF, salt),
        tagLength: 128,
      },
      key,
      encoder.encode(JSON.stringify(identity)),
    ),
  );

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
  };
}

/** Recover the identity from a locked record. Throws on a wrong passcode. */
export async function unlockIdentity(record, passcode) {
  if (!isLocked(record)) throw new Error("That record is not locked");
  if (record.version !== LOCK_VERSION) {
    throw new Error(`Locked with version ${record.version}; this app reads version ${LOCK_VERSION}`);
  }
  const kdf = record.kdf ?? {};
  const salt = base64ToBytes(kdf.salt);
  const key = await deriveWrappingKey(passcode, salt, kdf);

  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: base64ToBytes(record.nonce),
        additionalData: lockAad(record.username, kdf, salt),
        tagLength: 128,
      },
      key,
      base64ToBytes(record.ciphertext),
    );
  } catch {
    throw new Error("Wrong passcode");
  }
  return JSON.parse(new TextDecoder().decode(plaintext));
}
