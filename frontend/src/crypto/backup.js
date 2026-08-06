/**
 * Encrypted identity backup — Stage 1, capability 31.
 *
 * The problem this closes: private keys live in one browser's IndexedDB and exist
 * nowhere else. Clearing site data, losing the laptop, or switching machines destroys
 * the account permanently, and no server-side flow can bring it back — that is the same
 * property that stops the relay reading your messages.
 *
 * So the only safe backup is one the user holds and only they can open. The file below
 * is sealed with a passphrase-derived key using Argon2id, the same KDF the server uses
 * for passwords, at the same cost. Someone who steals the file still needs the
 * passphrase, and the cost parameters are what make guessing it expensive.
 *
 * What it deliberately does NOT do: upload anywhere. A backup that we store is a copy of
 * your identity that we hold, which is precisely the arrangement this product exists to
 * avoid.
 */
import { argon2idAsync } from "@noble/hashes/argon2.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { base64ToBytes, bytesToBase64, encoder } from "./bytes.js";

export const BACKUP_FORMAT = "prahari-identity-backup";
export const BACKUP_VERSION = 1;

/**
 * Matches the server's password hashing cost (time 3, 64 MiB). Deliberately expensive:
 * this file may sit in cloud storage for years, so the passphrase has to survive an
 * offline attack rather than an online rate limit. Costs are written into the file so a
 * future version can raise them without orphaning old backups.
 */
const KDF = { name: "argon2id", t: 3, m: 65536, p: 1, dkLen: 32 };

const SALT_BYTES = 16;
const NONCE_BYTES = 12;

/** The fields that constitute an identity. All are base64 in storage. */
const IDENTITY_FIELDS = [
  "ed25519Secret", "ed25519Public",
  "x25519Secret", "x25519Public",
  "mlKemSecret", "mlKemPublic",
];

/**
 * Header bytes bound into the AEAD as additional data.
 *
 * Binding the username and the KDF parameters means a file cannot be silently retargeted
 * at a different account, nor downgraded to cheaper parameters to make a guessing attack
 * easier — either edit breaks authentication instead of being accepted.
 */
function headerAad(username, kdf, salt) {
  return encoder.encode(
    `${BACKUP_FORMAT}|v${BACKUP_VERSION}|${username}|${kdf.name}|t=${kdf.t}|m=${kdf.m}|p=${kdf.p}|${bytesToBase64(salt)}`,
  );
}

async function deriveKey(passphrase, salt, kdf) {
  const raw = await argon2idAsync(encoder.encode(passphrase), salt, {
    t: kdf.t, m: kdf.m, p: kdf.p, dkLen: kdf.dkLen ?? 32,
  });
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

/**
 * Seal an identity into a portable file.
 *
 * @returns {Promise<string>} pretty-printed JSON, ready to download
 */
export async function exportIdentity(identity, username, passphrase) {
  if (!identity) throw new Error("No identity to back up");
  if (!passphrase || passphrase.length < 12) {
    throw new Error("Use a passphrase of at least 12 characters — it is the only thing protecting this file");
  }
  for (const field of IDENTITY_FIELDS) {
    if (!identity[field]) throw new Error(`Identity is incomplete: ${field} is missing`);
  }

  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
  const key = await deriveKey(passphrase, salt, KDF);

  const plaintext = encoder.encode(
    JSON.stringify(Object.fromEntries(IDENTITY_FIELDS.map((field) => [field, identity[field]]))),
  );
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: headerAad(username, KDF, salt), tagLength: 128 },
      key,
      plaintext,
    ),
  );

  return JSON.stringify(
    {
      format: BACKUP_FORMAT,
      version: BACKUP_VERSION,
      username,
      created_at: new Date().toISOString(),
      kdf: { name: KDF.name, t: KDF.t, m: KDF.m, p: KDF.p, salt: bytesToBase64(salt) },
      nonce: bytesToBase64(nonce),
      ciphertext: bytesToBase64(ciphertext),
    },
    null,
    2,
  );
}

/**
 * A backup is only useful if what comes out is a working identity, so the halves are
 * checked against each other rather than trusted. A file that decrypts but carries a
 * public key its own secret does not generate would otherwise install an identity that
 * fails later, at the first handshake, with nothing to point at.
 */
function assertConsistent(identity) {
  for (const field of IDENTITY_FIELDS) {
    if (typeof identity[field] !== "string" || !identity[field]) {
      throw new Error(`Backup is missing ${field}`);
    }
  }
  const edPublic = ed25519.getPublicKey(base64ToBytes(identity.ed25519Secret));
  if (bytesToBase64(edPublic) !== identity.ed25519Public) {
    throw new Error("Backup is inconsistent: the Ed25519 keys do not belong together");
  }
  const xPublic = x25519.getPublicKey(base64ToBytes(identity.x25519Secret));
  if (bytesToBase64(xPublic) !== identity.x25519Public) {
    throw new Error("Backup is inconsistent: the X25519 keys do not belong together");
  }
  if (base64ToBytes(identity.mlKemPublic).length !== 1184) {
    throw new Error("Backup is inconsistent: the ML-KEM encapsulation key is the wrong size");
  }
}

/**
 * Open a backup file.
 *
 * @returns {Promise<{username: string, identity: object, createdAt: string}>}
 */
export async function importIdentity(fileText, passphrase) {
  let envelope;
  try {
    envelope = JSON.parse(fileText);
  } catch {
    throw new Error("That file is not a PRAHARI identity backup");
  }
  if (envelope?.format !== BACKUP_FORMAT) {
    throw new Error("That file is not a PRAHARI identity backup");
  }
  if (envelope.version !== BACKUP_VERSION) {
    throw new Error(`This backup is version ${envelope.version}; this app reads version ${BACKUP_VERSION}`);
  }
  const kdf = envelope.kdf ?? {};
  if (kdf.name !== "argon2id") throw new Error(`Unsupported key derivation: ${kdf.name}`);

  const salt = base64ToBytes(kdf.salt);
  const key = await deriveKey(passphrase, salt, kdf);

  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: base64ToBytes(envelope.nonce),
        additionalData: headerAad(envelope.username, kdf, salt),
        tagLength: 128,
      },
      key,
      base64ToBytes(envelope.ciphertext),
    );
  } catch {
    // Indistinguishable outcomes on purpose: a wrong passphrase and a tampered file both
    // fail authentication, and saying which would tell an attacker they had the right
    // passphrase for a file they had modified.
    throw new Error("Could not open the backup — wrong passphrase, or the file has been altered");
  }

  const identity = JSON.parse(new TextDecoder().decode(plaintext));
  assertConsistent(identity);
  return { username: envelope.username, identity, createdAt: envelope.created_at };
}

/** Suggested filename. Dated, because people keep several. */
export function backupFilename(username) {
  const day = new Date().toISOString().slice(0, 10);
  return `prahari-identity-${username}-${day}.json`;
}
