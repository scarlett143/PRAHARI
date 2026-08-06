/**
 * Shared plumbing for anything sealed under a human-chosen secret.
 *
 * Two things need it — the portable backup file and the at-rest key lock — and they must
 * not drift apart. Key wrapping implemented twice is key wrapping fixed once.
 *
 * Costs differ by purpose and are stored alongside each artefact rather than assumed:
 * a backup may sit in cloud storage for years and should cost an attacker dearly, while
 * the lock is paid on every unlock and has to stay usable.
 */
import { argon2idAsync } from "@noble/hashes/argon2.js";
import { encoder } from "./bytes.js";

export const SALT_BYTES = 16;
export const NONCE_BYTES = 12;

/** For a file that may outlive the device it was made on. */
export const ARCHIVE_KDF = { name: "argon2id", t: 3, m: 65536, p: 1, dkLen: 32 };

/** For the at-rest lock, paid interactively every time the app is opened. */
export const INTERACTIVE_KDF = { name: "argon2id", t: 3, m: 32768, p: 1, dkLen: 32 };

export async function deriveWrappingKey(passphrase, salt, kdf) {
  if (kdf?.name !== "argon2id") throw new Error(`Unsupported key derivation: ${kdf?.name}`);
  const raw = await argon2idAsync(encoder.encode(passphrase), salt, {
    t: kdf.t,
    m: kdf.m,
    p: kdf.p,
    dkLen: kdf.dkLen ?? 32,
  });
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

export const randomSalt = () => crypto.getRandomValues(new Uint8Array(SALT_BYTES));
export const randomNonce = () => crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
