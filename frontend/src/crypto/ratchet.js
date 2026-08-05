/**
 * Double Ratchet over the existing hybrid handshake.
 *
 * What this adds to the per-epoch session key it replaces:
 *
 *   - **Per-message forward secrecy.** Every message gets its own key, derived by
 *     advancing a chain key one step. The message key is used once and dropped, so
 *     compromising the device does not expose messages already read.
 *   - **Break-in recovery.** Each time the direction of conversation flips, both sides
 *     mix a fresh X25519 exchange into the root key. An attacker who steals the state
 *     loses the ability to follow along after the next flip they cannot observe.
 *   - **Out-of-order delivery.** Keys for messages that arrive late are derived ahead of
 *     time and stored, bounded, rather than tearing down the chain.
 *
 * ## What it does not claim
 *
 * The DH ratchet is X25519 only, so the *ratchet steps* are classically secure. That is
 * weaker than the initial handshake, and it matters for one specific property:
 * break-in recovery against an adversary who can both steal state and break X25519.
 *
 * Confidentiality against harvest-now-decrypt-later is NOT weakened, and the reason is
 * worth stating precisely: the root key starts as the hybrid X25519+ML-KEM secret, and
 * every later root is `KDF(previous_root, dh_output)`. An attacker who records the
 * traffic and later breaks every X25519 exchange still cannot compute any root without
 * the initial ML-KEM secret. The post-quantum protection of the original handshake
 * carries forward through the whole chain.
 *
 * A fully post-quantum ratchet would additionally re-encapsulate ML-KEM on each step,
 * at roughly 2.3 KB of header per direction flip. That is not implemented here, and
 * nothing in the UI should claim it is.
 *
 * This module is deliberately free of storage, network and bundler imports so it can be
 * exercised directly under `node --test`.
 */
import { x25519 } from "@noble/curves/ed25519.js";

import { base64ToBytes, bytesToBase64, concatBytes, encoder } from "./bytes.js";

export const ENVELOPE_VERSION = 2;
const ROOT_INFO = encoder.encode("prahari/ratchet/root/v1");

// Distinct constants so the message key and the next chain key are independent outputs
// of the same chain key. Reusing one value for both would make them equal.
const MESSAGE_KEY_CONSTANT = new Uint8Array([0x01]);
const CHAIN_KEY_CONSTANT = new Uint8Array([0x02]);

const RATCHET_PUBLIC_BYTES = 32;
const COUNTER_BYTES = 4;
export const HEADER_BYTES = RATCHET_PUBLIC_BYTES + COUNTER_BYTES * 2;
const NONCE_BYTES = 12;

/**
 * Ceiling on keys derived to cover a gap in one chain.
 *
 * Without a bound, a peer could claim message number 2^32 and force the client to derive
 * four billion keys -- a denial of service written directly into the protocol. Anything
 * beyond this is treated as a broken or hostile stream.
 */
export const MAX_SKIP = 1000;

/** Ceiling on retained skipped keys across all chains, oldest evicted first. */
export const MAX_STORED_SKIPPED = 2000;

export class RatchetError extends Error {
  constructor(message, code) {
    super(message);
    this.name = "RatchetError";
    this.code = code;
  }
}

/* -- primitives ------------------------------------------------------------ */

async function hmac(key, data) {
  const imported = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", imported, data));
}

/** Root KDF: mixes a fresh DH output into the root, yielding a new root and chain key. */
async function kdfRootKey(rootKey, dhOutput) {
  const material = await crypto.subtle.importKey("raw", dhOutput, "HKDF", false, [
    "deriveBits",
  ]);
  const bits = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: rootKey, info: ROOT_INFO },
      material,
      512,
    ),
  );
  return { rootKey: bits.slice(0, 32), chainKey: bits.slice(32, 64) };
}

/** Symmetric ratchet: one step of a chain yields a message key and the next chain key. */
async function advanceChain(chainKey) {
  return {
    messageKey: await hmac(chainKey, MESSAGE_KEY_CONSTANT),
    nextChainKey: await hmac(chainKey, CHAIN_KEY_CONSTANT),
  };
}

function dh(secretKey, publicKey) {
  return x25519.getSharedSecret(secretKey, publicKey);
}

/* -- header ---------------------------------------------------------------- */

export function encodeHeader({ ratchetPublic, previousChainLength, messageNumber }) {
  const header = new Uint8Array(HEADER_BYTES);
  header.set(ratchetPublic, 0);
  const view = new DataView(header.buffer);
  view.setUint32(RATCHET_PUBLIC_BYTES, previousChainLength, false);
  view.setUint32(RATCHET_PUBLIC_BYTES + COUNTER_BYTES, messageNumber, false);
  return header;
}

export function decodeHeader(header) {
  if (header.length !== HEADER_BYTES) throw new RatchetError("bad header length", "bad_header");
  const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
  return {
    ratchetPublic: header.slice(0, RATCHET_PUBLIC_BYTES),
    previousChainLength: view.getUint32(RATCHET_PUBLIC_BYTES, false),
    messageNumber: view.getUint32(RATCHET_PUBLIC_BYTES + COUNTER_BYTES, false),
  };
}

/**
 * Associated data.
 *
 * The header is authenticated, not just carried: without this, a relay could rewrite the
 * message number or the ratchet public key and the AEAD would still verify.
 */
export function buildAad({ senderId, channelId, epoch }, header) {
  return concatBytes(
    encoder.encode(`prahari-v${ENVELOPE_VERSION}|${senderId}|${channelId}|${epoch}|`),
    header,
  );
}

/* -- state ----------------------------------------------------------------- */

function skipKey(ratchetPublic, messageNumber) {
  return `${bytesToBase64(ratchetPublic)}|${messageNumber}`;
}

/**
 * Initialise the side that sends first.
 *
 * `remoteRatchetPublic` is the peer's published X25519 key, which serves as their initial
 * ratchet key until they take their first step -- the same bootstrap X3DH uses with a
 * signed prekey.
 */
export async function initSender(sharedSecret, remoteRatchetPublic, keygen = x25519.keygen) {
  const keyPair = keygen();
  const { rootKey, chainKey } = await kdfRootKey(
    sharedSecret,
    dh(keyPair.secretKey, remoteRatchetPublic),
  );
  return {
    rootKey,
    sendRatchet: keyPair,
    remoteRatchetPublic,
    sendingChainKey: chainKey,
    receivingChainKey: null,
    sent: 0,
    received: 0,
    previousChainLength: 0,
    skipped: new Map(),
    // Test seam. Interop vectors replay a recorded conversation, which is only possible
    // if the ephemeral keypairs can be supplied rather than generated.
    keygen,
  };
}

/**
 * Initialise the side that receives first.
 *
 * It adopts its own long-term X25519 keypair as the initial ratchet keypair, because that
 * is the key the sender derived against. It holds no chain keys until the first message
 * arrives and triggers a DH ratchet step.
 */
export function initReceiver(sharedSecret, ownRatchetKeyPair, keygen = x25519.keygen) {
  return {
    rootKey: sharedSecret,
    sendRatchet: ownRatchetKeyPair,
    remoteRatchetPublic: null,
    sendingChainKey: null,
    receivingChainKey: null,
    sent: 0,
    received: 0,
    previousChainLength: 0,
    skipped: new Map(),
    keygen,
  };
}

/* -- ratchet steps --------------------------------------------------------- */

async function dhRatchet(state, header) {
  state.previousChainLength = state.sent;
  state.sent = 0;
  state.received = 0;
  state.remoteRatchetPublic = header.ratchetPublic;

  const receiving = await kdfRootKey(
    state.rootKey,
    dh(state.sendRatchet.secretKey, state.remoteRatchetPublic),
  );
  state.rootKey = receiving.rootKey;
  state.receivingChainKey = receiving.chainKey;

  // A fresh keypair here is what gives break-in recovery: from this step on, an attacker
  // holding the old state no longer has the secret the next root depends on.
  state.sendRatchet = (state.keygen ?? x25519.keygen)();
  const sending = await kdfRootKey(
    state.rootKey,
    dh(state.sendRatchet.secretKey, state.remoteRatchetPublic),
  );
  state.rootKey = sending.rootKey;
  state.sendingChainKey = sending.chainKey;
}

async function skipMessageKeys(state, until) {
  if (state.receivingChainKey === null) return;
  if (until - state.received > MAX_SKIP) {
    throw new RatchetError(
      `refusing to derive more than ${MAX_SKIP} skipped message keys`,
      "too_many_skipped",
    );
  }
  while (state.received < until) {
    const { messageKey, nextChainKey } = await advanceChain(state.receivingChainKey);
    state.skipped.set(skipKey(state.remoteRatchetPublic, state.received), messageKey);
    state.receivingChainKey = nextChainKey;
    state.received += 1;
  }
  // Map preserves insertion order, so the oldest retained key is the first entry.
  while (state.skipped.size > MAX_STORED_SKIPPED) {
    state.skipped.delete(state.skipped.keys().next().value);
  }
}

/* -- encrypt / decrypt ----------------------------------------------------- */

async function aesGcmEncrypt(messageKey, plaintext, aad) {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
  const key = await crypto.subtle.importKey("raw", messageKey, { name: "AES-GCM" }, false, [
    "encrypt",
  ]);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
      key,
      plaintext,
    ),
  );
  return { nonce, ciphertext };
}

async function aesGcmDecrypt(messageKey, nonce, ciphertext, aad) {
  const key = await crypto.subtle.importKey("raw", messageKey, { name: "AES-GCM" }, false, [
    "decrypt",
  ]);
  return new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
      key,
      ciphertext,
    ),
  );
}

/** Encrypt one message, advancing the sending chain by exactly one step. */
export async function ratchetEncrypt(state, plaintext, context) {
  if (state.sendingChainKey === null) {
    throw new RatchetError(
      "no sending chain yet: this side must receive a message before it can send",
      "no_sending_chain",
    );
  }
  const { messageKey, nextChainKey } = await advanceChain(state.sendingChainKey);
  const header = encodeHeader({
    ratchetPublic: state.sendRatchet.publicKey,
    previousChainLength: state.previousChainLength,
    messageNumber: state.sent,
  });

  state.sendingChainKey = nextChainKey;
  state.sent += 1;

  const { nonce, ciphertext } = await aesGcmEncrypt(
    messageKey,
    encoder.encode(plaintext),
    buildAad(context, header),
  );
  return bytesToBase64(
    concatBytes(new Uint8Array([ENVELOPE_VERSION]), header, nonce, ciphertext),
  );
}

/** Decrypt one message, ratcheting and filling gaps as the header requires. */
export async function ratchetDecrypt(state, envelopeB64, context) {
  const wire = base64ToBytes(envelopeB64);
  if (wire.length < 1 + HEADER_BYTES + NONCE_BYTES + 16 || wire[0] !== ENVELOPE_VERSION) {
    throw new RatchetError("unsupported or truncated envelope", "bad_envelope");
  }
  const headerBytes = wire.slice(1, 1 + HEADER_BYTES);
  const nonce = wire.slice(1 + HEADER_BYTES, 1 + HEADER_BYTES + NONCE_BYTES);
  const ciphertext = wire.slice(1 + HEADER_BYTES + NONCE_BYTES);
  const header = decodeHeader(headerBytes);
  const aad = buildAad(context, headerBytes);

  // A late message from a chain already left behind. Its key was derived when the gap was
  // first noticed, so it decrypts without disturbing current state.
  const stored = skipKey(header.ratchetPublic, header.messageNumber);
  if (state.skipped.has(stored)) {
    const messageKey = state.skipped.get(stored);
    const plaintext = await aesGcmDecrypt(messageKey, nonce, ciphertext, aad);
    // Only drop the key once the message it belongs to has actually authenticated;
    // discarding it on a forged message would lose the real one for good.
    state.skipped.delete(stored);
    return new TextDecoder().decode(plaintext);
  }

  const isNewRatchet =
    state.remoteRatchetPublic === null ||
    bytesToBase64(header.ratchetPublic) !== bytesToBase64(state.remoteRatchetPublic);

  if (isNewRatchet) {
    // Finish the outgoing chain first: everything the peer sent on it before flipping is
    // still in flight and must stay decryptable.
    if (state.receivingChainKey !== null) {
      await skipMessageKeys(state, header.previousChainLength);
    }
    await dhRatchet(state, header);
  }

  await skipMessageKeys(state, header.messageNumber);

  const { messageKey, nextChainKey } = await advanceChain(state.receivingChainKey);
  const plaintext = await aesGcmDecrypt(messageKey, nonce, ciphertext, aad);

  // Advance only after authentication, so a forged message cannot push the chain forward
  // and strand the legitimate one behind it.
  state.receivingChainKey = nextChainKey;
  state.received += 1;
  return new TextDecoder().decode(plaintext);
}

/* -- persistence ----------------------------------------------------------- */

export function serializeState(state) {
  return {
    v: 1,
    rootKey: bytesToBase64(state.rootKey),
    sendRatchetSecret: bytesToBase64(state.sendRatchet.secretKey),
    sendRatchetPublic: bytesToBase64(state.sendRatchet.publicKey),
    remoteRatchetPublic: state.remoteRatchetPublic
      ? bytesToBase64(state.remoteRatchetPublic)
      : null,
    sendingChainKey: state.sendingChainKey ? bytesToBase64(state.sendingChainKey) : null,
    receivingChainKey: state.receivingChainKey ? bytesToBase64(state.receivingChainKey) : null,
    sent: state.sent,
    received: state.received,
    previousChainLength: state.previousChainLength,
    skipped: [...state.skipped].map(([key, value]) => [key, bytesToBase64(value)]),
  };
}

export function deserializeState(raw) {
  if (!raw || raw.v !== 1) throw new RatchetError("unsupported ratchet state", "bad_state");
  return {
    rootKey: base64ToBytes(raw.rootKey),
    sendRatchet: {
      secretKey: base64ToBytes(raw.sendRatchetSecret),
      publicKey: base64ToBytes(raw.sendRatchetPublic),
    },
    remoteRatchetPublic: raw.remoteRatchetPublic
      ? base64ToBytes(raw.remoteRatchetPublic)
      : null,
    sendingChainKey: raw.sendingChainKey ? base64ToBytes(raw.sendingChainKey) : null,
    receivingChainKey: raw.receivingChainKey ? base64ToBytes(raw.receivingChainKey) : null,
    sent: raw.sent,
    received: raw.received,
    previousChainLength: raw.previousChainLength,
    skipped: new Map(raw.skipped.map(([key, value]) => [key, base64ToBytes(value)])),
    // Not serialised: a function cannot round-trip through storage, and a restored
    // state must always generate real keys rather than silently reusing a test seam.
    keygen: x25519.keygen,
  };
}
