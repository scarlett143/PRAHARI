/**
 * Per-channel ratchet lifecycle: bootstrap, persistence, and envelope dispatch.
 *
 * The ratchet is seeded from the existing hybrid handshake, so the post-quantum
 * protection of the initial key exchange carries into every chain derived from it. What
 * changes is that the per-epoch key is no longer used to encrypt anything directly -- it
 * becomes the root of a ratchet, and each message gets a key of its own.
 *
 * Two consequences worth being explicit about, because they are visible to users:
 *
 *   - A message can only be decrypted once. Plaintext is kept locally by the caller;
 *     see `savePlaintext` in storage/keys.js.
 *   - Ratchet state is per browser. Signing in elsewhere gives a device that can read
 *     what arrives from then on, never the backlog.
 */
import { api } from "../lib/api.js";
import { loadRatchetState, saveRatchetState } from "../storage/keys.js";
import { base64ToBytes } from "./bytes.js";
import { verifyRemoteBundle } from "./identity.js";
import { decryptMessage } from "./aead.js";
import { ensureSession } from "./session.js";
import {
  ENVELOPE_VERSION,
  deserializeState,
  initReceiver,
  initSender,
  ratchetDecrypt,
  ratchetEncrypt,
  serializeState,
} from "./ratchet.js";

/** Envelope version written before the ratchet existed, still readable. */
const LEGACY_VERSION = 1;

export function envelopeVersion(envelopeB64) {
  try {
    return base64ToBytes(envelopeB64)[0];
  } catch {
    return null;
  }
}

/**
 * Load the ratchet for a channel, bootstrapping it from the hybrid session on first use.
 *
 * Which side initialises as sender is decided by `session_initiator_id`, the same value
 * that already decides who publishes the hybrid offer -- so both ends reach the same
 * conclusion without another round trip.
 */
export async function openRatchet(channel, user, identity) {
  const stored = await loadRatchetState(channel.id);
  if (stored) return deserializeState(stored);

  if (!identity) throw new Error("This browser does not have your private identity keys");

  // The hybrid handshake still runs exactly as before; its output is the ratchet root
  // rather than the message key.
  const sharedSecret = await ensureSession(channel, user, identity);

  let state;
  if (user.id === channel.session_initiator_id) {
    const peer = channel.members.find((member) => member.id !== user.id);
    if (!peer) throw new Error("No peer found in channel");
    const bundle = await api(`/api/v2/keys/${encodeURIComponent(peer.username)}`);
    if (!verifyRemoteBundle(bundle)) throw new Error("Remote identity bundle signature is invalid");
    state = await initSender(sharedSecret, base64ToBytes(bundle.x25519_public_key));
  } else {
    // The responder's published X25519 key is what the initiator ratcheted against, so
    // it has to be the initial ratchet keypair on this side.
    state = initReceiver(sharedSecret, {
      secretKey: base64ToBytes(identity.x25519Secret),
      publicKey: base64ToBytes(identity.x25519Public),
    });
  }
  await saveRatchetState(channel.id, serializeState(state));
  return state;
}

/** Encrypt and persist the advanced state together. */
export async function encryptWithRatchet(channel, user, identity, plaintext) {
  const state = await openRatchet(channel, user, identity);
  const envelope = await ratchetEncrypt(state, plaintext, {
    senderId: user.id,
    channelId: channel.id,
    epoch: channel.key_epoch,
  });
  await saveRatchetState(channel.id, serializeState(state));
  return envelope;
}

/**
 * Decrypt one message.
 *
 * State is saved after every attempt that changed it, including ones that skipped keys
 * forward, because losing that work would strand the messages those keys belong to.
 */
export async function decryptWithRatchet(channel, user, identity, message) {
  const version = envelopeVersion(message.envelope_b64);

  if (version === LEGACY_VERSION) {
    // Written before the ratchet. Still decryptable with the per-epoch key, which is
    // exactly the property the ratchet removes going forward.
    const key = await ensureSession(channel, user, identity, message.key_epoch);
    return decryptMessage(key, message.envelope_b64, {
      senderId: message.sender_id,
      channelId: channel.id,
      epoch: message.key_epoch,
    });
  }

  if (version !== ENVELOPE_VERSION) {
    throw new Error(`Unsupported envelope version ${version}`);
  }

  const state = await openRatchet(channel, user, identity);
  try {
    return await ratchetDecrypt(state, message.envelope_b64, {
      senderId: message.sender_id,
      channelId: channel.id,
      epoch: message.key_epoch,
    });
  } finally {
    await saveRatchetState(channel.id, serializeState(state));
  }
}
