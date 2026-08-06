/**
 * Group channels: one shared key per epoch, sealed separately to every member.
 *
 * WHY THIS IS NOT THE RATCHET
 * ---------------------------
 * A Double Ratchet is a two-party construction -- its forward secrecy comes from two
 * sides advancing a shared DH chain. Three people have no such chain, and a message is
 * stored as ONE envelope for the whole channel, so an N-party message must be readable
 * with one key. Groups therefore use a shared epoch key with AEAD.
 *
 * The security consequence, stated plainly: a group gets forward secrecy at EPOCH
 * granularity, not per message. Compromising a member's stored epoch key exposes the
 * messages of that epoch, where the two-party ratchet would have exposed only one
 * message. Rotating the channel (`rotate-key`) is what advances it, and the server
 * already forces a rotation on the existing message-count and time limits.
 *
 * What is NOT given up: the key exchange is still hybrid X25519 + ML-KEM-768, so the
 * group key is sealed against a harvest-now-decrypt-later adversary exactly as the
 * two-party handshake is. The server sees only wrapped blobs it has no key for.
 */
import { api } from "../lib/api.js";
import { loadSessionKey, saveSessionKey } from "../storage/keys.js";
import { base64ToBytes, bytesToBase64, concatBytes, encoder } from "./bytes.js";
import { signSessionOffer, verifyRemoteBundle, verifySessionOffer } from "./identity.js";
import { initiateSession, respondSession } from "./hybrid.js";

const WRAP_NONCE_BYTES = 12;
const GROUP_KEY_BYTES = 32;

/** Binds a wrapped key to one channel, epoch and recipient, so a copy cannot be replayed
 *  at a different member or a different epoch even by the relay that stores it. */
function wrapAad(channelId, epoch, responderId) {
  return encoder.encode(`prahari/group-key-wrap/v1|${channelId}|${epoch}|${responderId}`);
}

async function importWrappingKey(raw) {
  if (raw.length !== 32) throw new Error("Wrapping key must be 32 bytes");
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function wrapGroupKey(wrappingKey, groupKey, { channelId, epoch, responderId }) {
  const nonce = crypto.getRandomValues(new Uint8Array(WRAP_NONCE_BYTES));
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: wrapAad(channelId, epoch, responderId), tagLength: 128 },
      await importWrappingKey(wrappingKey),
      groupKey,
    ),
  );
  return concatBytes(nonce, sealed);
}

async function unwrapGroupKey(wrappingKey, wrapped, { channelId, epoch, responderId }) {
  if (wrapped.length <= WRAP_NONCE_BYTES) throw new Error("Wrapped group key is truncated");
  const nonce = wrapped.slice(0, WRAP_NONCE_BYTES);
  const sealed = wrapped.slice(WRAP_NONCE_BYTES);
  let raw;
  try {
    raw = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce, additionalData: wrapAad(channelId, epoch, responderId), tagLength: 128 },
        await importWrappingKey(wrappingKey),
        sealed,
      ),
    );
  } catch {
    throw new Error("GROUP KEY UNWRAP FAILED — this copy was not sealed for you");
  }
  if (raw.length !== GROUP_KEY_BYTES) throw new Error("Unwrapped group key has the wrong length");
  return raw;
}

/**
 * The epoch's group key, minting and publishing it if this client is the initiator.
 *
 * Both roles are idempotent: a second call returns the stored key, and a re-published
 * batch is accepted only if it is byte-identical to what is already on the server.
 */
export async function ensureGroupKey(channel, user, identity, targetEpoch = channel.key_epoch) {
  const stored = await loadSessionKey(channel.id, targetEpoch);
  if (stored) return base64ToBytes(stored);
  if (!identity) throw new Error("This browser does not have your private identity keys");

  const isInitiator = user.id === channel.session_initiator_id;
  // Only the current epoch can be minted. An older one either has a stored key here or
  // is gone -- there is nothing to reconstruct it from.
  if (isInitiator && targetEpoch === channel.key_epoch) {
    try {
      return await publishGroupKey(channel, user, identity, targetEpoch);
    } catch (error) {
      // Another browser of ours already published this epoch. Our own sealed copy is
      // waiting on the server, so fall through and collect it like any other member.
      if (error.detail?.code !== "session_offer_exists") throw error;
    }
  }
  return collectGroupKey(channel, user, identity, targetEpoch);
}

async function publishGroupKey(channel, user, identity, epoch) {
  const groupKey = crypto.getRandomValues(new Uint8Array(GROUP_KEY_BYTES));

  // Every member, ourselves included -- see the note in sessions.py: the initiator needs
  // a recoverable copy or they alone could never read the group from another device.
  const offers = [];
  for (const member of channel.members) {
    const bundle = await api(`/api/v2/keys/${encodeURIComponent(member.username)}`);
    if (!verifyRemoteBundle(bundle)) {
      throw new Error(`Identity bundle signature is invalid for ${member.username}`);
    }
    const { key: wrappingKey, offer } = await initiateSession(bundle);
    const wrapped = await wrapGroupKey(wrappingKey, groupKey, {
      channelId: channel.id,
      epoch,
      responderId: member.id,
    });
    const entry = {
      channel_id: channel.id,
      key_epoch: epoch,
      responder_id: member.id,
      ...offer,
      wrapped_group_key: bytesToBase64(wrapped),
    };
    entry.offer_signature = signSessionOffer(identity, entry);
    offers.push(entry);
  }

  await api("/api/v2/sessions/offers/batch", {
    method: "POST",
    body: JSON.stringify({ channel_id: channel.id, key_epoch: epoch, offers }),
  });

  await saveSessionKey(channel.id, epoch, bytesToBase64(groupKey));
  return groupKey;
}

async function collectGroupKey(channel, user, identity, epoch) {
  let offer;
  try {
    offer = await api(`/api/v2/sessions/offers/${channel.id}?epoch=${epoch}`);
  } catch (error) {
    if (error.status === 404) {
      throw new Error("Waiting for the group initiator to publish this epoch's key");
    }
    throw error;
  }
  if (offer.responder_id !== user.id) throw new Error("Session offer is not addressed to this user");
  if (!offer.wrapped_group_key) throw new Error("Offer carries no wrapped group key");

  const initiator = channel.members.find((member) => member.id === offer.initiator_id);
  if (!initiator) throw new Error("Session initiator is not a channel member");
  const initiatorBundle = await api(`/api/v2/keys/${encodeURIComponent(initiator.username)}`);
  if (!verifyRemoteBundle(initiatorBundle)) {
    throw new Error("Initiator identity bundle signature is invalid");
  }
  // Covers the wrapped key too, so a relay cannot substitute one member's copy for
  // another's without breaking this check.
  if (!verifySessionOffer(initiatorBundle, offer)) {
    throw new Error("Session offer identity signature is invalid");
  }

  const wrappingKey = await respondSession(identity, offer);
  const groupKey = await unwrapGroupKey(wrappingKey, base64ToBytes(offer.wrapped_group_key), {
    channelId: channel.id,
    epoch,
    responderId: user.id,
  });
  await saveSessionKey(channel.id, epoch, bytesToBase64(groupKey));
  return groupKey;
}
