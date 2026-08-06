/**
 * Picks the construction a channel encrypts with, and is the only place that choice is
 * made.
 *
 *   - Two members  -> Double Ratchet. Per-message forward secrecy, unchanged.
 *   - Three or more -> shared epoch key (see groupSession.js for why the ratchet cannot
 *     stretch to N parties, and what that costs).
 *
 * Both paths start from the same hybrid X25519 + ML-KEM-768 handshake, so the
 * post-quantum property of the key exchange holds either way.
 */
import { decryptMessage, encryptMessage } from "./aead.js";
import { ensureGroupKey } from "./groupSession.js";
import { decryptWithRatchet, encryptWithRatchet, openRatchet } from "./ratchetSession.js";

/** The server's `group` flag is authoritative; member count is the fallback for a
 *  channel object that predates it. */
export function isGroupChannel(channel) {
  if (typeof channel?.group === "boolean") return channel.group;
  return (channel?.members?.length ?? 0) > 2;
}

/** Establish key material for a channel, so the UI can report status before any send. */
export async function openChannelSession(channel, user, identity) {
  if (isGroupChannel(channel)) {
    await ensureGroupKey(channel, user, identity);
    return { mode: "group", label: `Group key · epoch ${channel.key_epoch}` };
  }
  await openRatchet(channel, user, identity);
  return { mode: "ratchet", label: "Ratcheting · per-message keys" };
}

export async function encryptForChannel(channel, user, identity, plaintext) {
  if (!isGroupChannel(channel)) {
    return encryptWithRatchet(channel, user, identity, plaintext);
  }
  const key = await ensureGroupKey(channel, user, identity);
  return encryptMessage(key, plaintext, {
    senderId: user.id,
    channelId: channel.id,
    epoch: channel.key_epoch,
  });
}

export async function decryptForChannel(channel, user, identity, message) {
  if (!isGroupChannel(channel)) {
    return decryptWithRatchet(channel, user, identity, message);
  }
  // Keyed by the message's own epoch, not the channel's: history spans rotations, and
  // each epoch's key is stored separately.
  const key = await ensureGroupKey(channel, user, identity, message.key_epoch);
  return decryptMessage(key, message.envelope_b64, {
    senderId: message.sender_id,
    channelId: channel.id,
    epoch: message.key_epoch,
  });
}
