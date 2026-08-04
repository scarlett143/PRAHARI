import { api } from "../lib/api.js";
import { loadSessionKey, saveSessionKey } from "../storage/keys.js";
import { base64ToBytes, bytesToBase64 } from "./bytes.js";
import { signSessionOffer, verifyRemoteBundle, verifySessionOffer } from "./identity.js";
import { initiateSession, respondSession } from "./hybrid.js";

export async function getStoredSessionKey(channelId, epoch) {
  const stored = await loadSessionKey(channelId, epoch);
  return stored ? base64ToBytes(stored) : null;
}

export async function ensureSession(channel, user, identity, targetEpoch = channel.key_epoch) {
  const existing = await getStoredSessionKey(channel.id, targetEpoch);
  if (existing) return existing;
  if (!identity) throw new Error("This browser does not have your private identity keys");
  if (!channel.hybrid_session_supported || channel.members.length !== 2) {
    throw new Error("Hybrid demo sessions currently require exactly two channel members");
  }

  const initiatorId = channel.session_initiator_id;
  const other = channel.members.find((member) => member.id !== user.id);
  if (!other) throw new Error("No peer found in channel");

  if (user.id === initiatorId) {
    if (targetEpoch !== channel.key_epoch) {
      throw new Error("An initiator cannot reconstruct an old forward-secret session key after local key deletion");
    }
    const remoteBundle = await api(`/api/v2/keys/${encodeURIComponent(other.username)}`);
    if (!verifyRemoteBundle(remoteBundle)) throw new Error("Remote identity bundle signature is invalid");
    const { key, offer } = await initiateSession(remoteBundle);
    const signedOffer = {
      channel_id: channel.id,
      key_epoch: targetEpoch,
      responder_id: other.id,
      ...offer,
    };
    signedOffer.offer_signature = signSessionOffer(identity, signedOffer);
    let stored;
    try {
      stored = await api("/api/v2/sessions/offers", {
        method: "POST",
        body: JSON.stringify(signedOffer),
      });
    } catch (error) {
      if (error.detail?.code === "session_offer_exists") {
        throw new Error(
          "Another session offer already exists for this epoch and its private ephemeral is not in this browser. Rotate the channel to the next epoch.",
        );
      }
      throw error;
    }
    // The server keeps exactly one offer per epoch. If what came back is not the offer we
    // just signed, our key was derived from an ephemeral nobody else can reproduce, so
    // storing it would silently break every message. Fail loudly instead.
    if (
      stored.x25519_ephemeral_public !== signedOffer.x25519_ephemeral_public ||
      stored.ml_kem_ciphertext !== signedOffer.ml_kem_ciphertext
    ) {
      throw new Error(
        "The server returned a different session offer for this epoch. Rotate the channel to the next epoch to establish a fresh session.",
      );
    }
    await saveSessionKey(channel.id, targetEpoch, bytesToBase64(key));
    return key;
  }

  let offer;
  try {
    offer = await api(`/api/v2/sessions/offers/${channel.id}?epoch=${targetEpoch}`);
  } catch (error) {
    if (error.status === 404) throw new Error("Waiting for the session initiator to publish the hybrid offer");
    throw error;
  }
  if (offer.responder_id !== user.id) throw new Error("Session offer is not addressed to this user");
  const initiator = channel.members.find((member) => member.id === offer.initiator_id);
  if (!initiator) throw new Error("Session initiator is not a channel member");
  const initiatorBundle = await api(`/api/v2/keys/${encodeURIComponent(initiator.username)}`);
  if (!verifyRemoteBundle(initiatorBundle)) throw new Error("Initiator identity bundle signature is invalid");
  if (!verifySessionOffer(initiatorBundle, offer)) throw new Error("Session offer identity signature is invalid");
  const key = await respondSession(identity, offer);
  await saveSessionKey(channel.id, targetEpoch, bytesToBase64(key));
  return key;
}
