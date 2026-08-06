import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { base64ToBytes, bytesToBase64, concatBytes, encoder } from "./bytes.js";

const BUNDLE_LABEL = encoder.encode("PRAHARI-KEY-BUNDLE-V1\0");

export function generateIdentity() {
  const ed = ed25519.keygen();
  const x = x25519.keygen();
  const kem = ml_kem768.keygen();
  return {
    ed25519Secret: bytesToBase64(ed.secretKey),
    ed25519Public: bytesToBase64(ed.publicKey),
    x25519Secret: bytesToBase64(x.secretKey),
    x25519Public: bytesToBase64(x.publicKey),
    mlKemSecret: bytesToBase64(kem.secretKey),
    mlKemPublic: bytesToBase64(kem.publicKey),
  };
}

export function signChallenge(identity, challenge) {
  const signature = ed25519.sign(
    encoder.encode(challenge),
    base64ToBytes(identity.ed25519Secret),
  );
  return bytesToBase64(signature);
}

export function bundlePayload(xPublic, mlPublic) {
  return concatBytes(BUNDLE_LABEL, xPublic, mlPublic);
}

export function signBundle(identity) {
  const xPublic = base64ToBytes(identity.x25519Public);
  const mlPublic = base64ToBytes(identity.mlKemPublic);
  return bytesToBase64(
    ed25519.sign(bundlePayload(xPublic, mlPublic), base64ToBytes(identity.ed25519Secret)),
  );
}

export function verifyRemoteBundle(bundle) {
  if (!bundle?.key_verified) return false;
  return ed25519.verify(
    base64ToBytes(bundle.bundle_signature),
    bundlePayload(
      base64ToBytes(bundle.x25519_public_key),
      base64ToBytes(bundle.ml_kem_encapsulation_key),
    ),
    base64ToBytes(bundle.ed25519_public_key),
    { zip215: false },
  );
}

const SESSION_OFFER_LABEL = encoder.encode("PRAHARI-SESSION-OFFER-V1\0");

/**
 * `wrappedKey` is the group key sealed to this one recipient, and it is signed over
 * rather than merely sent alongside. Otherwise the relay could hand a member a wrapped
 * key taken from another channel or epoch and they would accept it -- the KEM half would
 * still verify. Empty for two-party offers, which keeps their payload byte-identical to
 * what was signed before groups existed.
 */
export function sessionOfferPayload({
  channelId,
  epoch,
  responderId,
  ephemeralPublic,
  kemCiphertext,
  wrappedKey = new Uint8Array(0),
}) {
  return concatBytes(
    SESSION_OFFER_LABEL,
    encoder.encode(channelId), new Uint8Array([0]),
    encoder.encode(String(epoch)), new Uint8Array([0]),
    encoder.encode(responderId), new Uint8Array([0]),
    ephemeralPublic,
    kemCiphertext,
    wrappedKey,
  );
}

const offerBytes = (offer) => ({
  channelId: offer.channel_id,
  epoch: offer.key_epoch,
  responderId: offer.responder_id,
  ephemeralPublic: base64ToBytes(offer.x25519_ephemeral_public),
  kemCiphertext: base64ToBytes(offer.ml_kem_ciphertext),
  wrappedKey: offer.wrapped_group_key
    ? base64ToBytes(offer.wrapped_group_key)
    : new Uint8Array(0),
});

export function signSessionOffer(identity, offer) {
  const payload = sessionOfferPayload(offerBytes(offer));
  return bytesToBase64(ed25519.sign(payload, base64ToBytes(identity.ed25519Secret)));
}

export function verifySessionOffer(remoteBundle, offer) {
  const payload = sessionOfferPayload(offerBytes(offer));
  return ed25519.verify(
    base64ToBytes(offer.offer_signature),
    payload,
    base64ToBytes(remoteBundle.ed25519_public_key),
    { zip215: false },
  );
}
