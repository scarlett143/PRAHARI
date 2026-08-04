import { x25519 } from "@noble/curves/ed25519.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { base64ToBytes, bytesToBase64, concatBytes, encoder } from "./bytes.js";

const KDF_LABEL = encoder.encode("prahari/hybrid-kem/v1/aes256gcm");
const ZERO_SALT = new Uint8Array(32);

async function deriveKey(xSecret, kemSecret, responderX, responderKem, ephemeralX, kemCiphertext) {
  const ikm = concatBytes(xSecret, kemSecret);
  const info = concatBytes(KDF_LABEL, responderX, responderKem, ephemeralX, kemCiphertext);
  const keyMaterial = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: ZERO_SALT, info },
    keyMaterial,
    256,
  );
  return new Uint8Array(bits);
}

export async function initiateSession(remoteBundle) {
  const responderX = base64ToBytes(remoteBundle.x25519_public_key);
  const responderKem = base64ToBytes(remoteBundle.ml_kem_encapsulation_key);
  const ephemeral = x25519.keygen();
  const xSecret = x25519.getSharedSecret(ephemeral.secretKey, responderX);
  const kem = ml_kem768.encapsulate(responderKem);
  const key = await deriveKey(
    xSecret,
    kem.sharedSecret,
    responderX,
    responderKem,
    ephemeral.publicKey,
    kem.cipherText,
  );
  return {
    key,
    offer: {
      x25519_ephemeral_public: bytesToBase64(ephemeral.publicKey),
      ml_kem_ciphertext: bytesToBase64(kem.cipherText),
    },
  };
}

export async function respondSession(identity, offer) {
  const responderX = base64ToBytes(identity.x25519Public);
  const responderKem = base64ToBytes(identity.mlKemPublic);
  const ephemeralX = base64ToBytes(offer.x25519_ephemeral_public);
  const kemCiphertext = base64ToBytes(offer.ml_kem_ciphertext);
  const xSecret = x25519.getSharedSecret(base64ToBytes(identity.x25519Secret), ephemeralX);
  const kemSecret = ml_kem768.decapsulate(kemCiphertext, base64ToBytes(identity.mlKemSecret));
  return deriveKey(xSecret, kemSecret, responderX, responderKem, ephemeralX, kemCiphertext);
}
