/**
 * Browser side of WebAuthn.
 *
 * Thin on purpose. Everything that decides anything happens on the server -- the challenge
 * is issued there, the origin and relying party are checked there, the signature is
 * verified there. This file only translates between the shapes the WebAuthn API wants and
 * the base64url the transport uses, and a bug here can make a ceremony fail but cannot
 * make a bad one succeed.
 *
 * The public key is taken from `getPublicKey()`, which hands back SPKI DER. That is what
 * lets the server skip parsing the attestation object entirely; see
 * backend/app/crypto/webauthn.py.
 */
import { base64ToBytes, bytesToBase64 } from "./bytes.js";

/** WebAuthn speaks base64url without padding; the API elsewhere uses standard base64. */
const toB64Url = (bytes) =>
  bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

const fromB64Url = (value) =>
  base64ToBytes(value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "="));

/** Whether this browser can do platform passkeys at all. */
export const passkeysSupported = () =>
  typeof window !== "undefined" &&
  Boolean(window.PublicKeyCredential) &&
  Boolean(navigator.credentials?.create);

export async function createPasskey(options) {
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: fromB64Url(options.challenge),
      rp: { id: options.rp.id, name: options.rp.name },
      user: {
        id: fromB64Url(options.user.id),
        name: options.user.name,
        displayName: options.user.displayName,
      },
      // ES256 first, then RS256 and Ed25519. All three are verified server-side; the order
      // is preference, not a restriction.
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
        { type: "public-key", alg: -8 },
      ],
      // Nothing is done with an attestation statement, so asking for one would collect a
      // hardware identifier this system has no use for.
      attestation: "none",
      authenticatorSelection: { userVerification: "preferred", residentKey: "preferred" },
      excludeCredentials: (options.excludeCredentials ?? []).map((id) => ({
        type: "public-key",
        id: fromB64Url(id),
      })),
      timeout: options.timeout_ms,
    },
  });
  if (!credential) throw new Error("No passkey was created");

  const publicKey = credential.response.getPublicKey?.();
  if (!publicKey) {
    // Rather than fall back to decoding the attestation object here, which is the entire
    // complexity this design avoids.
    throw new Error("This browser is too old to register a passkey");
  }

  return {
    credential_id: toB64Url(new Uint8Array(credential.rawId)),
    client_data_json: toB64Url(new Uint8Array(credential.response.clientDataJSON)),
    authenticator_data: toB64Url(new Uint8Array(credential.response.getAuthenticatorData())),
    public_key: bytesToBase64(new Uint8Array(publicKey)),
  };
}

export async function assertPasskey(options) {
  const credential = await navigator.credentials.get({
    publicKey: {
      challenge: fromB64Url(options.challenge),
      rpId: options.rp_id,
      allowCredentials: (options.allowCredentials ?? []).map((id) => ({
        type: "public-key",
        id: fromB64Url(id),
      })),
      userVerification: "preferred",
      timeout: options.timeout_ms,
    },
  });
  if (!credential) throw new Error("No passkey was offered");

  return {
    credential_id: toB64Url(new Uint8Array(credential.rawId)),
    client_data_json: toB64Url(new Uint8Array(credential.response.clientDataJSON)),
    authenticator_data: toB64Url(new Uint8Array(credential.response.authenticatorData)),
    signature: toB64Url(new Uint8Array(credential.response.signature)),
  };
}
