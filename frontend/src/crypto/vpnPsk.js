/**
 * Sealing a WireGuard pre-shared key to a gateway.
 *
 * This is the only part of the VPN feature that is cryptography, and it is where the
 * post-quantum claim actually lives. WireGuard's handshake is X25519, which falls to a
 * sufficiently capable quantum computer. It also mixes in an optional 32-byte pre-shared
 * key, and a tunnel whose PSK an attacker never obtained stays secure even when the
 * X25519 half does not. So the PSK is the thing that must not travel in the clear.
 *
 * It does not. The PSK is generated here, sealed to the gateway's published
 * X25519 + ML-KEM-768 bundle with the same hybrid KEM the messaging layer uses, and
 * handed to the control plane as ciphertext. PRAHARI stores a blob it cannot open; only
 * the gateway's identity key opens it.
 *
 * The narrow version of the claim, worth keeping straight: this does not make WireGuard
 * post-quantum. It distributes the one input that gives WireGuard post-quantum resistance
 * over a channel that already has it, without the control plane learning the input.
 */
import { x25519 } from "@noble/curves/ed25519.js";

import { bytesToBase64 } from "./bytes.js";
import { initiateSession } from "./hybrid.js";
import { encryptMessage } from "./aead.js";

/** WireGuard pre-shared keys are exactly 32 bytes. */
export const PSK_BYTES = 32;

/**
 * Generate a PSK and seal it to the gateway.
 *
 * @param {object} gatewayBundle the gateway account's published key bundle
 * @returns {Promise<{psk: string, sealed: string}>} the PSK for local use, and the blob to upload
 */
export async function sealPresharedKey(gatewayBundle) {
  const psk = crypto.getRandomValues(new Uint8Array(PSK_BYTES));

  // The same KEM that opens a channel, used to wrap one key. Reusing `initiateSession`
  // rather than assembling a second sealing scheme means there is one hybrid handshake in
  // this codebase to review, not two that drift apart.
  const { key, offer } = await initiateSession(gatewayBundle);
  // Base64 rather than raw bytes because the envelope format is text-oriented; the
  // gateway decodes it back to 32 bytes before handing it to WireGuard.
  const wrapped = await encryptMessage(key, bytesToBase64(psk), {
    // Bound as associated data so a blob sealed for one gateway cannot be replayed at
    // another: the AEAD fails rather than yielding a key the wrong endpoint would trust.
    senderId: "vpn-psk",
    channelId: gatewayBundle.user_id,
    epoch: 0,
  });

  return {
    // Kept only by the caller, for its own WireGuard config. Never uploaded.
    psk: bytesToBase64(psk),
    sealed: bytesToBase64(
      new TextEncoder().encode(
        JSON.stringify({
          v: 1,
          x25519_ephemeral_public: offer.x25519_ephemeral_public,
          ml_kem_ciphertext: offer.ml_kem_ciphertext,
          wrapped,
        }),
      ),
    ),
  };
}

/** A fresh WireGuard key pair, generated here and never uploaded in full. */
export function generateWireGuardKeypair() {
  const secretKey = crypto.getRandomValues(new Uint8Array(32));
  // WireGuard uses Curve25519 with the standard clamping, which x25519.getPublicKey applies.
  const publicKey = x25519.getPublicKey(secretKey);
  return {
    private_key: bytesToBase64(secretKey),
    public_key: bytesToBase64(publicKey),
  };
}

export const KEM_ALGORITHM = "X25519 + ML-KEM-768";
