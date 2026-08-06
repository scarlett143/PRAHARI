/**
 * Publish the public half of an identity to the server.
 *
 * Shared because two paths need it: signing in when the server has no verified bundle,
 * and unlocking a locked identity, where the keys only become available after the
 * passcode is entered — well after sign-in has finished.
 */
import { authApi } from "../lib/api.js";
import { signBundle, signChallenge } from "./identity.js";

export async function publishKeyBundle(identity) {
  const { challenge } = await authApi.challenge();
  await authApi.publishKeys({
    x25519_public_key: identity.x25519Public,
    ml_kem_encapsulation_key: identity.mlKemPublic,
    challenge_signature: signChallenge(identity, challenge),
    bundle_signature: signBundle(identity),
  });
}
