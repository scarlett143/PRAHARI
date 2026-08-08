/**
 * Sealing a WireGuard pre-shared key.
 *
 * The assertions are mostly negative, because the requirement is negative: the blob that
 * goes to the control plane must not contain the key, and it must not open for anyone but
 * the gateway it was sealed to.
 */
import test from "node:test";
import assert from "node:assert/strict";

import { generateIdentity } from "./identity.js";
import { respondSession } from "./hybrid.js";
import { decryptMessage } from "./aead.js";
import { PSK_BYTES, generateWireGuardKeypair, sealPresharedKey } from "./vpnPsk.js";
import { base64ToBytes } from "./bytes.js";

const TIMEOUT = 120_000;

/** A gateway account as the API would return it. */
function gatewayBundle(identity, userId = "gateway-account") {
  return {
    user_id: userId,
    x25519_public_key: identity.x25519Public,
    ml_kem_encapsulation_key: identity.mlKemPublic,
  };
}

/** What the gateway does on receipt: unwrap the KEM, then open the AEAD. */
async function openAsGateway(identity, sealedB64, userId = "gateway-account") {
  const envelope = JSON.parse(new TextDecoder().decode(base64ToBytes(sealedB64)));
  const key = await respondSession(identity, {
    x25519_ephemeral_public: envelope.x25519_ephemeral_public,
    ml_kem_ciphertext: envelope.ml_kem_ciphertext,
  });
  return decryptMessage(key, envelope.wrapped, {
    senderId: "vpn-psk",
    channelId: userId,
    epoch: 0,
  });
}

test("the gateway recovers exactly the key that was sealed", { timeout: TIMEOUT }, async () => {
  const gateway = generateIdentity();
  const { psk, sealed } = await sealPresharedKey(gatewayBundle(gateway));

  assert.equal(base64ToBytes(psk).length, PSK_BYTES, "WireGuard needs exactly 32 bytes");
  assert.equal(await openAsGateway(gateway, sealed), psk);
});

test("the sealed blob does not contain the key", { timeout: TIMEOUT }, async () => {
  const gateway = generateIdentity();
  const { psk, sealed } = await sealPresharedKey(gatewayBundle(gateway));

  // The control plane stores exactly this string.
  assert.ok(!sealed.includes(psk), "the pre-shared key survived into the uploaded blob");
});

test("another gateway cannot open it", { timeout: TIMEOUT }, async () => {
  const gateway = generateIdentity();
  const impostor = generateIdentity();
  const { sealed } = await sealPresharedKey(gatewayBundle(gateway));

  await assert.rejects(() => openAsGateway(impostor, sealed));
});

test("a blob sealed for one gateway cannot be replayed at another", { timeout: TIMEOUT }, async () => {
  // The gateway's account id is bound as associated data, so the AEAD fails rather than
  // handing a second endpoint a key its peers would then trust.
  const gateway = generateIdentity();
  const { sealed } = await sealPresharedKey(gatewayBundle(gateway, "gateway-one"));

  await assert.rejects(() => openAsGateway(gateway, sealed, "gateway-two"));
});

test("two seals of the same gateway differ", { timeout: TIMEOUT }, async () => {
  const gateway = generateIdentity();
  const first = await sealPresharedKey(gatewayBundle(gateway));
  const second = await sealPresharedKey(gatewayBundle(gateway));

  assert.notEqual(first.psk, second.psk, "each peer gets its own pre-shared key");
  assert.notEqual(first.sealed, second.sealed);
});

test("a WireGuard key pair is generated locally and is well formed", () => {
  const pair = generateWireGuardKeypair();

  assert.equal(base64ToBytes(pair.private_key).length, 32);
  assert.equal(base64ToBytes(pair.public_key).length, 32);
  assert.notEqual(pair.private_key, pair.public_key);
  assert.notEqual(generateWireGuardKeypair().public_key, pair.public_key);
});
