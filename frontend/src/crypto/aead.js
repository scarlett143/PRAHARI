import { base64ToBytes, bytesToBase64, concatBytes, encoder } from "./bytes.js";

const VERSION = 1;
const NONCE_BYTES = 12;

export function buildAad(senderId, channelId, epoch) {
  return encoder.encode(`prahari-v${VERSION}|${senderId}|${channelId}|${epoch}`);
}

async function importAesKey(rawKey) {
  if (rawKey.length !== 32) throw new Error("AES-256 session key must be 32 bytes");
  return crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

export async function encryptMessage(rawKey, plaintext, { senderId, channelId, epoch }) {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: buildAad(senderId, channelId, epoch), tagLength: 128 },
      await importAesKey(rawKey),
      encoder.encode(plaintext),
    ),
  );
  return bytesToBase64(concatBytes(new Uint8Array([VERSION, NONCE_BYTES]), nonce, ciphertext));
}

export async function decryptMessage(rawKey, envelopeB64, { senderId, channelId, epoch }) {
  const wire = base64ToBytes(envelopeB64);
  if (wire.length < 30 || wire[0] !== VERSION || wire[1] !== NONCE_BYTES) {
    throw new Error("Unsupported or truncated encrypted envelope");
  }
  const nonce = wire.slice(2, 2 + NONCE_BYTES);
  const ciphertext = wire.slice(2 + NONCE_BYTES);
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData: buildAad(senderId, channelId, epoch), tagLength: 128 },
      await importAesKey(rawKey),
      ciphertext,
    );
    return new TextDecoder().decode(plaintext);
  } catch {
    throw new Error("MESSAGE AUTHENTICATION FAILED");
  }
}
