export const encoder = new TextEncoder();

export function concatBytes(...arrays) {
  const total = arrays.reduce((sum, value) => sum + value.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const value of arrays) {
    out.set(value, offset);
    offset += value.length;
  }
  return out;
}

export function bytesToBase64(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

export function base64ToBytes(value) {
  const binary = atob(value);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}
