const DB_NAME = "prahari-keys-v1";
const STORE = "records";

function openDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function put(key, value) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function get(key) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly");
    const request = tx.objectStore(STORE).get(key);
    request.onsuccess = () => resolve(request.result ?? null);
    request.onerror = () => reject(request.error);
  });
}

export const loadIdentity = (username) => get(`identity:${username}`);

/**
 * Overwriting an identity destroys the only copy of that user's private keys and makes
 * every message they ever received permanently undecryptable. Refuse by default so a
 * mistyped username on the register screen cannot silently wipe a real account.
 */
export async function saveIdentity(username, value, { overwrite = false } = {}) {
  if (!overwrite && (await loadIdentity(username))) {
    throw new Error(
      `An identity for "${username}" already exists in this browser. Log in instead — registering again would destroy the private keys that decrypt your messages.`,
    );
  }
  return put(`identity:${username}`, value);
}
export const saveSessionKey = (channelId, epoch, value) => put(`session:${channelId}:${epoch}`, value);
export const loadSessionKey = (channelId, epoch) => get(`session:${channelId}:${epoch}`);
