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

async function getAllInPrefix(prefix) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly");
    // "￿" sorts after any character IndexedDB will see in an id, so this bounds the
    // scan to one channel instead of reading every record in the store.
    const range = IDBKeyRange.bound(prefix, `${prefix}￿`);
    const request = tx.objectStore(STORE).getAll(range);
    request.onsuccess = () => resolve(request.result ?? []);
    request.onerror = () => reject(request.error);
  });
}

export const loadIdentity = (username) => get(`identity:${username}`);

/**
 * Usernames this browser holds private keys for.
 *
 * Only the KEYS are read, never the records, so listing identities never pulls private
 * key material into memory. The sign-in screen uses this to answer the one question that
 * decides whether a login can possibly work: are the keys for this account on THIS
 * device? Nothing on the server can answer it, because the server never had them.
 */
export async function listIdentities() {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly");
    const range = IDBKeyRange.bound("identity:", "identity:￿");
    const request = tx.objectStore(STORE).getAllKeys(range);
    request.onsuccess = () =>
      resolve((request.result ?? []).map((key) => String(key).slice("identity:".length)).sort());
    request.onerror = () => reject(request.error);
  });
}

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
/* -- peer trust -------------------------------------------------------------
   What we have seen a contact's keys to be, and whether a human confirmed it.

   Kept local and never sent: this is precisely the record that must not be under the
   relay's control, since its whole purpose is to catch the relay handing over a
   different key than it did last time. */

/** @returns {Promise<{fingerprint: string, firstSeen: string, verifiedAt: string|null}|null>} */
export const loadPeerTrust = (username) => get(`trust:${username}`);

export const savePeerTrust = (username, record) => put(`trust:${username}`, record);

/**
 * Reconcile a freshly fetched bundle against what this browser remembers.
 *
 * @returns {Promise<{state: "new"|"known"|"changed", record: object, previous: object|null}>}
 *   `changed` is the one that matters -- it means the keys behind an existing contact
 *   moved, which is either a reinstall or an attack, and only the contact can say which.
 */
export async function reconcilePeerTrust(username, fingerprint) {
  const previous = await loadPeerTrust(username);
  if (!previous) {
    const record = { fingerprint, firstSeen: new Date().toISOString(), verifiedAt: null };
    await savePeerTrust(username, record);
    return { state: "new", record, previous: null };
  }
  if (previous.fingerprint === fingerprint) {
    return { state: "known", record: previous, previous };
  }
  // Verification does NOT carry across a key change -- that would defeat the point.
  const record = {
    fingerprint,
    firstSeen: new Date().toISOString(),
    verifiedAt: null,
    replacedFingerprint: previous.fingerprint,
    replacedAt: new Date().toISOString(),
  };
  await savePeerTrust(username, record);
  return { state: "changed", record, previous };
}

export async function markPeerVerified(username, fingerprint) {
  const existing = (await loadPeerTrust(username)) ?? {
    fingerprint,
    firstSeen: new Date().toISOString(),
  };
  const record = { ...existing, fingerprint, verifiedAt: new Date().toISOString() };
  await savePeerTrust(username, record);
  return record;
}

export const saveSessionKey = (channelId, epoch, value) => put(`session:${channelId}:${epoch}`, value);
export const loadSessionKey = (channelId, epoch) => get(`session:${channelId}:${epoch}`);

/* -- ratchet ---------------------------------------------------------------- */

export const saveRatchetState = (channelId, value) => put(`ratchet:${channelId}`, value);
export const loadRatchetState = (channelId) => get(`ratchet:${channelId}`);

/**
 * Decrypted message text, held locally.
 *
 * This is a consequence of the ratchet, not a convenience: a message key is destroyed
 * the moment it is used, so nothing can decrypt the same envelope twice. Without a local
 * copy, every message would become unreadable as soon as it had been read once, and
 * reopening a channel would show a wall of failures.
 *
 * It also makes explicit a property the design already implied: history lives on this
 * device. A new browser can read what arrives after it joins, never what came before.
 */
export const savePlaintext = (channelId, messageId, record) =>
  put(`plain:${channelId}:${messageId}`, record);

export async function loadPlaintexts(channelId) {
  const rows = await getAllInPrefix(`plain:${channelId}:`);
  return new Map(rows.filter(Boolean).map((row) => [row.messageId, row]));
}
