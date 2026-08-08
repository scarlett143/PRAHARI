/**
 * Per-account console preferences: drafts, mute, archive, folders, saved messages and
 * unread counts.
 *
 * All of it is local, and that is a design decision rather than an unfinished one.
 *
 * Every item here is *personal* state — which conversations you have muted, how you have
 * filed them, what you started typing. None of it is something another member needs to
 * agree with, so none of it has to be shared. Sending it to the relay would hand over a
 * detailed picture of what you care about and who you are avoiding, all of it perfectly
 * readable, from a server whose entire premise is that it cannot read your messages.
 * Muting a channel is not more secret than the channel's contents, but there is no reason
 * to give it away for free.
 *
 * It costs the server nothing: no columns, no endpoints, no requests. On a box shared with
 * the operator's other services that is the difference between a feature and a bill.
 *
 * The trade is honest and worth stating: preferences do not follow you to another browser.
 * Syncing them is a multi-device question (Stage 5), and the right shape then is a sealed
 * blob the relay stores without reading — not the plain columns this avoids today.
 *
 * Pins are deliberately NOT here. A pin is shared state that everyone in a channel sees,
 * so it travels as a sealed envelope like any other conversation verb; see crypto/payload.js.
 */
const DB_NAME = "prahari-prefs-v1";
const STORE = "prefs";

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

async function read(key, fallback) {
  try {
    const db = await openDb();
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readonly");
      const request = tx.objectStore(STORE).get(key);
      request.onsuccess = () => resolve(request.result ?? fallback);
      request.onerror = () => reject(request.error);
    });
  } catch {
    // A preference is never worth failing a render over. Private browsing and blocked
    // storage both land here, and the console must still open.
    return fallback;
  }
}

async function write(key, value) {
  try {
    const db = await openDb();
    await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).put(value, key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } catch {
    /* See above: preferences degrade, they do not throw. */
  }
}

/**
 * The whole preference set for one account, in one record.
 *
 * One record rather than a key per channel: the console reads all of this on every render
 * of the sidebar, and a single get beats one per channel across a workspace.
 */
const EMPTY = {
  muted: {},     // channelId -> true
  archived: {},  // channelId -> true
  folders: {},   // folderName -> [channelId]
  drafts: {},    // channelId -> text
  unread: {},    // channelId -> { count, mentions }
  saved: [],     // [{ id, channelId, body, sender, savedAt }]
};

const keyFor = (username) => `prefs:${username}`;

export async function loadPrefs(username) {
  const stored = await read(keyFor(username), null);
  // Spread over EMPTY so a record written by an older build gains new fields rather than
  // returning undefined into the middle of a render.
  return { ...EMPTY, ...(stored ?? {}) };
}

export async function savePrefs(username, prefs) {
  await write(keyFor(username), prefs);
  return prefs;
}

/** Apply a change and persist it in one step, returning the new set. */
export async function updatePrefs(username, mutate) {
  const current = await loadPrefs(username);
  const next = mutate({ ...current });
  await savePrefs(username, next);
  return next;
}

/* -- helpers over the shape ------------------------------------------------- */

const toggleFlag = (map, channelId) => {
  const next = { ...map };
  if (next[channelId]) delete next[channelId];
  else next[channelId] = true;
  return next;
};

export const toggleMuted = (prefs, channelId) => ({
  ...prefs,
  muted: toggleFlag(prefs.muted, channelId),
});

export const toggleArchived = (prefs, channelId) => ({
  ...prefs,
  archived: toggleFlag(prefs.archived, channelId),
});

/** Note the count and whether any of it named you; the badge distinguishes the two. */
export function bumpUnread(prefs, channelId, { mention = false } = {}) {
  const entry = prefs.unread[channelId] ?? { count: 0, mentions: 0 };
  return {
    ...prefs,
    unread: {
      ...prefs.unread,
      [channelId]: {
        count: entry.count + 1,
        mentions: entry.mentions + (mention ? 1 : 0),
      },
    },
  };
}

export function clearUnread(prefs, channelId) {
  if (!prefs.unread[channelId]) return prefs;
  const unread = { ...prefs.unread };
  delete unread[channelId];
  return { ...prefs, unread };
}

export const setDraft = (prefs, channelId, text) => {
  const drafts = { ...prefs.drafts };
  // An empty draft is an absent draft; keeping "" would show a draft marker on every
  // channel the user has ever opened.
  if (text.trim()) drafts[channelId] = text;
  else delete drafts[channelId];
  return { ...prefs, drafts };
};

export function assignFolder(prefs, channelId, folder) {
  const folders = {};
  // A channel belongs to at most one folder, so it is removed from the others rather than
  // added to a second -- two homes for one channel is how a sidebar starts lying.
  for (const [name, members] of Object.entries(prefs.folders)) {
    const kept = members.filter((id) => id !== channelId);
    if (kept.length) folders[name] = kept;
  }
  if (folder) folders[folder] = [...(folders[folder] ?? []), channelId];
  return { ...prefs, folders };
}

export const folderOf = (prefs, channelId) =>
  Object.entries(prefs.folders).find(([, members]) => members.includes(channelId))?.[0] ?? "";

const SAVED_LIMIT = 500;

export function saveMessage(prefs, entry) {
  if (prefs.saved.some((item) => item.id === entry.id)) return prefs;
  return {
    ...prefs,
    // Newest first, and bounded: this is a convenience store in a browser, not an archive.
    saved: [{ ...entry, savedAt: new Date().toISOString() }, ...prefs.saved].slice(0, SAVED_LIMIT),
  };
}

export const unsaveMessage = (prefs, messageId) => ({
  ...prefs,
  saved: prefs.saved.filter((item) => item.id !== messageId),
});

export const isSaved = (prefs, messageId) => prefs.saved.some((item) => item.id === messageId);
