/**
 * Fold a stream of decrypted events into the transcript a person reads.
 *
 * The server stores an ordered list of envelopes and knows nothing about what they mean,
 * so assembling "message, later edited, with two reactions, replying to that one" happens
 * entirely here. Every rule below is enforced client-side because the relay has no way to
 * enforce it — it cannot read either the event or the message the event refers to.
 *
 * That is safe rather than naive: an envelope's AAD binds its sender, so an event
 * claiming to be from someone else fails authentication and is discarded long before it
 * reaches this function. `sender_id` on a decrypted event is therefore a fact, not a
 * claim, which is what makes the ownership checks below meaningful.
 */
import { KIND } from "../crypto/payload.js";

/**
 * @param {Array} rows decrypted rows, oldest first, each `{id, sender_id, sender, created_at, payload, authenticated}`
 * @returns {Array} displayable messages with edits, deletions and reactions applied
 */
export function buildTranscript(rows) {
  const messages = [];
  const byId = new Map();

  // First pass: the messages themselves, so later events have something to attach to
  // regardless of the order they arrived in.
  for (const row of rows) {
    if (row.payload?.t !== KIND.MESSAGE) continue;
    const entry = {
      ...row,
      body: row.payload.body ?? "",
      replyTo: row.payload.reply_to ?? null,
      editedAt: null,
      // The relay's own soft-delete flag counts as a retraction on its own. The author's
      // sealed `del` event is authoritative, but it may sit outside the window we loaded
      // while the blanked row is right here -- and rendering that as an empty message
      // would be worse than rendering it as what it is.
      deleted: Boolean(row.deleted_at),
      reactions: new Map(),
      pinned: false,
      pinnedBy: null,
    };
    messages.push(entry);
    byId.set(row.id, entry);
  }

  for (const row of rows) {
    const payload = row.payload;
    if (!payload || payload.t === KIND.MESSAGE) continue;
    const target = byId.get(payload.target);
    if (!target) continue; // Refers to something outside the window we loaded.

    switch (payload.t) {
      case KIND.EDIT:
        // Only the author may rewrite their own words. Anyone else's edit is discarded
        // rather than shown, because a transcript that can be rewritten by a third party
        // is worse than one that cannot be edited at all.
        if (row.sender_id !== target.sender_id) break;
        // Last edit wins. Events arrive in server order, so this is simply the newest.
        target.body = payload.body;
        target.editedAt = row.created_at;
        break;

      case KIND.DELETE:
        if (row.sender_id !== target.sender_id) break;
        target.deleted = true;
        target.body = "";
        target.reactions = new Map();
        // A retracted message cannot stay pinned to the top of the channel; that would
        // leave a tombstone in the most prominent place in the conversation.
        target.pinned = false;
        target.pinnedBy = null;
        break;

      case KIND.PIN:
        // Last event wins, whoever sent it. A pin is channel-wide state rather than a
        // personal one, so unpinning has to work for everyone -- otherwise one member
        // could pin something the rest of the channel could not remove. Restricting who
        // may pin is a Stage 4 question, once channels have roles to restrict it to.
        if (target.deleted) break;
        target.pinned = payload.op !== "remove";
        target.pinnedBy = target.pinned ? row.sender_name : null;
        break;

      case KIND.REACTION: {
        // Anyone in the channel may react, but only ever as themselves.
        const people = target.reactions.get(payload.emoji) ?? new Set();
        if (payload.op === "remove") people.delete(row.sender_id);
        else people.add(row.sender_id);
        if (people.size === 0) target.reactions.delete(payload.emoji);
        else target.reactions.set(payload.emoji, people);
        break;
      }

      default:
        break;
    }
  }

  // A deleted message keeps its place in the transcript. Removing the row would silently
  // renumber the conversation around it and hide that anything was withdrawn.
  return messages.map((entry) => ({
    ...entry,
    reactions: [...entry.reactions.entries()]
      .map(([emoji, people]) => ({ emoji, count: people.size, people: [...people] }))
      .sort((left, right) => right.count - left.count || left.emoji.localeCompare(right.emoji)),
  }));
}

/**
 * Usernames mentioned in a message body.
 *
 * Entirely client-side, and it has to be: the body is ciphertext to the relay, so a
 * server-side mention index would mean handing it the plaintext to search. Detection
 * therefore happens after decryption, here, on whatever this device can already read.
 *
 * A consequence worth knowing rather than hiding: this only sees channels you have open.
 * PRAHARI cannot tell you that a channel you are not looking at mentions you without
 * decrypting its messages, and in a channel using the Double Ratchet, decrypting ahead of
 * time consumes chain keys that belong to messages you have not displayed yet.
 */
const MENTION_PATTERN = /(^|[^\w@])@([a-zA-Z0-9_.-]{1,64})/g;

export function findMentions(body) {
  if (typeof body !== "string" || !body.includes("@")) return [];
  const found = new Set();
  for (const match of body.matchAll(MENTION_PATTERN)) found.add(match[2].toLowerCase());
  return [...found];
}

/** Case-insensitive: people type a name the way it reads, not the way it is stored. */
export const mentionsUser = (body, username) =>
  Boolean(username) && findMentions(body).includes(username.toLowerCase());

/** Quoted preview for a reply, kept short enough to sit above the reply itself. */
export function quoteFor(messages, replyToId, limit = 120) {
  const source = messages.find((entry) => entry.id === replyToId);
  if (!source) return null;
  if (source.deleted) {
    return { sender: source.sender_name, body: "Message deleted", missing: true };
  }
  const body = source.body.length > limit ? `${source.body.slice(0, limit)}…` : source.body;
  return { sender: source.sender_name, body };
}
