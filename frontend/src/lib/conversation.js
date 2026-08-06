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
      deleted: false,
      reactions: new Map(),
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

/** Quoted preview for a reply, kept short enough to sit above the reply itself. */
export function quoteFor(messages, replyToId, limit = 120) {
  const source = messages.find((entry) => entry.id === replyToId);
  if (!source) return null;
  if (source.deleted) return { sender: source.sender, body: "Message deleted", missing: true };
  const body = source.body.length > limit ? `${source.body.slice(0, limit)}…` : source.body;
  return { sender: source.sender, body };
}
