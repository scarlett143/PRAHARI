/**
 * What actually travels inside an encrypted envelope — Stage 2's foundation.
 *
 * Until now an envelope carried a bare string, so the only thing a conversation could
 * express was "someone said this". Replies, edits, retractions and reactions each need to
 * say something *about* an earlier message, and the obvious way to build them — a column
 * on the message row, or a separate endpoint per verb — would hand the relay exactly the
 * metadata this product exists to withhold. A server that stores `reaction: 👍` knows what
 * you thought of a message it supposedly cannot read.
 *
 * So every verb is the same sealed envelope with a different payload inside, and the
 * server cannot tell them apart: it sees ciphertext arriving on a channel, and that is
 * all it ever sees. One mechanism, one security review.
 *
 * AUTHORITY. Each envelope's AAD binds the sender id (see aead.js and ratchet.js), so an
 * event claiming to come from someone else fails authentication outright and never
 * reaches this layer. That is what makes it safe to decide "may this person edit that
 * message?" on the client — the alternative would be asking a server that cannot read
 * either message to adjudicate.
 */

/**
 * A NUL byte cannot appear in text a person typed, so it distinguishes a structured
 * payload from the plain strings written before this format existed — without which
 * someone typing valid JSON into the message box would have their words interpreted as a
 * command.
 */
const MARKER = "\u0000";
export const PAYLOAD_VERSION = 1;

export const KIND = {
  MESSAGE: "msg",
  EDIT: "edit",
  DELETE: "del",
  REACTION: "react",
};

const MAX_BODY = 8000;
const MAX_EMOJI = 24;

export function encodePayload(payload) {
  return MARKER + JSON.stringify({ v: PAYLOAD_VERSION, ...payload });
}

/* -- constructors ----------------------------------------------------------- */

export const textMessage = (body, replyTo = null) =>
  encodePayload({ t: KIND.MESSAGE, body, ...(replyTo ? { reply_to: replyTo } : {}) });

export const editMessage = (targetId, body) =>
  encodePayload({ t: KIND.EDIT, target: targetId, body });

export const deleteMessage = (targetId) => encodePayload({ t: KIND.DELETE, target: targetId });

export const reactionEvent = (targetId, emoji, op = "add") =>
  encodePayload({ t: KIND.REACTION, target: targetId, emoji, op });

/* -- decoding --------------------------------------------------------------- */

/**
 * Turn decrypted bytes into a payload.
 *
 * Anything unrecognised degrades to a plain message rather than throwing. A conversation
 * that refuses to render because one participant is running a newer build is a worse
 * outcome than showing that message as text, and this layer has no way to know which
 * version its peers are on.
 */
export function decodePayload(plaintext) {
  if (typeof plaintext !== "string") return { t: KIND.MESSAGE, body: "" };
  if (!plaintext.startsWith(MARKER)) {
    // Written before typed payloads existed. Still a perfectly good message.
    return { t: KIND.MESSAGE, body: plaintext, legacy: true };
  }

  let parsed;
  try {
    parsed = JSON.parse(plaintext.slice(MARKER.length));
  } catch {
    return { t: KIND.MESSAGE, body: plaintext.slice(MARKER.length) };
  }
  if (!parsed || typeof parsed !== "object") {
    return { t: KIND.MESSAGE, body: "" };
  }

  switch (parsed.t) {
    case KIND.EDIT:
      if (!isId(parsed.target) || typeof parsed.body !== "string") break;
      return { t: KIND.EDIT, target: parsed.target, body: clamp(parsed.body, MAX_BODY) };

    case KIND.DELETE:
      if (!isId(parsed.target)) break;
      return { t: KIND.DELETE, target: parsed.target };

    case KIND.REACTION:
      if (!isId(parsed.target) || typeof parsed.emoji !== "string" || !parsed.emoji) break;
      return {
        t: KIND.REACTION,
        target: parsed.target,
        emoji: clamp(parsed.emoji, MAX_EMOJI),
        op: parsed.op === "remove" ? "remove" : "add",
      };

    case KIND.MESSAGE:
    default:
      break;
  }

  return {
    t: KIND.MESSAGE,
    body: typeof parsed.body === "string" ? clamp(parsed.body, MAX_BODY) : "",
    ...(isId(parsed.reply_to) ? { reply_to: parsed.reply_to } : {}),
  };
}

const isId = (value) => typeof value === "string" && value.length > 0 && value.length <= 64;
const clamp = (value, limit) => (value.length > limit ? value.slice(0, limit) : value);

/** Only message payloads occupy a row in the transcript; the rest act on one. */
export const isDisplayable = (payload) => payload?.t === KIND.MESSAGE;
