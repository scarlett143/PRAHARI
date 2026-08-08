/**
 * The pure half of the preference store.
 *
 * Everything here operates on a plain object, so it is testable without IndexedDB. The
 * persistence wrapper around it is a thin get/put and is deliberately not exercised here.
 */
import test from "node:test";
import assert from "node:assert/strict";

import {
  assignFolder,
  bumpUnread,
  clearUnread,
  folderOf,
  isSaved,
  saveMessage,
  setDraft,
  toggleArchived,
  toggleMuted,
  unsaveMessage,
} from "./prefs.js";

const EMPTY = { muted: {}, archived: {}, folders: {}, drafts: {}, unread: {}, saved: [] };

test("mute and archive toggle independently per channel", () => {
  let prefs = toggleMuted(EMPTY, "c1");
  assert.equal(prefs.muted.c1, true);
  assert.equal(prefs.archived.c1, undefined, "muting must not archive");

  prefs = toggleArchived(prefs, "c1");
  assert.equal(prefs.archived.c1, true);
  assert.equal(prefs.muted.c1, true, "archiving must not clear the mute");

  prefs = toggleMuted(prefs, "c1");
  assert.equal(prefs.muted.c1, undefined);
  assert.equal(prefs.archived.c1, true);
});

test("unread counts mentions separately from messages", () => {
  let prefs = bumpUnread(EMPTY, "c1");
  prefs = bumpUnread(prefs, "c1", { mention: true });
  prefs = bumpUnread(prefs, "c1");

  assert.deepEqual(prefs.unread.c1, { count: 3, mentions: 1 });
  assert.equal(prefs.unread.c2, undefined, "another channel is untouched");
});

test("opening a channel clears only its own unread state", () => {
  let prefs = bumpUnread(bumpUnread(EMPTY, "c1"), "c2");
  prefs = clearUnread(prefs, "c1");

  assert.equal(prefs.unread.c1, undefined);
  assert.deepEqual(prefs.unread.c2, { count: 1, mentions: 0 });
  // Clearing something already clear must not churn the object, or every render writes.
  assert.equal(clearUnread(prefs, "c1"), prefs);
});

test("an empty draft is an absent draft", () => {
  let prefs = setDraft(EMPTY, "c1", "half a thought");
  assert.equal(prefs.drafts.c1, "half a thought");

  prefs = setDraft(prefs, "c1", "   ");
  assert.equal(prefs.drafts.c1, undefined, "whitespace must not leave a draft marker behind");
});

test("a channel lives in at most one folder", () => {
  let prefs = assignFolder(EMPTY, "c1", "Operations");
  assert.equal(folderOf(prefs, "c1"), "Operations");

  prefs = assignFolder(prefs, "c1", "Archive review");
  assert.equal(folderOf(prefs, "c1"), "Archive review");
  assert.equal(
    Object.keys(prefs.folders).includes("Operations"),
    false,
    "a folder left empty by a move should not linger in the sidebar",
  );

  prefs = assignFolder(prefs, "c1", "");
  assert.equal(folderOf(prefs, "c1"), "", "a blank folder unfiles the channel");
});

test("moving one channel does not disturb others in the same folder", () => {
  let prefs = assignFolder(assignFolder(EMPTY, "c1", "Ops"), "c2", "Ops");
  prefs = assignFolder(prefs, "c1", "Other");

  assert.equal(folderOf(prefs, "c2"), "Ops");
  assert.equal(folderOf(prefs, "c1"), "Other");
});

test("saving is idempotent and removable", () => {
  const entry = { id: "m1", channelId: "c1", body: "keep this", sender: "alice" };
  let prefs = saveMessage(EMPTY, entry);
  assert.equal(prefs.saved.length, 1);
  assert.equal(isSaved(prefs, "m1"), true);
  assert.ok(prefs.saved[0].savedAt, "the save time is recorded");

  prefs = saveMessage(prefs, entry);
  assert.equal(prefs.saved.length, 1, "saving twice must not duplicate");

  prefs = unsaveMessage(prefs, "m1");
  assert.equal(isSaved(prefs, "m1"), false);
});

test("a saved message keeps its own copy of the body", () => {
  // Not a reference: the ratchet destroys a message key on use, and the author may retract
  // the original, so a pointer would decay into an empty row.
  const prefs = saveMessage(EMPTY, { id: "m1", channelId: "c1", body: "the text", sender: "bob" });
  assert.equal(prefs.saved[0].body, "the text");
});

test("the saved list is bounded", () => {
  let prefs = EMPTY;
  for (let index = 0; index < 520; index += 1) {
    prefs = saveMessage(prefs, { id: `m${index}`, channelId: "c1", body: "x", sender: "a" });
  }
  assert.equal(prefs.saved.length, 500, "this is a browser convenience store, not an archive");
  assert.equal(prefs.saved[0].id, "m519", "newest first");
});
