import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { authApi, linkApi, workspaceApi } from "../lib/api.js";
import { verifyRemoteBundle } from "../crypto/identity.js";
import { formatForDisplay, identityFingerprint, safetyNumber } from "../crypto/verification.js";
import { verifyKeyHistory } from "../crypto/transparency.js";
import { markPeerVerified, reconcilePeerTrust } from "../storage/keys.js";
import {
  decryptForChannel,
  encryptForChannel,
  isGroupChannel,
  openChannelSession,
} from "../crypto/channelCrypto.js";
import { loadPlaintexts, savePlaintext } from "../storage/keys.js";
import {
  decodePayload,
  deleteMessage as deletePayload,
  editMessage as editPayload,
  pinEvent,
  reactionEvent,
  textMessage,
} from "../crypto/payload.js";
import { buildTranscript, mentionsUser, quoteFor } from "../lib/conversation.js";
import {
  assignFolder,
  bumpUnread,
  clearUnread,
  folderOf,
  isSaved,
  loadPrefs,
  saveMessage,
  setDraft as setDraftPref,
  toggleArchived,
  toggleMuted,
  unsaveMessage,
  updatePrefs,
} from "../storage/prefs.js";
import { Alert, Badge, EmptyState, Field, Panel } from "../components/ui.jsx";
import Linkify, { LinkCard, extractLinks } from "../components/Linkify.jsx";
import { InvitePanel, LinkRequests, PeerDirectory } from "../components/DirectoryPanel.jsx";
import { clockTime } from "../lib/format.js";

/** A typing notice is stale almost immediately; peers stop showing it on their own. */
const TYPING_TTL_MS = 4000;
/** Long enough that a pause for thought is not reported as "stopped typing". */
const TYPING_IDLE_MS = 2500;

/** Offered inline on every message. Any emoji is valid on the wire -- these are only the
 *  ones reachable without a picker, which Stage 2 does not have yet. */
const QUICK_REACTIONS = ["👍", "✅", "❓", "🙏"];

/** Human-to-human secure messaging over the same hybrid handshake the aircraft link
 *  uses: a Double Ratchet between two people, a shared epoch key among more. */
export default function MessagingRoute({
  user,
  identity,
  socketEvent,
  socketSend,
  // Owned by App now that the switcher lives in the masthead, which outlives this view.
  workspaces,
  activeWorkspaceId,
  onWorkspacesChanged,
}) {
  const [channel, setChannel] = useState(null);
  const [messages, setMessages] = useState([]);
  const [replyTo, setReplyTo] = useState(null);
  const [editing, setEditing] = useState(null);
  const [prefs, setPrefs] = useState(null);
  const [showArchived, setShowArchived] = useState(false);
  const [showSaved, setShowSaved] = useState(false);
  const [draft, setDraft] = useState("");
  const [sessionStatus, setSessionStatus] = useState({ tone: "neutral", text: "No channel open" });
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [presence, setPresence] = useState({});
  const [links, setLinks] = useState({ incoming: [], outgoing: [], history: [] });
  const [typingPeers, setTypingPeers] = useState({});
  const [directoryToken, setDirectoryToken] = useState(0);

  const logRef = useRef(null);
  const channelRef = useRef(null);
  const acknowledged = useRef(new Set());
  const typingSentAt = useRef(0);
  const typingStopTimer = useRef(null);
  const draftSaveTimer = useRef(null);

  channelRef.current = channel;

  // Events are stored in arrival order; this is where they become a conversation.
  const transcript = useMemo(() => buildTranscript(messages), [messages]);
  const pinned = useMemo(() => transcript.filter((item) => item.pinned), [transcript]);

  /** Persist a preference change and reflect it immediately. */
  const editPrefs = useCallback(
    (mutate) => updatePrefs(user.username, mutate).then(setPrefs),
    [user.username],
  );

  useEffect(() => {
    loadPrefs(user.username).then(setPrefs);
  }, [user.username]);

  const activeWorkspace = useMemo(
    () => workspaces.find((item) => item.id === activeWorkspaceId) || workspaces[0] || null,
    [workspaces, activeWorkspaceId],
  );

  /* -- loading ------------------------------------------------------------- */

  // Delegated upward: App holds the list, so a change here has to reach the masthead.
  const refreshWorkspaces = useCallback(
    async () => (await onWorkspacesChanged?.()) ?? workspaces,
    [onWorkspacesChanged, workspaces],
  );

  const refreshLinks = useCallback(async () => {
    try {
      setLinks(await linkApi.list());
    } catch {
      /* the link list is supplementary; a failure here must not blank the chat */
    }
  }, []);

  const refreshPresence = useCallback(async () => {
    try {
      const snapshot = await workspaceApi.presence();
      const next = {};
      for (const peer of snapshot.peers) next[peer.id] = peer.online;
      setPresence(next);
    } catch {
      /* presence is decoration; never surface it as a chat error */
    }
  }, []);

  /**
   * Decrypt one envelope, or return what was already decrypted.
   *
   * A ratchet message key is destroyed once used, so the same envelope can never be
   * decrypted twice. The locally stored plaintext is therefore the only copy after the
   * first read -- consulting it first is what makes reopening a channel work at all.
   */
  const decode = useCallback(
    async (message, target, cache) => {
      // The relay blanks the envelope of a retracted message, so there is nothing to
      // decrypt and trying would surface a decryption failure where a deliberate
      // withdrawal happened. `buildTranscript` renders the tombstone from `deleted_at`.
      if (message.deleted_at) {
        return { ...message, plaintext: "", payload: { t: "msg", body: "" }, authenticated: true };
      }
      const known = cache?.get(message.id);
      if (known) {
        return {
          ...message,
          plaintext: known.plaintext,
          payload: decodePayload(known.plaintext),
          authenticated: known.authenticated,
        };
      }
      try {
        const plaintext = await decryptForChannel(target, user, identity, message);
        await savePlaintext(target.id, message.id, {
          messageId: message.id,
          plaintext,
          authenticated: true,
        });
        return { ...message, plaintext, payload: decodePayload(plaintext), authenticated: true };
      } catch (caught) {
        // Deliberately not cached: a failure here can be transient (the peer has not
        // published their offer yet), and storing it would make it permanent.
        // An undecryptable row still occupies a place in the transcript, so it needs a
        // payload shape -- with the failure as its body.
        return {
          ...message,
          plaintext: caught.message,
          payload: { t: "msg", body: caught.message },
          authenticated: false,
        };
      }
    },
    [user, identity],
  );

  const loadMessages = useCallback(
    async (target) => {
      if (!target) return;
      const [rows, cache] = await Promise.all([
        workspaceApi.messages(target.id),
        loadPlaintexts(target.id),
      ]);
      // Strictly sequential: the ratchet is a state machine, so decrypting concurrently
      // would interleave chain advances and corrupt it.
      const decoded = [];
      for (const row of rows) decoded.push(await decode(row, target, cache));
      setMessages(decoded);
    },
    [decode],
  );

  const openChannel = useCallback(
    async (channelId) => {
      setError("");
      const details = await workspaceApi.channel(channelId);
      setChannel(details);
      setTypingPeers({});
      setReplyTo(null);
      setEditing(null);
      // Opening a channel is what marks it read, and it restores whatever was half-typed
      // here last time. The draft is per channel, so switching away mid-sentence and
      // coming back does not lose the sentence.
      const stored = await updatePrefs(user.username, (draftPrefs) =>
        clearUnread(draftPrefs, channelId),
      );
      setPrefs(stored);
      setDraft(stored.drafts[channelId] ?? "");
      setSessionStatus({ tone: "neutral", text: "Establishing hybrid session…" });
      try {
        const { label } = await openChannelSession(details, user, identity);
        setSessionStatus({ tone: "good", text: label });
      } catch (caught) {
        setSessionStatus({ tone: "warning", text: caught.message });
      }
      await loadMessages(details);
    },
    [user, identity, loadMessages],
  );

  useEffect(() => {
    refreshWorkspaces().catch((caught) => setError(caught.message));
    refreshLinks();
    refreshPresence();
  }, [refreshWorkspaces, refreshLinks, refreshPresence]);

  useEffect(() => {
    if (!activeWorkspace) return;
    const stillOpen = activeWorkspace.channels.some((item) => item.id === channel?.id);
    const first = activeWorkspace.channels[0];
    if (!stillOpen && first) openChannel(first.id).catch((caught) => setError(caught.message));
  }, [activeWorkspace, channel?.id, openChannel]);

  /* -- realtime ------------------------------------------------------------ */

  useEffect(() => {
    if (!socketEvent) return;
    const current = channelRef.current;

    switch (socketEvent.type) {
      case "connected": {
        // Snapshot closes the join race: peers already online before we connected.
        const online = {};
        for (const id of socketEvent.online_peers || []) online[id] = true;
        setPresence((prev) => ({ ...prev, ...online }));
        break;
      }

      case "presence.changed":
        setPresence((prev) => ({ ...prev, [socketEvent.user_id]: socketEvent.online }));
        if (!socketEvent.online) {
          setTypingPeers((prev) => {
            const next = { ...prev };
            delete next[socketEvent.user_id];
            return next;
          });
        }
        break;

      case "message.created": {
        const incoming = socketEvent.message;

        // A message for a channel we are not looking at only raises a badge. Counting it
        // costs nothing extra -- the relay already fans this frame out to every member,
        // so the alternative would be polling every channel for something we were just
        // told. The envelope is deliberately left sealed: decrypting ahead of time to
        // check for a mention would consume ratchet chain keys belonging to messages this
        // device has not displayed yet, so an unopened channel's badge counts messages,
        // never mentions.
        if (socketEvent.channel_id !== current?.id) {
          if (incoming.sender_id !== user.id) {
            editPrefs((draftPrefs) => bumpUnread(draftPrefs, socketEvent.channel_id));
          }
          break;
        }
        if (!current) break;
        // Append rather than refetch: the envelope is already in the frame, so the
        // message renders without a round trip and without re-running the handshake.
        //
        // Our own messages are skipped here: `send` already recorded the plaintext, and
        // running the echo through the ratchet would consume a receiving-chain key that
        // belongs to a message from the peer.
        if (incoming.sender_id !== user.id) {
          decode(incoming, current).then((decoded) => {
            setMessages((prev) =>
              prev.some((item) => item.id === decoded.id) ? prev : [...prev, decoded],
            );
          });
        }
        setTypingPeers((prev) => {
          const next = { ...prev };
          delete next[incoming.sender_id];
          return next;
        });
        break;
      }

      case "message.deleted": {
        if (!current || socketEvent.channel_id !== current.id) break;
        // Mirrors what the relay just did to its own copy. The author's sealed `del`
        // event arrives separately as an ordinary message and is what actually decides
        // this; acting on the notice too simply means the tombstone appears at once
        // rather than after the next reload.
        setMessages((prev) =>
          prev.map((item) =>
            item.id === socketEvent.message_id
              ? { ...item, deleted_at: socketEvent.deleted_at }
              : item,
          ),
        );
        break;
      }

      case "message.receipts": {
        if (!current || socketEvent.channel_id !== current.id) break;
        const byId = new Map(
          (socketEvent.receipts || []).map((row) => [row.message_id, row]),
        );
        setMessages((prev) =>
          prev.map((item) =>
            byId.has(item.id)
              ? {
                  ...item,
                  receipt: {
                    delivered_at: byId.get(item.id).delivered_at,
                    read_at: byId.get(item.id).read_at,
                  },
                }
              : item,
          ),
        );
        break;
      }

      case "typing": {
        if (!current || socketEvent.channel_id !== current.id) break;
        if (socketEvent.state === "stop") {
          setTypingPeers((prev) => {
            const next = { ...prev };
            delete next[socketEvent.user_id];
            return next;
          });
        } else {
          setTypingPeers((prev) => ({
            ...prev,
            [socketEvent.user_id]: { username: socketEvent.username, at: Date.now() },
          }));
        }
        break;
      }

      case "session.offer_created":
      case "channel.epoch_rotated":
        if (current && socketEvent.channel_id === current.id) {
          openChannel(current.id).catch((caught) => setError(caught.message));
        }
        break;

      case "link.requested":
      case "link.declined":
      case "link.cancelled":
        refreshLinks();
        setDirectoryToken((value) => value + 1);
        break;

      case "link.accepted":
      case "server.member_joined":
      case "server.member_added":
        // A new peer or channel exists now; the sidebar must show it without a reload.
        refreshWorkspaces().catch(() => {});
        refreshLinks();
        refreshPresence();
        setDirectoryToken((value) => value + 1);
        break;

      default:
        break;
    }
  }, [socketEvent, decode, openChannel, refreshWorkspaces, refreshLinks, refreshPresence, editPrefs, user.id]);

  /* Typing notices expire locally, so a peer that drops mid-sentence does not leave a
     permanent "is typing…" behind. */
  useEffect(() => {
    if (!Object.keys(typingPeers).length) return undefined;
    const timer = setInterval(() => {
      const cutoff = Date.now() - TYPING_TTL_MS;
      setTypingPeers((prev) => {
        const next = {};
        let changed = false;
        for (const [id, value] of Object.entries(prev)) {
          if (value.at >= cutoff) next[id] = value;
          else changed = true;
        }
        return changed ? next : prev;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, [typingPeers]);

  /* -- receipts ------------------------------------------------------------ */

  useEffect(() => {
    if (!channel) return;
    const pending = messages
      .filter((item) => item.sender_id !== user.id && !acknowledged.current.has(item.id))
      .map((item) => item.id);
    if (!pending.length) return;

    // Focus decides the claim: "read" is only honest if the window is actually in front
    // of the operator. Otherwise the message is merely delivered.
    const state = document.hasFocus() ? "read" : "delivered";
    for (const id of pending) acknowledged.current.add(id);
    workspaceApi.acknowledge(channel.id, pending, state).catch(() => {
      for (const id of pending) acknowledged.current.delete(id);
    });
  }, [messages, channel, user.id]);

  useEffect(() => {
    acknowledged.current = new Set();
  }, [channel?.id]);

  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight });
  }, [messages, typingPeers]);

  /* -- sending ------------------------------------------------------------- */

  function signalTyping(state) {
    if (!channel || !socketSend) return;
    socketSend({ type: "typing", channel_id: channel.id, state });
  }

  function onDraftChange(value) {
    setDraft(value);
    if (!channel) return;

    const now = Date.now();
    // The server rate-limits typing frames anyway; not spamming it is simply polite.
    if (value && now - typingSentAt.current > 1500) {
      typingSentAt.current = now;
      signalTyping("start");
    }
    clearTimeout(typingStopTimer.current);
    typingStopTimer.current = setTimeout(() => {
      typingSentAt.current = 0;
      signalTyping("stop");
    }, TYPING_IDLE_MS);

    // Persisted on the same idle timer as the typing notice rather than per keystroke:
    // a draft only has to survive closing the tab, and writing to IndexedDB on every
    // character is work nobody asked for.
    clearTimeout(draftSaveTimer.current);
    draftSaveTimer.current = setTimeout(() => {
      editPrefs((draftPrefs) => setDraftPref(draftPrefs, channel.id, value));
    }, TYPING_IDLE_MS);
  }

  /** One sealed envelope, uploaded. Separated so `emit` can run it twice after a rotation. */
  async function sealAndSend(target, payloadText) {
    const envelope = await encryptForChannel(target, user, identity, payloadText);
    return workspaceApi.send({
      client_message_id: crypto.randomUUID(),
      channel_id: target.id,
      key_epoch: target.key_epoch,
      envelope_b64: envelope,
    });
  }

  /**
   * Seal one payload and put it on the channel.
   *
   * Every verb goes through here -- a message, an edit, a retraction, a reaction. They
   * are indistinguishable on the wire precisely because they take the same path.
   */
  async function emit(payloadText) {
    let target = channel;
    let created;
    try {
      created = await sealAndSend(target, payloadText);
    } catch (caught) {
      if (caught.code !== "rekey_required") throw caught;
      // An epoch reaching its message or time limit is routine, not a failure: it is the
      // forward-secrecy boundary doing its job. Surfacing it made sending look broken and
      // put the operator in the position of pressing a button to make their own message
      // go. Rotate and resend once; a second refusal is a real problem and propagates.
      const rotated = await workspaceApi.rotateEpoch(target.id);
      target = { ...target, key_epoch: rotated.key_epoch };
      setChannel(target);
      await openChannelSession(target, user, identity);
      setSessionStatus({ tone: "good", text: `Encrypted · epoch ${rotated.key_epoch}` });
      created = await sealAndSend(target, payloadText);
    }
    // Our own plaintext is stored, not re-derived: the sending key is gone the instant
    // it is used, so this is the only copy this device will ever have.
    await savePlaintext(target.id, created.id, {
      messageId: created.id,
      plaintext: payloadText,
      authenticated: true,
    });
    // Render immediately; the echoed socket frame is de-duplicated by id, so this is not
    // a race with the fan-out.
    setMessages((prev) =>
      prev.some((item) => item.id === created.id)
        ? prev
        : [
            ...prev,
            {
              ...created,
              plaintext: payloadText,
              payload: decodePayload(payloadText),
              authenticated: true,
              receipt: null,
            },
          ],
    );
    return created;
  }

  async function act(run) {
    if (!channel) return;
    setError("");
    setBusy(true);
    try {
      await run();
    } catch (caught) {
      // `emit` already rotates and retries once, so reaching here with this code means
      // the fresh epoch was refused too -- a real fault rather than the routine limit.
      setError(
        caught.code === "rekey_required"
          ? "The channel refused a freshly rotated epoch. Reopen the channel and try again."
          : caught.message,
      );
    } finally {
      setBusy(false);
    }
  }

  const toggleReaction = (messageId, emoji, mine) =>
    act(() => emit(reactionEvent(messageId, emoji, mine ? "remove" : "add")));

  const submitEdit = (messageId, body) =>
    act(async () => {
      await emit(editPayload(messageId, body));
      setEditing(null);
    });

  const retract = (messageId) =>
    act(async () => {
      await emit(deletePayload(messageId));
      // Tell the relay to drop the stored ciphertext too. The event above is what other
      // clients honour; this is what stops the server handing the message out again.
      await workspaceApi.deleteMessage(messageId).catch(() => {});
    });

  const togglePin = (messageId, currentlyPinned) =>
    act(() => emit(pinEvent(messageId, currentlyPinned ? "remove" : "add")));

  /**
   * Keep a copy of one message under this account, on this device.
   *
   * The body is copied out rather than referenced. A saved message has to survive the
   * thing it points at: the author can retract the original at any time, and after a
   * ratchet step the envelope cannot be decrypted a second time regardless. A reference
   * would quietly become an empty row.
   */
  const toggleSaved = (message) =>
    editPrefs((draftPrefs) =>
      isSaved(draftPrefs, message.id)
        ? unsaveMessage(draftPrefs, message.id)
        : saveMessage(draftPrefs, {
            id: message.id,
            channelId: channel.id,
            channelName: channel.name,
            sender: message.sender_name,
            body: message.body,
            createdAt: message.created_at,
          }),
    );

  async function send() {
    const text = draft.trim();
    if (!text || !channel) return;
    setError("");
    setBusy(true);
    clearTimeout(typingStopTimer.current);
    clearTimeout(draftSaveTimer.current);
    typingSentAt.current = 0;
    signalTyping("stop");
    try {
      await emit(textMessage(text, replyTo?.id ?? null));
      setDraft("");
      setReplyTo(null);
      // A sent draft is no longer a draft.
      editPrefs((draftPrefs) => setDraftPref(draftPrefs, channel.id, ""));
    } catch (caught) {
      if (caught.code === "rekey_required") {
        // Reached only when the retry on a freshly rotated epoch was also refused.
        setError("The channel refused a freshly rotated epoch. Reopen the channel and try again.");
      } else {
        setError(caught.message);
      }
      // The draft is deliberately left in the box on failure: clearing it would destroy
      // what someone just wrote to report that it did not send.
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => () => clearTimeout(typingStopTimer.current), []);

  /* -- render -------------------------------------------------------------- */

  const peers = useMemo(
    () => (channel?.members || []).filter((member) => member.id !== user.id),
    [channel, user.id],
  );
  const typingNames = Object.values(typingPeers).map((value) => value.username);

  if (!workspaces.length) {
    return (
      <div className="chat">
        <aside className="chat__sidebar">
          <PeerDirectory
            presence={presence}
            refreshToken={directoryToken}
            onLinked={refreshLinks}
            onOpenChannel={(id) => refreshWorkspaces().then(() => openChannel(id))}
          />
          <LinkRequests
            links={links}
            onChanged={async () => {
              await refreshLinks();
              await refreshWorkspaces();
            }}
            onOpenChannel={(id) => refreshWorkspaces().then(() => openChannel(id))}
          />
        </aside>
        <section className="chat__main">
          <FirstWorkspace onCreated={refreshWorkspaces} onOpen={openChannel} />
        </section>
      </div>
    );
  }

  return (
    <div className="chat">
      <aside className="chat__sidebar">
        {/* The workspace is chosen in the masthead now. This panel shows what is inside
            the chosen one, so the heading names it rather than offering a second, easily
            desynchronised place to switch. */}
        <Panel title={activeWorkspace?.name || "Workspace"}>
          <div className="stack">
            <ChannelList
              channels={activeWorkspace?.channels ?? []}
              activeId={channel?.id}
              prefs={prefs}
              showArchived={showArchived}
              onToggleArchivedView={() => setShowArchived((value) => !value)}
              onOpen={(id) => openChannel(id).catch((c) => setError(c.message))}
              onToggleMute={(id) => editPrefs((p) => toggleMuted(p, id))}
              onToggleArchive={(id) => editPrefs((p) => toggleArchived(p, id))}
              onSetFolder={(id, folder) => editPrefs((p) => assignFolder(p, id, folder))}
            />
          </div>
        </Panel>

        <LinkRequests
          links={links}
          onChanged={async () => {
            await refreshLinks();
            await refreshWorkspaces();
          }}
          onOpenChannel={openChannel}
        />

        <PeerDirectory
          presence={presence}
          refreshToken={directoryToken}
          onLinked={refreshLinks}
          onOpenChannel={openChannel}
        />

        {activeWorkspace?.owner_id === user.id && <InvitePanel workspace={activeWorkspace} />}

        {activeWorkspace?.owner_id === user.id && (
          <AddPeer workspace={activeWorkspace} onAdded={refreshWorkspaces} />
        )}

        {channel && <PeerVerification channel={channel} user={user} identity={identity} />}

        <NewGroup
          user={user}
          links={links}
          workspaces={workspaces}
          activeWorkspace={activeWorkspace}
          onCreated={refreshWorkspaces}
          onOpen={openChannel}
        />

        {channel && isGroupChannel(channel) && (
          <GroupMembers
            channel={channel}
            user={user}
            links={links}
            workspaces={workspaces}
            presence={presence}
            onChanged={async () => {
              await refreshWorkspaces();
              await openChannel(channel.id);
            }}
          />
        )}

        <Panel title="Members">
          <ul className="stack" style={{ gap: "var(--sp-2)" }}>
            {activeWorkspace?.members.map((name) => {
              const member = channel?.members?.find((row) => row.username === name);
              const online = member ? presence[member.id] : undefined;
              return (
                <li key={name} className="row" style={{ gap: "var(--sp-2)" }}>
                  <span
                    className={online ? "dot dot--pulse" : "dot"}
                    style={{ color: online ? "var(--good)" : "var(--muted)" }}
                    aria-hidden="true"
                  />
                  <span className="truncate">{name}</span>
                  {name === user.username && <span className="muted">you</span>}
                </li>
              );
            })}
          </ul>
        </Panel>
      </aside>

      <section className="chat__main">
        <header className="chat__header">
          <div className="topbar__title">
            <div className="eyebrow">End-to-end encrypted</div>
            <h3># {channel?.name || "Select a channel"}</h3>
          </div>
          <div className="topbar__actions">
            {peers.map((peer) => (
              <Badge key={peer.id} tone={presence[peer.id] ? "good" : "neutral"}>
                {presence[peer.id] ? "online" : "offline"} · {peer.username}
              </Badge>
            ))}
            <Badge tone={sessionStatus.tone}>{sessionStatus.text}</Badge>
            <button
              className="btn btn--sm"
              onClick={() => setShowSaved((value) => !value)}
              aria-pressed={showSaved}
            >
              {showSaved ? "Back to channel" : `Saved (${prefs?.saved.length ?? 0})`}
            </button>
            <button
              className="btn btn--sm"
              disabled={!channel}
              onClick={async () => {
                try {
                  const rotated = await workspaceApi.rotateEpoch(channel.id);
                  await openChannel(channel.id);
                  setSessionStatus({ tone: "good", text: `Rotated to epoch ${rotated.key_epoch}` });
                } catch (caught) {
                  setError(caught.message);
                }
              }}
            >
              Rotate epoch
            </button>
          </div>
        </header>

        {showSaved && (
          <SavedMessages
            saved={prefs?.saved ?? []}
            onRemove={(id) => editPrefs((p) => unsaveMessage(p, id))}
          />
        )}

        {!showSaved && pinned.length > 0 && (
          <div className="pinned-bar reveal">
            <span className="eyebrow" aria-hidden="true">📌 Pinned</span>
            <ul className="stack" style={{ gap: "var(--sp-1)" }}>
              {pinned.map((item) => (
                <li key={item.id} className="row row--between" style={{ gap: "var(--sp-3)" }}>
                  <span className="truncate">
                    <strong>{item.sender_name}</strong> {item.body}
                  </span>
                  <button
                    className="link-btn"
                    disabled={busy}
                    onClick={() => togglePin(item.id, true)}
                  >
                    Unpin
                  </button>
                </li>
              ))}
            </ul>
          </div>
        )}

        <div className="chat__log" ref={logRef} hidden={showSaved}>
          {transcript.map((message) => {
            const mine = message.sender_id === user.id;
            const messageLinks =
              message.authenticated && !message.deleted ? extractLinks(message.body) : [];
            const quote = message.replyTo ? quoteFor(transcript, message.replyTo) : null;
            // Mentions are found here, after decryption, because the relay only ever held
            // ciphertext -- there is no server-side mention index to consult.
            const mentioned =
              !message.deleted && !mine && mentionsUser(message.body, user.username);
            return (
              <article
                key={message.id}
                className={[
                  "message",
                  mine ? "message--mine" : "",
                  message.authenticated ? "" : "message--unauthenticated",
                  message.deleted ? "message--deleted" : "",
                  mentioned ? "message--mentioned" : "",
                  message.pinned ? "message--pinned" : "",
                ].filter(Boolean).join(" ")}
              >
                <div className="message__meta">
                  <strong>{message.sender_name}</strong>
                  <span>epoch {message.key_epoch}</span>
                  <span>{clockTime(message.created_at)}</span>
                  {message.editedAt && <span title="Edited by its author">edited</span>}
                  {message.pinned && (
                    <span title={`Pinned by ${message.pinnedBy ?? "a member"}`}>📌 pinned</span>
                  )}
                  {mentioned && <Badge tone="accent">mentions you</Badge>}
                  {message.authenticated ? (
                    <Badge tone="good">authenticated</Badge>
                  ) : (
                    <Badge tone="critical">not authenticated</Badge>
                  )}
                  {mine && !message.deleted && <ReceiptMark receipt={message.receipt} />}
                </div>

                {quote && (
                  <div className="message__quote">
                    <strong>{quote.sender}</strong>
                    <span className={quote.missing ? "muted" : undefined}>{quote.body}</span>
                  </div>
                )}

                {message.deleted ? (
                  <p className="message__body muted">Message deleted</p>
                ) : editing === message.id ? (
                  <EditBox
                    initial={message.body}
                    busy={busy}
                    onCancel={() => setEditing(null)}
                    onSave={(body) => submitEdit(message.id, body)}
                  />
                ) : (
                  <p className="message__body">
                    {message.authenticated ? <Linkify text={message.body} /> : message.body}
                  </p>
                )}

                {messageLinks.map((url) => (
                  <LinkCard key={url.href} url={url} />
                ))}

                {message.reactions.length > 0 && (
                  <div className="chips" style={{ marginTop: "var(--sp-2)" }}>
                    {message.reactions.map((entry) => (
                      <button
                        key={entry.emoji}
                        type="button"
                        className={entry.people.includes(user.id) ? "chip chip--active" : "chip"}
                        onClick={() =>
                          toggleReaction(message.id, entry.emoji, entry.people.includes(user.id))
                        }
                      >
                        {entry.emoji} {entry.count}
                      </button>
                    ))}
                  </div>
                )}

                {!message.deleted && message.authenticated && (
                  <div className="message__actions">
                    {QUICK_REACTIONS.map((emoji) => (
                      <button
                        key={emoji}
                        type="button"
                        className="link-btn"
                        title={`React ${emoji}`}
                        onClick={() =>
                          toggleReaction(
                            message.id,
                            emoji,
                            message.reactions.some(
                              (entry) => entry.emoji === emoji && entry.people.includes(user.id),
                            ),
                          )
                        }
                      >
                        {emoji}
                      </button>
                    ))}
                    <button type="button" className="link-btn" onClick={() => setReplyTo(message)}>
                      Reply
                    </button>
                    <button
                      type="button"
                      className="link-btn"
                      disabled={busy}
                      onClick={() => togglePin(message.id, message.pinned)}
                    >
                      {message.pinned ? "Unpin" : "Pin"}
                    </button>
                    <button
                      type="button"
                      className="link-btn"
                      title="Keep a copy on this device"
                      onClick={() => toggleSaved(message)}
                    >
                      {prefs && isSaved(prefs, message.id) ? "Unsave" : "Save"}
                    </button>
                    {mine && (
                      <>
                        <button type="button" className="link-btn" onClick={() => setEditing(message.id)}>
                          Edit
                        </button>
                        <button type="button" className="link-btn" onClick={() => retract(message.id)}>
                          Delete
                        </button>
                      </>
                    )}
                  </div>
                )}
              </article>
            );
          })}
          {!transcript.length && (
            <EmptyState title="No messages yet">
              Everything sent here is encrypted in your browser before upload.
            </EmptyState>
          )}
        </div>

        {typingNames.length > 0 && (
          <div className="typing" aria-live="polite">
            <span className="typing__dots" aria-hidden="true">
              <i /><i /><i />
            </span>
            {typingNames.join(", ")} {typingNames.length === 1 ? "is" : "are"} typing…
          </div>
        )}

        {error && (
          <div style={{ padding: "0 var(--sp-4)" }}>
            <Alert tone="error">{error}</Alert>
          </div>
        )}

        {replyTo && (
          <div className="composer__reply reveal--up">
            <div>
              <strong>Replying to {replyTo.sender_name}</strong>
              <span className="muted">{quoteFor(transcript, replyTo.id)?.body ?? ""}</span>
            </div>
            <button type="button" className="link-btn" onClick={() => setReplyTo(null)}>
              Cancel
            </button>
          </div>
        )}

        <div className="chat__composer">
          <textarea
            className="textarea"
            value={draft}
            placeholder="Encrypted locally before upload…"
            aria-label="Message"
            onChange={(changeEvent) => onDraftChange(changeEvent.target.value)}
            onBlur={() => signalTyping("stop")}
            onKeyDown={(keyEvent) => {
              if (keyEvent.key === "Enter" && !keyEvent.shiftKey) {
                keyEvent.preventDefault();
                send();
              }
            }}
          />
          <button className="btn btn--primary" onClick={send} disabled={busy || !channel}>
            {busy ? "Encrypting…" : "Send"}
          </button>
        </div>
      </section>
    </div>
  );
}

/**
 * Messages kept under this account, across channels.
 *
 * Each entry is a copy made at the moment it was saved, not a pointer. That is forced by
 * the ratchet: a message key is destroyed on use, so the original envelope cannot simply
 * be decrypted again later, and the author may retract it in the meantime. Saving stores
 * what you could read when you saved it.
 */
function SavedMessages({ saved, onRemove }) {
  if (!saved.length) {
    return (
      <div className="chat__log">
        <EmptyState title="Nothing saved">
          Use <strong>Save</strong> on any message to keep a copy here. Saved messages live
          in this browser only — they are never uploaded.
        </EmptyState>
      </div>
    );
  }

  return (
    <div className="chat__log">
      {saved.map((item) => (
        <article key={item.id} className="message">
          <div className="message__meta">
            <strong>{item.sender}</strong>
            <span># {item.channelName}</span>
            <span>{clockTime(item.createdAt)}</span>
            <button
              type="button"
              className="link-btn"
              style={{ marginLeft: "auto" }}
              onClick={() => onRemove(item.id)}
            >
              Remove
            </button>
          </div>
          <p className="message__body">{item.body}</p>
        </article>
      ))}
    </div>
  );
}

/**
 * Channels, grouped by the folders this device has filed them into.
 *
 * Muted, archived and foldered are all local preferences (see storage/prefs.js), so none
 * of this arrangement is visible to the relay -- it never learns which conversations the
 * operator cares about.
 */
function ChannelList({
  channels,
  activeId,
  prefs,
  showArchived,
  onToggleArchivedView,
  onOpen,
  onToggleMute,
  onToggleArchive,
  onSetFolder,
}) {
  const [managing, setManaging] = useState(null);
  const muted = prefs?.muted ?? {};
  const archived = prefs?.archived ?? {};
  const unread = prefs?.unread ?? {};

  const visible = channels.filter((item) => Boolean(archived[item.id]) === showArchived);
  const archivedCount = channels.filter((item) => archived[item.id]).length;

  // Grouped into folders, with everything unfiled last under a blank heading. Sorted so
  // the sidebar does not reshuffle as folders are added.
  const groups = new Map();
  for (const item of visible) {
    const folder = prefs ? folderOf(prefs, item.id) : "";
    if (!groups.has(folder)) groups.set(folder, []);
    groups.get(folder).push(item);
  }
  const ordered = [...groups.entries()].sort(([left], [right]) => {
    if (!left) return 1;
    if (!right) return -1;
    return left.localeCompare(right);
  });

  const knownFolders = [...new Set(Object.keys(prefs?.folders ?? {}))].sort();

  return (
    <div>
      <div className="row row--between">
        <div className="eyebrow">{showArchived ? "Archived" : "Channels"}</div>
        {(archivedCount > 0 || showArchived) && (
          <button className="link-btn" onClick={onToggleArchivedView}>
            {showArchived ? "Back to channels" : `Archived (${archivedCount})`}
          </button>
        )}
      </div>

      {!visible.length && (
        <p className="subtle" style={{ marginTop: "var(--sp-2)" }}>
          {showArchived ? "Nothing archived." : "No channels here."}
        </p>
      )}

      {ordered.map(([folder, items]) => (
        <div key={folder || "__unfiled"} style={{ marginTop: "var(--sp-3)" }}>
          {folder && <div className="eyebrow subtle">{folder}</div>}
          <div className="rail__nav" style={{ marginTop: "var(--sp-2)" }}>
            {items.map((item) => {
              const badge = unread[item.id];
              const isMuted = Boolean(muted[item.id]);
              return (
                <div key={item.id}>
                  <button
                    className={item.id === activeId ? "nav-item nav-item--active" : "nav-item"}
                    onClick={() => onOpen(item.id)}
                  >
                    <span aria-hidden="true">#</span>
                    <span className="truncate">{item.name}</span>
                    {isMuted && (
                      <span className="subtle" title="Muted" aria-label="Muted">
                        ⊘
                      </span>
                    )}
                    {prefs?.drafts?.[item.id] && (
                      <span className="subtle" title="Unsent draft" aria-label="Unsent draft">
                        ✎
                      </span>
                    )}
                    {/* A muted channel still counts, it simply does not shout: the number
                        is shown quietly rather than as an unread badge. */}
                    {badge?.count > 0 && (
                      <span
                        className={isMuted ? "nav-item__count" : "badge badge--accent"}
                        style={{ marginLeft: "auto" }}
                      >
                        {badge.count}
                        {badge.mentions > 0 && " @"}
                      </span>
                    )}
                    {!badge?.count && <span className="nav-item__count">E{item.key_epoch}</span>}
                  </button>

                  {managing === item.id ? (
                    <div className="stack reveal" style={{ gap: "var(--sp-2)", padding: "var(--sp-2)" }}>
                      <input
                        className="input"
                        list="prahari-folders"
                        placeholder="Folder name (blank to unfile)"
                        aria-label={`Folder for ${item.name}`}
                        defaultValue={prefs ? folderOf(prefs, item.id) : ""}
                        onKeyDown={(keyEvent) => {
                          if (keyEvent.key !== "Enter") return;
                          onSetFolder(item.id, keyEvent.currentTarget.value.trim());
                          setManaging(null);
                        }}
                      />
                      <div className="row" style={{ gap: "var(--sp-2)" }}>
                        <button className="link-btn" onClick={() => onToggleMute(item.id)}>
                          {isMuted ? "Unmute" : "Mute"}
                        </button>
                        <button className="link-btn" onClick={() => onToggleArchive(item.id)}>
                          {archived[item.id] ? "Unarchive" : "Archive"}
                        </button>
                        <button className="link-btn" onClick={() => setManaging(null)}>
                          Done
                        </button>
                      </div>
                    </div>
                  ) : (
                    <button
                      className="link-btn"
                      style={{ paddingLeft: "var(--sp-3)" }}
                      onClick={() => setManaging(item.id)}
                    >
                      Options
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      ))}

      <datalist id="prahari-folders">
        {knownFolders.map((name) => (
          <option key={name} value={name} />
        ))}
      </datalist>
    </div>
  );
}

/**
 * Rewrite one message in place.
 *
 * Saving publishes a new sealed event rather than altering the original, which is the
 * only thing a blind relay could support: the first envelope stays exactly as it was
 * stored and anchored, and readers apply the edit on top of it. "Edited" is therefore an
 * honest label -- the earlier text existed and was delivered.
 */
function EditBox({ initial, busy, onSave, onCancel }) {
  const [value, setValue] = useState(initial);
  const unchanged = value.trim() === initial.trim();

  return (
    <div className="stack" style={{ gap: "var(--sp-2)" }}>
      <textarea
        className="textarea"
        value={value}
        aria-label="Edit message"
        autoFocus
        onChange={(changeEvent) => setValue(changeEvent.target.value)}
        onKeyDown={(keyEvent) => {
          if (keyEvent.key === "Escape") onCancel();
          if (keyEvent.key === "Enter" && !keyEvent.shiftKey) {
            keyEvent.preventDefault();
            if (value.trim() && !unchanged) onSave(value.trim());
          }
        }}
      />
      <div className="row" style={{ gap: "var(--sp-2)" }}>
        <button
          type="button"
          className="btn btn--primary"
          disabled={busy || !value.trim() || unchanged}
          onClick={() => onSave(value.trim())}
        >
          {busy ? "Encrypting…" : "Save"}
        </button>
        <button type="button" className="link-btn" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </div>
  );
}

/** Sent → delivered → read, as reported by the peer's client. */
function ReceiptMark({ receipt }) {
  if (receipt?.read_at) {
    return <span className="receipt receipt--read" title="Read by the recipient">✓✓ read</span>;
  }
  if (receipt?.delivered_at) {
    return <span className="receipt" title="Delivered to the recipient">✓ delivered</span>;
  }
  return <span className="receipt receipt--sent" title="Stored by the relay">✓ sent</span>;
}

function FirstWorkspace({ onCreated, onOpen }) {
  const [name, setName] = useState("Secure Workspace");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  return (
    <Panel eyebrow="Get started" title="Create your first secure workspace">
      <div className="stack" style={{ maxWidth: "480px" }}>
        <p className="muted">
          Then invite someone with a link, or find them in the directory and request a
          link. Two peers get a Double Ratchet with a key per message; add more and the
          channel becomes a group sharing one key per epoch.
        </p>
        <Field label="Workspace name" id="workspace-name">
          <input
            id="workspace-name"
            className="input"
            value={name}
            onChange={(changeEvent) => setName(changeEvent.target.value)}
          />
        </Field>
        {error && <Alert tone="error">{error}</Alert>}
        <button
          className="btn btn--primary"
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            setError("");
            try {
              const created = await workspaceApi.create(name);
              await onCreated();
              if (created.channels[0]) await onOpen(created.channels[0].id);
            } catch (caught) {
              setError(caught.message);
            } finally {
              setBusy(false);
            }
          }}
        >
          {busy ? "Creating…" : "Create workspace"}
        </button>
      </div>
    </Panel>
  );
}

/**
 * Confirm that the keys the relay handed you really belong to the people you are
 * talking to — Stage 1, capability 23.
 *
 * Two jobs. The safety number is what two people compare out of band, and it matches
 * only if each side is seeing the other's genuine key. The louder job is change
 * detection: the fingerprint seen on first contact is remembered locally, and if it ever
 * moves, that is surfaced as an alert rather than accepted quietly. A one-time check
 * would miss a substitution introduced later, which is the interesting case.
 */
function PeerVerification({ channel, user, identity }) {
  const [rows, setRows] = useState([]);
  const [expanded, setExpanded] = useState("");

  const peers = useMemo(
    () => (channel?.members || []).filter((member) => member.id !== user.id),
    [channel?.members, user.id],
  );

  const localBundle = useMemo(
    () =>
      identity && {
        ed25519_public_key: identity.ed25519Public,
        x25519_public_key: identity.x25519Public,
        ml_kem_encapsulation_key: identity.mlKemPublic,
      },
    [identity],
  );

  useEffect(() => {
    if (!localBundle || peers.length === 0) return;
    let cancelled = false;

    (async () => {
      const collected = [];
      for (const peer of peers) {
        try {
          const bundle = await authApi.keyBundle(peer.username);
          if (!verifyRemoteBundle(bundle)) {
            collected.push({ username: peer.username, error: "Bundle signature is invalid" });
            continue;
          }
          const fingerprint = identityFingerprint(bundle);
          const { state, record } = await reconcilePeerTrust(peer.username, fingerprint);

          // Recomputed here, never taken on the relay's word. This answers a different
          // question from the fingerprint above: the fingerprint says whether the key
          // changed, the chain says whether the *record* of that key has been rewritten.
          let transparency = null;
          try {
            transparency = await verifyKeyHistory(await authApi.keyHistory(peer.username));
          } catch {
            // A history the relay will not serve is not proof of tampering, and refusing
            // to render the channel over it would make the feature a denial-of-service.
            transparency = { ok: false, reason: "History unavailable", unavailable: true };
          }

          collected.push({
            username: peer.username,
            state,
            record,
            transparency,
            number: safetyNumber(localBundle, bundle),
          });
        } catch (caught) {
          collected.push({ username: peer.username, error: caught.message });
        }
      }
      if (!cancelled) setRows(collected);
    })();

    return () => {
      cancelled = true;
    };
  }, [peers, localBundle]);

  if (!identity || peers.length === 0) return null;

  const changed = rows.filter((row) => row.state === "changed");

  return (
    <Panel eyebrow="Key custody" title="Verify contacts">
      {changed.length > 0 && (
        <Alert tone="error" title="A contact's keys changed">
          {changed.map((row) => row.username).join(", ")} presented different keys than
          before. That happens on a reinstall — but it is also what an intercepted
          connection looks like. Confirm the new number with them before trusting it.
        </Alert>
      )}

      <ul className="stack" style={{ gap: "var(--sp-2)", marginTop: changed.length ? "var(--sp-3)" : 0 }}>
        {rows.map((row) => (
          <li key={row.username} className="stack" style={{ gap: "var(--sp-2)" }}>
            <div className="row" style={{ justifyContent: "space-between", gap: "var(--sp-2)" }}>
              <button
                type="button"
                className="link-btn truncate"
                onClick={() => setExpanded(expanded === row.username ? "" : row.username)}
                aria-expanded={expanded === row.username}
              >
                {row.username}
              </button>
              <span className="row" style={{ gap: "var(--sp-2)" }}>
                {/* A rewritten history outranks every other state here: it says the
                    record itself is untrustworthy, so "verified" would be a lie. */}
                {row.transparency && !row.transparency.ok && !row.transparency.unavailable && (
                  <Badge tone="critical" title={row.transparency.reason}>
                    history broken
                  </Badge>
                )}
                {row.error ? (
                  <Badge tone="critical">error</Badge>
                ) : row.state === "changed" ? (
                  <Badge tone="critical">keys changed</Badge>
                ) : row.record?.verifiedAt ? (
                  <Badge tone="good">verified</Badge>
                ) : (
                  <Badge tone="warning">unverified</Badge>
                )}
              </span>
            </div>

            {expanded === row.username && (
              <div className="stack" style={{ gap: "var(--sp-2)" }}>
                {row.error ? (
                  <Alert tone="error">{row.error}</Alert>
                ) : (
                  <>
                    <p className="subtle">
                      Read these numbers to {row.username} in person or on a call you
                      trust. If they match on both screens, no one is in between.
                    </p>
                    <pre className="safety">
                      {formatForDisplay(row.number).join("\n")}
                    </pre>

                    {row.transparency && !row.transparency.ok && !row.transparency.unavailable ? (
                      <Alert tone="error" title="This account's key history does not add up">
                        {row.transparency.reason} Every published key commits to the one
                        before it, so this cannot happen by accident — the record has been
                        changed since it was written. Do not trust the number above until
                        you have confirmed it with {row.username} directly.
                      </Alert>
                    ) : row.transparency?.ok ? (
                      <p className="subtle">
                        Key history checks out in this browser:{" "}
                        {row.transparency.changes === 0
                          ? "this is the only key they have ever published."
                          : `${row.transparency.changes} key change${
                              row.transparency.changes === 1 ? "" : "s"
                            } on record, none of them since rewritten.`}
                      </p>
                    ) : null}
                    {row.record?.verifiedAt ? (
                      <p className="subtle">
                        Verified {new Date(row.record.verifiedAt).toLocaleDateString()}.
                      </p>
                    ) : (
                      <button
                        type="button"
                        className="btn"
                        onClick={async () => {
                          const updated = await markPeerVerified(row.username, row.record.fingerprint);
                          setRows((current) =>
                            current.map((item) =>
                              item.username === row.username
                                ? { ...item, state: "known", record: updated }
                                : item,
                            ),
                          );
                        }}
                      >
                        These numbers match
                      </button>
                    )}
                  </>
                )}
              </div>
            )}
          </li>
        ))}
      </ul>
    </Panel>
  );
}

/** Everyone whose link request was accepted, in either direction. */
function linkedPeers(links, user) {
  const accepted = (links.history || []).filter((row) => row.status === "accepted");
  const names = accepted.map((row) => (row.requester === user.username ? row.target : row.requester));
  return [...new Set(names)].filter(Boolean).sort();
}

/**
 * Create a group channel from linked peers.
 *
 * A channel lives inside a workspace and only its owner may add channels, but a link can
 * land in a workspace owned by either side. So rather than requiring the right workspace
 * to be selected, this works in one the user owns and pulls the chosen peers into it,
 * creating that workspace if they do not have one yet.
 */
function NewGroup({ user, links, workspaces, activeWorkspace, onCreated, onOpen }) {
  const [name, setName] = useState("");
  const [selected, setSelected] = useState([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const peers = linkedPeers(links, user);
  if (peers.length === 0) return null;

  const toggle = (peer) =>
    setSelected((current) =>
      current.includes(peer) ? current.filter((row) => row !== peer) : [...current, peer],
    );

  async function create() {
    setBusy(true);
    setError("");
    try {
      let workspace =
        activeWorkspace?.owner_id === user.id
          ? activeWorkspace
          : workspaces.find((row) => row.owner_id === user.id);
      if (!workspace) workspace = await workspaceApi.create("Secure Workspace");

      // Group membership is validated against the workspace, so anyone missing has to
      // join it first. Already-a-member is not an error worth surfacing.
      const present = new Set(workspace.members || []);
      for (const peer of selected) {
        if (present.has(peer)) continue;
        await workspaceApi.addMember(workspace.id, peer);
      }

      const created = await workspaceApi.createGroup(
        workspace.id,
        name.trim() || `group-${selected.length + 1}`,
        selected,
      );
      setName("");
      setSelected([]);
      await onCreated();
      await onOpen(created.id);
    } catch (caught) {
      setError(caught.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel title="New group" eyebrow={`${peers.length} linked`}>
      <div className="stack">
        <Field label="Group name" id="group-name">
          <input
            id="group-name"
            className="input"
            value={name}
            placeholder="operations"
            onChange={(changeEvent) => setName(changeEvent.target.value)}
          />
        </Field>

        <div className="stack" style={{ gap: "var(--sp-2)" }}>
          <span className="field__label">Members</span>
          {peers.map((peer) => (
            <label key={peer} className="row" style={{ gap: "var(--sp-2)" }}>
              <input
                type="checkbox"
                checked={selected.includes(peer)}
                onChange={() => toggle(peer)}
              />
              <span className="truncate">{peer}</span>
            </label>
          ))}
        </div>

        {selected.length === 1 && (
          <Alert tone="info">
            Two people use a Double Ratchet — a key per message. Pick a second peer for a
            group, which shares one key per epoch instead.
          </Alert>
        )}
        {error && <Alert tone="error">{error}</Alert>}

        <button className="btn btn--primary" disabled={busy || selected.length === 0} onClick={create}>
          {busy ? "Creating…" : `Create group with ${selected.length || "…"}`}
        </button>
      </div>
    </Panel>
  );
}

/** Membership of the open group, plus the control that grows it. */
function GroupMembers({ channel, user, links, workspaces, presence, onChanged }) {
  const [adding, setAdding] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const workspace = workspaces.find((row) => row.id === channel.server_id);
  const owns = workspace?.owner_id === user.id;
  const present = new Set((channel.members || []).map((member) => member.username));
  const candidates = linkedPeers(links, user).filter((peer) => !present.has(peer));

  async function add() {
    setBusy(true);
    setError("");
    try {
      await workspaceApi.addChannelMember(channel.id, adding);
      setAdding("");
      await onChanged();
    } catch (caught) {
      setError(caught.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel title="Group members" eyebrow={`epoch ${channel.key_epoch}`}>
      <ul className="stack" style={{ gap: "var(--sp-2)" }}>
        {(channel.members || []).map((member) => (
          <li key={member.id} className="row" style={{ gap: "var(--sp-2)" }}>
            <span
              className={presence[member.id] ? "dot dot--pulse" : "dot"}
              style={{ color: presence[member.id] ? "var(--good)" : "var(--muted)" }}
              aria-hidden="true"
            />
            <span className="truncate">{member.username}</span>
            {member.id === user.id && <span className="muted">you</span>}
            {!member.key_verified && <Badge tone="warning">no keys</Badge>}
          </li>
        ))}
      </ul>

      {owns && candidates.length > 0 && (
        <div className="stack" style={{ marginTop: "var(--sp-3)" }}>
          <Field label="Add a linked peer" id="group-add">
            <select
              id="group-add"
              className="select"
              value={adding}
              onChange={(changeEvent) => setAdding(changeEvent.target.value)}
            >
              <option value="">Choose someone…</option>
              {candidates.map((peer) => (
                <option key={peer} value={peer}>{peer}</option>
              ))}
            </select>
          </Field>
          <p className="muted" style={{ fontSize: "var(--text-xs)" }}>
            Adding someone rotates the channel to a new epoch. They can read what follows,
            never the messages already sent.
          </p>
          {error && <Alert tone="error">{error}</Alert>}
          <button className="btn" disabled={!adding || busy} onClick={add}>
            {busy ? "Adding…" : "Add and re-key"}
          </button>
        </div>
      )}
    </Panel>
  );
}

function AddPeer({ workspace, onAdded }) {
  const [username, setUsername] = useState("");
  const [note, setNote] = useState(null);
  const [error, setError] = useState("");

  return (
    <Panel title="Add by username">
      <div className="stack">
        <Field label="Username" id="peer-username">
          <input
            id="peer-username"
            className="input"
            value={username}
            placeholder="their username"
            onChange={(changeEvent) => setUsername(changeEvent.target.value)}
          />
        </Field>
        {note && <Alert tone="warning">{note}</Alert>}
        {error && <Alert tone="error">{error}</Alert>}
        <button
          className="btn"
          disabled={!username}
          onClick={async () => {
            setError("");
            setNote(null);
            try {
              const result = await workspaceApi.addMember(workspace.id, username);
              setUsername("");
              if (result.note) setNote(result.note);
              await onAdded();
            } catch (caught) {
              setError(caught.message);
            }
          }}
        >
          Add peer
        </button>
      </div>
    </Panel>
  );
}
