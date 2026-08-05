import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { linkApi, workspaceApi } from "../lib/api.js";
import { decryptMessage, encryptMessage } from "../crypto/aead.js";
import { ensureSession, getStoredSessionKey } from "../crypto/session.js";
import { Alert, Badge, EmptyState, Field, Panel } from "../components/ui.jsx";
import Linkify, { LinkCard, extractLinks } from "../components/Linkify.jsx";
import { InvitePanel, LinkRequests, PeerDirectory } from "../components/DirectoryPanel.jsx";
import { clockTime } from "../lib/format.js";

/** A typing notice is stale almost immediately; peers stop showing it on their own. */
const TYPING_TTL_MS = 4000;
/** Long enough that a pause for thought is not reported as "stopped typing". */
const TYPING_IDLE_MS = 2500;

/** Human-to-human secure messaging over the same two-party hybrid session the
 *  aircraft link uses. */
export default function MessagingRoute({ user, identity, socketEvent, socketSend }) {
  const [workspaces, setWorkspaces] = useState([]);
  const [activeWorkspaceId, setActiveWorkspaceId] = useState("");
  const [channel, setChannel] = useState(null);
  const [messages, setMessages] = useState([]);
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

  channelRef.current = channel;

  const activeWorkspace = useMemo(
    () => workspaces.find((item) => item.id === activeWorkspaceId) || workspaces[0] || null,
    [workspaces, activeWorkspaceId],
  );

  /* -- loading ------------------------------------------------------------- */

  const refreshWorkspaces = useCallback(async () => {
    const data = await workspaceApi.list();
    setWorkspaces(data);
    setActiveWorkspaceId((current) => current || data[0]?.id || "");
    return data;
  }, []);

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

  /** Decrypt one envelope against the session key for its epoch. */
  const decode = useCallback(
    async (message, target) => {
      try {
        let key = await getStoredSessionKey(target.id, message.key_epoch);
        if (!key && message.key_epoch === target.key_epoch) {
          key = await ensureSession(target, user, identity, message.key_epoch);
        }
        if (!key) throw new Error("No session key held for this epoch");
        const plaintext = await decryptMessage(key, message.envelope_b64, {
          senderId: message.sender_id,
          channelId: target.id,
          epoch: message.key_epoch,
        });
        return { ...message, plaintext, authenticated: true };
      } catch (caught) {
        return { ...message, plaintext: caught.message, authenticated: false };
      }
    },
    [user, identity],
  );

  const loadMessages = useCallback(
    async (target) => {
      if (!target) return;
      const rows = await workspaceApi.messages(target.id);
      setMessages(await Promise.all(rows.map((row) => decode(row, target))));
    },
    [decode],
  );

  const openChannel = useCallback(
    async (channelId) => {
      setError("");
      const details = await workspaceApi.channel(channelId);
      setChannel(details);
      setTypingPeers({});
      setSessionStatus({ tone: "neutral", text: "Establishing hybrid session…" });
      try {
        await ensureSession(details, user, identity);
        setSessionStatus({
          tone: "good",
          text: `Session established · epoch ${details.key_epoch}`,
        });
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
        if (!current || socketEvent.channel_id !== current.id) break;
        const incoming = socketEvent.message;
        // Append rather than refetch: the envelope is already in the frame, so the
        // message renders without a round trip and without re-running the handshake.
        decode(incoming, current).then((decoded) => {
          setMessages((prev) =>
            prev.some((item) => item.id === decoded.id) ? prev : [...prev, decoded],
          );
        });
        setTypingPeers((prev) => {
          const next = { ...prev };
          delete next[incoming.sender_id];
          return next;
        });
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
  }, [socketEvent, decode, openChannel, refreshWorkspaces, refreshLinks, refreshPresence]);

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
  }

  async function send() {
    const text = draft.trim();
    if (!text || !channel) return;
    setError("");
    setBusy(true);
    clearTimeout(typingStopTimer.current);
    typingSentAt.current = 0;
    signalTyping("stop");
    try {
      const key = await ensureSession(channel, user, identity);
      const envelope = await encryptMessage(key, text, {
        senderId: user.id,
        channelId: channel.id,
        epoch: channel.key_epoch,
      });
      const created = await workspaceApi.send({
        client_message_id: crypto.randomUUID(),
        channel_id: channel.id,
        key_epoch: channel.key_epoch,
        envelope_b64: envelope,
      });
      setDraft("");
      // Render our own message immediately; the echoed socket frame is de-duplicated by
      // id, so this is not a race with the fan-out.
      setMessages((prev) =>
        prev.some((item) => item.id === created.id)
          ? prev
          : [...prev, { ...created, plaintext: text, authenticated: true, receipt: null }],
      );
    } catch (caught) {
      if (caught.code === "rekey_required") {
        setError("This epoch reached its rotation limit. Rotate the epoch and send again.");
      } else {
        setError(caught.message);
      }
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
        <Panel title="Workspace">
          <div className="stack">
            <select
              className="select"
              value={activeWorkspace?.id || ""}
              onChange={(changeEvent) => setActiveWorkspaceId(changeEvent.target.value)}
              aria-label="Select workspace"
            >
              {workspaces.map((item) => (
                <option key={item.id} value={item.id}>{item.name}</option>
              ))}
            </select>

            <div>
              <div className="eyebrow">Channels</div>
              <div className="rail__nav" style={{ marginTop: "var(--sp-2)" }}>
                {activeWorkspace?.channels.map((item) => (
                  <button
                    key={item.id}
                    className={item.id === channel?.id ? "nav-item nav-item--active" : "nav-item"}
                    onClick={() => openChannel(item.id).catch((c) => setError(c.message))}
                  >
                    <span aria-hidden="true">#</span>
                    <span className="truncate">{item.name}</span>
                    <span className="nav-item__count">E{item.key_epoch}</span>
                  </button>
                ))}
              </div>
            </div>
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

        <div className="chat__log" ref={logRef}>
          {messages.map((message) => {
            const mine = message.sender_id === user.id;
            const messageLinks = message.authenticated ? extractLinks(message.plaintext) : [];
            return (
              <article
                key={message.id}
                className={[
                  "message",
                  mine ? "message--mine" : "",
                  message.authenticated ? "" : "message--unauthenticated",
                ].filter(Boolean).join(" ")}
              >
                <div className="message__meta">
                  <strong>{message.sender_name}</strong>
                  <span>epoch {message.key_epoch}</span>
                  <span>{clockTime(message.created_at)}</span>
                  {message.authenticated ? (
                    <Badge tone="good">authenticated</Badge>
                  ) : (
                    <Badge tone="critical">not authenticated</Badge>
                  )}
                  {mine && <ReceiptMark receipt={message.receipt} />}
                </div>
                <p className="message__body">
                  {message.authenticated ? <Linkify text={message.plaintext} /> : message.plaintext}
                </p>
                {messageLinks.map((url) => (
                  <LinkCard key={url.href} url={url} />
                ))}
              </article>
            );
          })}
          {!messages.length && (
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
          link. Channels hold exactly two peers, because the hybrid session is two-party.
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
