import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { workspaceApi } from "../lib/api.js";
import { decryptMessage, encryptMessage } from "../crypto/aead.js";
import { ensureSession, getStoredSessionKey } from "../crypto/session.js";
import { Alert, Badge, EmptyState, Field, Panel } from "../components/ui.jsx";
import { clockTime } from "../lib/format.js";

/** Human-to-human secure messaging over the same two-party hybrid session the
 *  aircraft link uses. */
export default function MessagingRoute({ user, identity, socketEvent }) {
  const [workspaces, setWorkspaces] = useState([]);
  const [activeWorkspaceId, setActiveWorkspaceId] = useState("");
  const [channel, setChannel] = useState(null);
  const [messages, setMessages] = useState([]);
  const [draft, setDraft] = useState("");
  const [sessionStatus, setSessionStatus] = useState({ tone: "neutral", text: "No channel open" });
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const logRef = useRef(null);

  const activeWorkspace = useMemo(
    () => workspaces.find((item) => item.id === activeWorkspaceId) || workspaces[0] || null,
    [workspaces, activeWorkspaceId],
  );

  const refreshWorkspaces = useCallback(async () => {
    const data = await workspaceApi.list();
    setWorkspaces(data);
    setActiveWorkspaceId((current) => current || data[0]?.id || "");
    return data;
  }, []);

  const loadMessages = useCallback(
    async (target) => {
      if (!target) return;
      const rows = await workspaceApi.messages(target.id);
      const decoded = await Promise.all(
        rows.map(async (message) => {
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
        }),
      );
      setMessages(decoded);
    },
    [user, identity],
  );

  const openChannel = useCallback(
    async (channelId) => {
      setError("");
      const details = await workspaceApi.channel(channelId);
      setChannel(details);
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
  }, [refreshWorkspaces]);

  useEffect(() => {
    if (!activeWorkspace) return;
    const stillOpen = activeWorkspace.channels.some((item) => item.id === channel?.id);
    const first = activeWorkspace.channels[0];
    if (!stillOpen && first) openChannel(first.id).catch((caught) => setError(caught.message));
  }, [activeWorkspace, channel?.id, openChannel]);

  useEffect(() => {
    if (!socketEvent || !channel) return;
    const relevant = ["message.created", "session.offer_created", "channel.epoch_rotated"];
    if (socketEvent.channel_id === channel.id && relevant.includes(socketEvent.type)) {
      openChannel(channel.id).catch((caught) => setError(caught.message));
    }
  }, [socketEvent, channel, openChannel]);

  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight });
  }, [messages]);

  async function send() {
    const text = draft.trim();
    if (!text || !channel) return;
    setError("");
    setBusy(true);
    try {
      const key = await ensureSession(channel, user, identity);
      const envelope = await encryptMessage(key, text, {
        senderId: user.id,
        channelId: channel.id,
        epoch: channel.key_epoch,
      });
      await workspaceApi.send({
        client_message_id: crypto.randomUUID(),
        channel_id: channel.id,
        key_epoch: channel.key_epoch,
        envelope_b64: envelope,
      });
      setDraft("");
      await loadMessages(channel);
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

  if (!workspaces.length) {
    return <FirstWorkspace onCreated={refreshWorkspaces} onOpen={openChannel} />;
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

        {activeWorkspace?.owner_id === user.id && (
          <AddPeer workspace={activeWorkspace} onAdded={refreshWorkspaces} />
        )}

        <Panel title="Members">
          <ul className="stack" style={{ gap: "var(--sp-2)" }}>
            {activeWorkspace?.members.map((name) => (
              <li key={name} className="row">
                <span className="dot" style={{ color: "var(--good)" }} aria-hidden="true" />
                <span className="truncate">{name}</span>
              </li>
            ))}
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
          {messages.map((message) => (
            <article
              key={message.id}
              className={[
                "message",
                message.sender_id === user.id ? "message--mine" : "",
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
              </div>
              <p className="message__body">{message.plaintext}</p>
            </article>
          ))}
          {!messages.length && (
            <EmptyState title="No messages yet">
              Everything sent here is encrypted in your browser before upload.
            </EmptyState>
          )}
        </div>

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
            onChange={(changeEvent) => setDraft(changeEvent.target.value)}
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

function FirstWorkspace({ onCreated, onOpen }) {
  const [name, setName] = useState("Secure Workspace");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  return (
    <Panel eyebrow="Get started" title="Create your first secure workspace">
      <div className="stack" style={{ maxWidth: "480px" }}>
        <p className="muted">
          Then register a second user in another browser profile and add them by username.
          Channels hold exactly two peers, because the hybrid session is two-party.
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
    <Panel title="Add a peer">
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
