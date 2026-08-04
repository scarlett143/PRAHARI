import { useEffect, useMemo, useState } from "react";
import { api } from "../api/client.js";
import { decryptMessage, encryptMessage } from "../crypto/aead.js";
import { ensureSession, getStoredSessionKey } from "../crypto/session.js";

export default function ChatPage({ user, identity, socketEvent }) {
  const [servers, setServers] = useState([]);
  const [activeServerId, setActiveServerId] = useState("");
  const [channel, setChannel] = useState(null);
  const [messages, setMessages] = useState([]);
  const [draft, setDraft] = useState("");
  const [workspaceName, setWorkspaceName] = useState("Secure Demo");
  const [inviteName, setInviteName] = useState("");
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");

  const activeServer = useMemo(
    () => servers.find((server) => server.id === activeServerId) || servers[0] || null,
    [servers, activeServerId],
  );

  async function refreshServers() {
    const data = await api("/api/v2/servers");
    setServers(data);
    if (!activeServerId && data[0]) setActiveServerId(data[0].id);
    return data;
  }

  async function openChannel(channelId) {
    setError("");
    const details = await api(`/api/v2/channels/${channelId}`);
    setChannel(details);
    setStatus("Preparing hybrid session…");
    try {
      await ensureSession(details, user, identity);
      setStatus(`Encrypted session ready · Epoch ${details.key_epoch}`);
    } catch (err) {
      setStatus(err.message);
    }
    await loadMessages(details);
  }

  async function loadMessages(details = channel) {
    if (!details) return;
    const rows = await api(`/api/v2/channels/${details.id}/messages`);
    const decoded = await Promise.all(rows.map(async (message) => {
      try {
        let key = await getStoredSessionKey(details.id, message.key_epoch);
        if (!key && message.key_epoch === details.key_epoch) {
          key = await ensureSession(details, user, identity, message.key_epoch);
        }
        if (!key) throw new Error("session key unavailable");
        const plaintext = await decryptMessage(key, message.envelope_b64, {
          senderId: message.sender_id,
          channelId: details.id,
          epoch: message.key_epoch,
        });
        return { ...message, plaintext, authenticated: true };
      } catch (err) {
        return { ...message, plaintext: `[${err.message}]`, authenticated: false };
      }
    }));
    setMessages(decoded);
  }

  useEffect(() => { refreshServers().catch((err) => setError(err.message)); }, []);

  useEffect(() => {
    if (!activeServer) return;
    const stillValid = activeServer.channels.some((item) => item.id === channel?.id);
    if (!stillValid && activeServer.channels[0]) openChannel(activeServer.channels[0].id).catch((err) => setError(err.message));
  }, [activeServerId, servers]);

  useEffect(() => {
    if (!socketEvent || !channel) return;
    if (socketEvent.channel_id === channel.id && ["message.created", "session.offer_created", "channel.epoch_rotated"].includes(socketEvent.type)) {
      openChannel(channel.id).catch((err) => setError(err.message));
    }
  }, [socketEvent]);

  async function createWorkspace() {
    try {
      const created = await api("/api/v2/servers", { method: "POST", body: JSON.stringify({ name: workspaceName }) });
      await refreshServers();
      setActiveServerId(created.id);
      if (created.channels[0]) await openChannel(created.channels[0].id);
    } catch (err) { setError(err.message); }
  }

  async function addMember() {
    if (!activeServer || !inviteName) return;
    try {
      await api(`/api/v2/servers/${activeServer.id}/members`, { method: "POST", body: JSON.stringify({ username: inviteName }) });
      setInviteName("");
      await refreshServers();
      if (channel) await openChannel(channel.id);
    } catch (err) { setError(err.message); }
  }

  async function rotateKey() {
    if (!channel) return;
    try {
      const result = await api(`/api/v2/channels/${channel.id}/rotate-key`, { method: "POST", body: "{}" });
      setStatus(`Rotated to Epoch ${result.key_epoch}`);
      await openChannel(channel.id);
    } catch (err) { setError(err.message); }
  }

  async function send() {
    if (!draft.trim() || !channel) return;
    setError("");
    try {
      const key = await ensureSession(channel, user, identity);
      const envelope = await encryptMessage(key, draft.trim(), {
        senderId: user.id,
        channelId: channel.id,
        epoch: channel.key_epoch,
      });
      await api("/api/v2/messages", {
        method: "POST",
        body: JSON.stringify({
          client_message_id: crypto.randomUUID(),
          channel_id: channel.id,
          key_epoch: channel.key_epoch,
          envelope_b64: envelope,
        }),
      });
      setDraft("");
      await loadMessages();
    } catch (err) {
      if (err.detail?.code === "rekey_required" || String(err.message).includes("rekey_required")) {
        setError("This epoch reached its rotation limit. Rotate the key and retry.");
      } else setError(err.message);
    }
  }

  if (!servers.length) {
    return (
      <section className="empty-state panel">
        <span className="eyebrow">START THE DEMO</span>
        <h2>Create your first secure workspace</h2>
        <p>Then register a second user in another browser/profile and add that username.</p>
        <div className="inline-form"><input value={workspaceName} onChange={(e) => setWorkspaceName(e.target.value)} /><button className="primary" onClick={createWorkspace}>Create</button></div>
        {error && <div className="alert error">{error}</div>}
      </section>
    );
  }

  return (
    <section className="chat-layout">
      <aside className="workspace-panel panel">
        <label className="tiny">Workspace</label>
        <select value={activeServer?.id || ""} onChange={(e) => setActiveServerId(e.target.value)}>
          {servers.map((server) => <option key={server.id} value={server.id}>{server.name}</option>)}
        </select>
        <div className="section-title">Channels</div>
        <div className="channel-list">
          {activeServer?.channels.map((item) => <button key={item.id} className={channel?.id === item.id ? "active" : ""} onClick={() => openChannel(item.id)}># {item.name}<span>E{item.key_epoch}</span></button>)}
        </div>
        {activeServer?.owner_id === user.id && <div className="member-box"><div className="section-title">Add encrypted peer</div><input placeholder="username" value={inviteName} onChange={(e) => setInviteName(e.target.value)} /><button onClick={addMember}>Add member</button></div>}
        <div className="member-list"><div className="section-title">Members</div>{activeServer?.members.map((name) => <span key={name}>● {name}</span>)}</div>
      </aside>

      <div className="message-panel panel">
        <header className="message-header">
          <div><div className="eyebrow">END-TO-END ENCRYPTED</div><h2># {channel?.name || "Select channel"}</h2><p className="tiny">{status}</p></div>
          <button onClick={rotateKey} disabled={!channel}>Rotate epoch</button>
        </header>
        <div className="messages">
          {messages.map((message) => <article key={message.id} className={`message ${message.sender_id === user.id ? "mine" : ""}`}><div className="message-meta"><strong>{message.sender_name}</strong><span>Epoch {message.key_epoch}</span><span>{message.authenticated ? "✓ authenticated" : "⚠ failed"}</span></div><p>{message.plaintext}</p></article>)}
          {!messages.length && <div className="empty-message">No ciphertext yet. Send the first encrypted message.</div>}
        </div>
        {error && <div className="alert error compact">{error}</div>}
        <div className="composer"><textarea value={draft} onChange={(e) => setDraft(e.target.value)} placeholder="Encrypted locally before upload…" onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); } }} /><button className="primary" onClick={send}>Send encrypted</button></div>
      </div>
    </section>
  );
}
