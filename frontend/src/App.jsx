import { useEffect, useState } from "react";
import { api, getApiUrl, getToken, setToken } from "./api/client.js";
import { loadIdentity } from "./storage/keys.js";
import AuthPage from "./pages/AuthPage.jsx";
import ChatPage from "./pages/ChatPage.jsx";
import AnchorsPage from "./pages/AnchorsPage.jsx";
import QuantumPage from "./pages/QuantumPage.jsx";
import SecurityPage from "./pages/SecurityPage.jsx";

export default function App() {
  const [user, setUser] = useState(null);
  const [identity, setIdentity] = useState(null);
  const [view, setView] = useState("chat");
  const [socketEvent, setSocketEvent] = useState(null);
  const [checking, setChecking] = useState(true);

  async function acceptUser(nextUser) {
    setUser(nextUser);
    setIdentity(await loadIdentity(nextUser.username));
  }

  useEffect(() => {
    if (!getToken()) { setChecking(false); return; }
    api("/api/v2/auth/me").then(acceptUser).catch(() => setToken("")).finally(() => setChecking(false));
  }, []);

  useEffect(() => {
    if (!user || !getToken()) return undefined;
    const wsUrl = getApiUrl().replace(/^http/, "ws") + `/ws?token=${encodeURIComponent(getToken())}`;
    const socket = new WebSocket(wsUrl);
    socket.onmessage = (event) => {
      try { setSocketEvent(JSON.parse(event.data)); } catch {}
    };
    const keepalive = setInterval(() => {
      if (socket.readyState === WebSocket.OPEN) socket.send("ping");
    }, 25000);
    return () => { clearInterval(keepalive); socket.close(); };
  }, [user?.id]);

  function logout() {
    setToken("");
    setUser(null);
    setIdentity(null);
    setView("chat");
  }

  if (checking) return <main className="loading-screen"><div className="shield pulse">P</div><p>Checking secure session…</p></main>;
  if (!user) return <AuthPage onAuthenticated={acceptUser} />;

  return (
    <main className="app-shell">
      <aside className="nav-rail">
        <div className="nav-brand"><div className="shield small">P</div><strong>PRAHARI</strong></div>
        <nav>
          <button className={view === "chat" ? "active" : ""} onClick={() => setView("chat")}><span>⌁</span>Encrypted Chat</button>
          <button className={view === "anchors" ? "active" : ""} onClick={() => setView("anchors")}><span>◇</span>Merkle Proofs</button>
          <button className={view === "quantum" ? "active" : ""} onClick={() => setView("quantum")}><span>◉</span>Quantum Lab</button>
          <button className={view === "security" ? "active" : ""} onClick={() => setView("security")}><span>✓</span>Security</button>
        </nav>
        <div className="account-card"><div className="avatar">{user.username[0]?.toUpperCase()}</div><div><strong>{user.username}</strong><span>{user.key_verified ? "Verified identity" : "Keys unverified"}</span></div><button onClick={logout}>↪</button></div>
      </aside>
      <section className="content-shell">
        <header className="topbar"><div><span className="live-dot" /> API connected</div><div className="crypto-strip"><span>AES-256-GCM</span><span>X25519</span><span>ML-KEM-768</span><span>Ed25519</span></div></header>
        <div className="content-area">
          {view === "chat" && <ChatPage user={user} identity={identity} socketEvent={socketEvent} />}
          {view === "anchors" && <AnchorsPage />}
          {view === "quantum" && <QuantumPage />}
          {view === "security" && <SecurityPage identityAvailable={Boolean(identity)} />}
        </div>
      </section>
    </main>
  );
}
