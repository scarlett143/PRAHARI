import { useCallback, useEffect, useState } from "react";
import { authApi, getToken, setToken } from "./lib/api.js";
import { useRealtime } from "./lib/useRealtime.js";
import { loadIdentity } from "./storage/keys.js";
import { Badge, Mark, Spinner } from "./components/ui.jsx";
import AuthRoute from "./routes/AuthRoute.jsx";
import JoinRoute from "./routes/JoinRoute.jsx";
import MessagingRoute from "./routes/MessagingRoute.jsx";
import FleetRoute from "./routes/FleetRoute.jsx";
import LinkConsoleRoute from "./routes/LinkConsoleRoute.jsx";
import ProofsRoute from "./routes/ProofsRoute.jsx";
import QuantumRoute from "./routes/QuantumRoute.jsx";
import SecurityRoute from "./routes/SecurityRoute.jsx";

const VIEWS = [
  { id: "messaging", label: "Messaging", glyph: "◈", title: "Secure messaging" },
  { id: "fleet", label: "Fleet", glyph: "◭", title: "Fleet registry" },
  { id: "proofs", label: "Proofs", glyph: "◇", title: "Merkle anchors" },
  { id: "quantum", label: "Quantum lab", glyph: "◉", title: "Quantum security lab" },
  { id: "security", label: "Security", glyph: "✓", title: "Security posture" },
];

const THEME_KEY = "prahari_theme";

/** `/join/<code>` is the only path the app serves besides the console itself. */
function readInviteCode() {
  const match = window.location.pathname.match(/^\/join\/([A-Za-z0-9_-]{8,64})\/?$/);
  return match ? match[1] : "";
}

export default function App() {
  const [user, setUser] = useState(null);
  const [identity, setIdentity] = useState(null);
  const [view, setView] = useState("messaging");
  const [consoleTarget, setConsoleTarget] = useState(null);
  const [checking, setChecking] = useState(true);
  const [inviteCode, setInviteCode] = useState(readInviteCode);
  const [theme, setTheme] = useState(() => localStorage.getItem(THEME_KEY) || "dark");

  /** Clear the invite from state and the address bar together, so a reload does not
   *  drop the operator back onto a code they already redeemed. */
  const dismissInvite = useCallback(() => {
    setInviteCode("");
    if (window.location.pathname !== "/") {
      window.history.replaceState({}, "", "/");
    }
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem(THEME_KEY, theme);
  }, [theme]);

  const acceptUser = useCallback(async (nextUser) => {
    setUser(nextUser);
    setIdentity(await loadIdentity(nextUser.username));
  }, []);

  useEffect(() => {
    if (!getToken()) {
      setChecking(false);
      return;
    }
    authApi
      .me()
      .then(acceptUser)
      .catch(() => setToken(""))
      .finally(() => setChecking(false));
  }, [acceptUser]);

  const {
    event: socketEvent,
    status: socketStatus,
    send: socketSend,
  } = useRealtime(Boolean(user));

  function signOut() {
    setToken("");
    setUser(null);
    setIdentity(null);
    setConsoleTarget(null);
    setView("messaging");
  }

  if (checking) return <Spinner label="Checking secure session…" />;
  // The invite screen renders before authentication so an invitee can see what they were
  // sent without having to register on faith first.
  if (inviteCode) {
    return (
      <JoinRoute
        code={inviteCode}
        user={user}
        onDismiss={dismissInvite}
        onJoined={() => authApi.me().then(acceptUser).catch(() => {})}
      />
    );
  }
  if (!user) return <AuthRoute onAuthenticated={acceptUser} />;

  const active = consoleTarget
    ? { title: `Link · ${consoleTarget.callsign}` }
    : VIEWS.find((item) => item.id === view) ?? VIEWS[0];

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main">Skip to content</a>

      <aside className="rail">
        <div className="rail__brand">
          <Mark />
          <div>
            <strong>PRAHARI</strong>
            <div className="eyebrow">Secure comms</div>
          </div>
        </div>

        <nav className="rail__nav" aria-label="Primary">
          {VIEWS.map((item) => (
            <button
              key={item.id}
              className={!consoleTarget && view === item.id ? "nav-item nav-item--active" : "nav-item"}
              aria-current={!consoleTarget && view === item.id ? "page" : undefined}
              onClick={() => {
                setConsoleTarget(null);
                setView(item.id);
              }}
            >
              <span aria-hidden="true">{item.glyph}</span>
              {item.label}
            </button>
          ))}
        </nav>

        <div className="rail__spacer" />

        <div className="rail__section">
          <div className="eyebrow">Signed in</div>
          <p className="truncate"><strong>{user.username}</strong></p>
          {user.key_verified ? (
            <Badge tone="good">identity verified</Badge>
          ) : (
            <Badge tone="warning">keys unpublished</Badge>
          )}
        </div>

        <div className="rail__nav">
          <button className="nav-item" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>
            <span aria-hidden="true">{theme === "dark" ? "☾" : "☀"}</span>
            {theme === "dark" ? "Dark theme" : "Light theme"}
          </button>
          <button className="nav-item" onClick={signOut}>
            <span aria-hidden="true">⤶</span>
            Sign out
          </button>
        </div>
      </aside>

      <div className="main">
        <header className="topbar">
          <div className="topbar__title">
            <h2>{active.title}</h2>
          </div>
          <div className="topbar__actions">
            <Badge tone={socketStatus === "open" ? "good" : "warning"}>
              <span
                className={socketStatus === "open" ? "dot dot--pulse" : "dot"}
                aria-hidden="true"
              />
              {socketStatus === "open" ? "realtime connected" : `realtime ${socketStatus}`}
            </Badge>
            <Badge>AES-256-GCM</Badge>
            <Badge>X25519</Badge>
            <Badge>ML-KEM-768</Badge>
            <Badge>Ed25519</Badge>
          </div>
        </header>

        <main className="view" id="main">
          {consoleTarget ? (
            <LinkConsoleRoute
              target={consoleTarget}
              user={user}
              identity={identity}
              socketEvent={socketEvent}
              onBack={() => setConsoleTarget(null)}
            />
          ) : view === "messaging" ? (
            <MessagingRoute
              user={user}
              identity={identity}
              socketEvent={socketEvent}
              socketSend={socketSend}
            />
          ) : view === "fleet" ? (
            <FleetRoute onOpenConsole={setConsoleTarget} />
          ) : view === "proofs" ? (
            <ProofsRoute />
          ) : view === "quantum" ? (
            <QuantumRoute />
          ) : (
            <SecurityRoute identityAvailable={Boolean(identity)} />
          )}
        </main>
      </div>
    </div>
  );
}
