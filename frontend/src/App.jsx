import { Suspense, lazy, useCallback, useEffect, useState } from "react";
import { authApi, getToken, setToken } from "./lib/api.js";
import { useRealtime } from "./lib/useRealtime.js";
import { loadIdentity } from "./storage/keys.js";
import { isLocked } from "./crypto/keylock.js";
import { publishKeyBundle } from "./crypto/publish.js";
import UnlockRoute from "./routes/UnlockRoute.jsx";
import { Badge, Mark, Spinner } from "./components/ui.jsx";
import GooeyNav from "./components/GooeyNav.jsx";
import AuthRoute from "./routes/AuthRoute.jsx";
import JoinRoute from "./routes/JoinRoute.jsx";
import MessagingRoute from "./routes/MessagingRoute.jsx";

// Split out of the initial download. Messaging is what almost every session opens on;
// the map, charts and Argon2 that these pull in are dead weight until someone actually
// navigates to them, and on a low-powered device that is parse time as well as bytes.
const FleetRoute = lazy(() => import("./routes/FleetRoute.jsx"));
const LinkConsoleRoute = lazy(() => import("./routes/LinkConsoleRoute.jsx"));
const ProofsRoute = lazy(() => import("./routes/ProofsRoute.jsx"));
const QuantumRoute = lazy(() => import("./routes/QuantumRoute.jsx"));
const SecurityRoute = lazy(() => import("./routes/SecurityRoute.jsx"));

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
  const [lockedRecord, setLockedRecord] = useState(null);
  // True once we know this device's record is sealed, so the masthead can offer to re-seal it.
  const [lockable, setLockable] = useState(false);
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

  // A locked record is held aside rather than put into `identity`: everything downstream
  // treats a non-null identity as usable key material, and a wrapped blob is not.
  const acceptUser = useCallback(async (nextUser) => {
    setUser(nextUser);
    const record = await loadIdentity(nextUser.username);
    if (isLocked(record)) {
      setLockedRecord(record);
      setLockable(true);
      setIdentity(null);
    } else {
      setLockedRecord(null);
      setIdentity(record);
    }
  }, []);

  // The api layer clears the token and fires this when the server stops accepting it,
  // so a revoked session lands back on sign-in rather than on a wall of failures.
  useEffect(() => {
    const ended = () => {
      setUser(null);
      setIdentity(null);
      setLockedRecord(null);
      setConsoleTarget(null);
    };
    window.addEventListener("prahari:session-ended", ended);
    return () => window.removeEventListener("prahari:session-ended", ended);
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
    setLockedRecord(null);
    setConsoleTarget(null);
    setView("messaging");
  }

  /** Drop the keys from memory without ending the session. */
  function lockNow() {
    loadIdentity(user.username).then((record) => {
      if (isLocked(record)) {
        setIdentity(null);
        setLockedRecord(record);
      }
    });
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

  // Signed in, but the keys on this device are sealed. Nothing downstream can encrypt or
  // decrypt until they are opened, so this stands in front of the whole console.
  if (lockedRecord) {
    return (
      <UnlockRoute
        user={user}
        record={lockedRecord}
        onUnlocked={async (unlocked) => {
          setIdentity(unlocked);
          setLockedRecord(null);
          setLockable(true);
          // The bundle can only be published once the keys are readable, which is after
          // this point rather than at sign-in.
          if (!user.key_verified) {
            try {
              await publishKeyBundle(unlocked);
              setUser(await authApi.me());
            } catch {
              /* Surfaced by the console's own "identity verified" badge. */
            }
          }
        }}
        onSignOut={signOut}
      />
    );
  }

  const active = consoleTarget
    ? { title: `Link · ${consoleTarget.callsign}` }
    : VIEWS.find((item) => item.id === view) ?? VIEWS[0];

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main">Skip to content</a>

      <header className="masthead">
        <div className="masthead__brand">
          <Mark />
          <div>
            <strong>PRAHARI</strong>
            <div className="eyebrow">Secure comms</div>
          </div>
        </div>

        {/* Opening a link console leaves every view unselected on purpose: the console is
            not one of them, and highlighting the view behind it would misreport where you
            are. */}
        <GooeyNav
          items={VIEWS}
          activeId={consoleTarget ? null : view}
          onSelect={(id) => {
            setConsoleTarget(null);
            setView(id);
          }}
        />

        <div className="masthead__actions">
          <span className="masthead__user truncate" title={user.username}>
            <strong>{user.username}</strong>
            {user.key_verified ? (
              <Badge tone="good">verified</Badge>
            ) : (
              <Badge tone="warning">keys unpublished</Badge>
            )}
          </span>
          <button
            className="icon-btn"
            onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
            title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
            aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
          >
            <span aria-hidden="true">{theme === "dark" ? "☾" : "☀"}</span>
          </button>
          {lockable && (
            <button className="icon-btn" onClick={lockNow} title="Lock keys" aria-label="Lock keys">
              <span aria-hidden="true">⚿</span>
            </button>
          )}
          <button className="icon-btn" onClick={signOut} title="Sign out" aria-label="Sign out">
            <span aria-hidden="true">⤶</span>
          </button>
        </div>
      </header>

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
          <Suspense fallback={<Spinner label="Loading…" />}>
          {consoleTarget ? (
            <LinkConsoleRoute
              target={consoleTarget}
              user={user}
              identity={identity}
              socketEvent={socketEvent}
              socketStatus={socketStatus}
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
            <SecurityRoute user={user} identity={identity} />
          )}
          </Suspense>
        </main>
      </div>
    </div>
  );
}
