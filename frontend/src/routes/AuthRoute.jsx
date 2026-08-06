import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { authApi, opsApi, setToken } from "../lib/api.js";
import { estimatePasswordStrength, generatePassword } from "../lib/password.js";
import { generateIdentity, signBundle, signChallenge } from "../crypto/identity.js";
import { listIdentities, loadIdentity, saveIdentity } from "../storage/keys.js";
import { Alert, Badge, Mark } from "../components/ui.jsx";

/** Mirrors the server's own rule, so a bad name is caught before a round trip. */
const USERNAME_PATTERN = /^[A-Za-z0-9_.-]+$/;
const LAST_USER_KEY = "prahari_last_user";
const MIN_PASSWORD_LENGTH = 12;

function validateUsername(username) {
  if (!username) return "";
  if (username.length < 3) return "At least 3 characters.";
  if (username.length > 64) return "At most 64 characters.";
  if (!USERNAME_PATTERN.test(username)) return "Letters, digits, dot, dash and underscore only.";
  return "";
}

/**
 * Registration generates Ed25519, X25519 and ML-KEM-768 private keys in this
 * browser. They are written to IndexedDB and never sent anywhere -- the server
 * only ever receives the public halves and the signatures over them.
 */
export default function AuthRoute({ onAuthenticated }) {
  const [mode, setMode] = useState("login");
  const [username, setUsername] = useState(() => localStorage.getItem(LAST_USER_KEY) || "");
  const [password, setPassword] = useState("");
  const [revealed, setRevealed] = useState(false);
  const [capsLock, setCapsLock] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const [identities, setIdentities] = useState([]);
  const [health, setHealth] = useState({ state: "checking" });
  const passwordRef = useRef(null);

  // Which accounts this browser can actually decrypt for. The server cannot tell us
  // this -- it never held the private keys -- so it has to be read locally.
  const refreshIdentities = useCallback(() => {
    listIdentities()
      .then(setIdentities)
      .catch(() => setIdentities([]));
  }, []);

  useEffect(() => {
    refreshIdentities();
  }, [refreshIdentities]);

  useEffect(() => {
    let cancelled = false;
    opsApi
      .health()
      .then((body) => {
        if (!cancelled) setHealth({ state: "online", ...body });
      })
      .catch(() => {
        if (!cancelled) setHealth({ state: "offline" });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const usernameError = validateUsername(username);
  const hasLocalKeys = identities.includes(username);
  const strength = useMemo(() => estimatePasswordStrength(password), [password]);

  // Registering over an existing local identity would destroy the only copy of those
  // private keys. saveIdentity refuses it, but that refusal lands *after* the account is
  // created on the server, leaving an account whose keys never existed. Catch it here.
  const registerWouldClobber = mode === "register" && hasLocalKeys;

  const blocked =
    busy || !username || !password || Boolean(usernameError) || registerWouldClobber ||
    (mode === "register" && password.length < MIN_PASSWORD_LENGTH);

  function switchMode(next) {
    setMode(next);
    setError("");
    setNotice("");
  }

  function trackCapsLock(keyboardEvent) {
    // getModifierState is only meaningful on a real key event, which is why this is not
    // derived from state elsewhere.
    if (typeof keyboardEvent.getModifierState === "function") {
      setCapsLock(keyboardEvent.getModifierState("CapsLock"));
    }
  }

  function useGeneratedPassword() {
    const generated = generatePassword();
    setPassword(generated);
    setRevealed(true);
    setNotice(
      "Generated a random password. Save it in your password manager now — it unwraps your keys and cannot be recovered.",
    );
    passwordRef.current?.focus();
  }

  async function publishBundle(identity) {
    const { challenge } = await authApi.challenge();
    await authApi.publishKeys({
      x25519_public_key: identity.x25519Public,
      ml_kem_encapsulation_key: identity.mlKemPublic,
      challenge_signature: signChallenge(identity, challenge),
      bundle_signature: signBundle(identity),
    });
  }

  async function submit(submitEvent) {
    submitEvent.preventDefault();
    setBusy(true);
    setError("");
    setNotice("");
    try {
      if (mode === "register") {
        const identity = generateIdentity();
        // Register before persisting: writing first would clobber an existing
        // local identity when the username is already taken.
        const auth = await authApi.register({
          username,
          password,
          ed25519_public_key: identity.ed25519Public,
        });
        await saveIdentity(username, identity);
        setToken(auth.access_token);
        await publishBundle(identity);
      } else {
        const auth = await authApi.login({ username, password });
        setToken(auth.access_token);
        if (!auth.key_verified) {
          const identity = await loadIdentity(username);
          if (!identity) {
            throw new Error(
              "This browser does not hold your private keys. Sign in from the browser you registered with — keys cannot be recovered from the server.",
            );
          }
          await publishBundle(identity);
        }
      }
      localStorage.setItem(LAST_USER_KEY, username);
      onAuthenticated(await authApi.me());
    } catch (caught) {
      setToken("");
      setError(
        caught?.status === 401
          ? "That username and password do not match an account."
          : caught.message,
      );
      refreshIdentities();
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="auth">
      <div className="auth__shell">
        <aside className="auth__brief">
          <div className="row">
            <Mark large />
            <div>
              <div className="eyebrow">Post-quantum secure comms</div>
              <h1 className="auth__wordmark">PRAHARI</h1>
            </div>
          </div>

          <p className="auth__lede">
            End-to-end encrypted messaging and UAV command-and-control, built to stay
            private against an adversary holding a quantum computer.
          </p>

          <ul className="auth__properties">
            <li>
              <strong>Keys never leave this device.</strong> Ed25519, X25519 and ML-KEM-768
              private keys are generated here and stored in IndexedDB.
            </li>
            <li>
              <strong>The server cannot read your messages.</strong> It routes and stores
              sealed envelopes it has no key for.
            </li>
            <li>
              <strong>Forward secrecy per message.</strong> A Double Ratchet destroys each
              message key immediately after use.
            </li>
          </ul>

          <ServiceStatus health={health} />
        </aside>

        <section className="auth__card">
          <div className="segmented" role="group" aria-label="Authentication mode">
            <button type="button" aria-pressed={mode === "login"} onClick={() => switchMode("login")}>
              Sign in
            </button>
            <button
              type="button"
              aria-pressed={mode === "register"}
              onClick={() => switchMode("register")}
            >
              Create identity
            </button>
          </div>

          {identities.length > 0 && (
            <div className="auth__identities">
              <span className="field__label">Identities on this browser</span>
              <div className="chips">
                {identities.map((name) => (
                  <button
                    key={name}
                    type="button"
                    className={name === username ? "chip chip--active" : "chip"}
                    onClick={() => {
                      setUsername(name);
                      switchMode("login");
                    }}
                  >
                    {name}
                  </button>
                ))}
              </div>
            </div>
          )}

          <form onSubmit={submit} className="stack" noValidate>
            <div className="field">
              <label className="field__label" htmlFor="username">
                Username
              </label>
              <input
                id="username"
                className="input"
                value={username}
                onChange={(changeEvent) => setUsername(changeEvent.target.value.trim())}
                required
                autoComplete="username"
                autoFocus
                aria-invalid={Boolean(usernameError)}
                aria-describedby="username-hint"
              />
              <span className="field__hint" id="username-hint">
                {usernameError || "Letters, digits, dot, dash and underscore."}
              </span>
            </div>

            <div className="field">
              <div className="field__row">
                <label className="field__label" htmlFor="password">
                  Password
                </label>
                {mode === "register" && (
                  <button type="button" className="link-btn" onClick={useGeneratedPassword}>
                    Generate
                  </button>
                )}
              </div>

              <div className="input-group">
                <input
                  id="password"
                  ref={passwordRef}
                  type={revealed ? "text" : "password"}
                  className="input"
                  value={password}
                  onChange={(changeEvent) => setPassword(changeEvent.target.value)}
                  onKeyUp={trackCapsLock}
                  onKeyDown={trackCapsLock}
                  onBlur={() => setCapsLock(false)}
                  required
                  autoComplete={mode === "login" ? "current-password" : "new-password"}
                  aria-describedby="password-hint"
                />
                <button
                  type="button"
                  className="input-group__btn"
                  onClick={() => setRevealed((current) => !current)}
                  aria-pressed={revealed}
                  aria-label={revealed ? "Hide password" : "Show password"}
                >
                  {revealed ? "Hide" : "Show"}
                </button>
              </div>

              {mode === "register" && password && <StrengthMeter strength={strength} />}

              <span className="field__hint" id="password-hint">
                {mode === "register"
                  ? `At least ${MIN_PASSWORD_LENGTH} characters. This password unwraps your keys — it cannot be reset.`
                  : "The password you chose when you created this identity."}
              </span>
            </div>

            {capsLock && (
              <Alert tone="warning">Caps Lock is on.</Alert>
            )}

            <KeyAvailability
              mode={mode}
              username={username}
              usernameError={usernameError}
              hasLocalKeys={hasLocalKeys}
            />

            {mode === "register" && !registerWouldClobber && (
              <Alert tone="info" title="Keys are generated locally">
                Ed25519, X25519 and ML-KEM-768 private keys are created in this browser and
                stored in IndexedDB. Clearing site data destroys them permanently.
              </Alert>
            )}

            {notice && <Alert tone="warning" title="Save this password">{notice}</Alert>}
            {error && <Alert tone="error">{error}</Alert>}

            <button className="btn btn--primary btn--block" disabled={blocked}>
              {busy ? "Working…" : mode === "login" ? "Sign in" : "Create secure identity"}
            </button>
          </form>
        </section>
      </div>
    </main>
  );
}

/**
 * The one question that decides whether a sign-in can work at all. An account with no
 * keys on this device can authenticate and still be unable to read a single message, so
 * saying so before the attempt is worth more than any error afterwards.
 */
function KeyAvailability({ mode, username, usernameError, hasLocalKeys }) {
  if (!username || usernameError) return null;

  if (mode === "register" && hasLocalKeys) {
    return (
      <Alert tone="error" title="This identity already exists here">
        Creating it again would destroy the private keys that decrypt your existing
        messages. Switch to <strong>Sign in</strong> instead.
      </Alert>
    );
  }
  if (mode === "register") return null;

  return hasLocalKeys ? (
    <Alert tone="good" title="Keys found on this browser">
      Your private keys for <strong>{username}</strong> are stored here, so your messages
      will decrypt.
    </Alert>
  ) : (
    <Alert tone="warning" title="No keys on this browser">
      Nothing stored here for <strong>{username}</strong>. You can still sign in, but past
      messages stay unreadable until you use the browser you registered with — keys cannot
      be recovered from the server.
    </Alert>
  );
}

function StrengthMeter({ strength }) {
  const { bits, score, label, tone, notes } = strength;
  return (
    <div className="strength">
      <div className="strength__track" aria-hidden="true">
        {[0, 1, 2, 3].map((step) => (
          <span
            key={step}
            className="strength__step"
            data-filled={step <= score}
            style={step <= score ? { background: `var(--${tone})` } : undefined}
          />
        ))}
      </div>
      <div className="strength__meta" role="status">
        <span style={{ color: `var(--${tone})` }}>{label}</span>
        <span className="muted">~{bits} bits</span>
      </div>
      {notes.length > 0 && <span className="field__hint">{notes[0]}</span>}
    </div>
  );
}

/**
 * Surfaces reachability and which ML-KEM implementation is actually running. If the API
 * is down this is the difference between "the site is broken" and a precise answer --
 * the sign-in form would otherwise fail with nothing to explain why.
 */
function ServiceStatus({ health }) {
  if (health.state === "checking") {
    return <div className="auth__status muted">Checking service…</div>;
  }

  if (health.state === "offline") {
    return (
      <div className="auth__status">
        <Alert tone="error" title="Service unreachable">
          The API is not responding, so sign-in and registration will fail. This is a
          server-side problem, not your connection.
        </Alert>
      </div>
    );
  }

  const constantTime = String(health.pqc_backend || "").includes("constant-time");
  return (
    <div className="auth__status">
      <Badge tone="good">Service online</Badge>
      <Badge tone="accent">{health.pqc_algorithm || "ML-KEM-768"}</Badge>
      <Badge tone={constantTime ? "good" : "warning"}>
        {constantTime ? "Constant-time backend" : "Research backend"}
      </Badge>
    </div>
  );
}
