import { useState } from "react";
import { authApi, setToken } from "../lib/api.js";
import { generateIdentity, signBundle, signChallenge } from "../crypto/identity.js";
import { loadIdentity, saveIdentity } from "../storage/keys.js";
import { Alert, Field, Mark } from "../components/ui.jsx";

/**
 * Registration generates Ed25519, X25519 and ML-KEM-768 private keys in this
 * browser. They are written to IndexedDB and never sent anywhere -- the server
 * only ever receives the public halves and the signatures over them.
 */
export default function AuthRoute({ onAuthenticated }) {
  const [mode, setMode] = useState("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

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
      onAuthenticated(await authApi.me());
    } catch (caught) {
      setToken("");
      setError(caught.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="auth">
      <section className="auth__card">
        <div className="row">
          <Mark large />
          <div>
            <div className="eyebrow">Post-quantum secure comms</div>
            <h1>PRAHARI</h1>
          </div>
        </div>

        <p className="muted">
          Private keys stay in this browser. The server routes and stores encrypted
          envelopes it cannot open.
        </p>

        <div className="segmented" role="group" aria-label="Authentication mode">
          <button type="button" aria-pressed={mode === "login"} onClick={() => setMode("login")}>
            Sign in
          </button>
          <button type="button" aria-pressed={mode === "register"} onClick={() => setMode("register")}>
            Create identity
          </button>
        </div>

        <form onSubmit={submit} className="stack">
          <Field label="Username" id="username">
            <input
              id="username"
              className="input"
              value={username}
              onChange={(changeEvent) => setUsername(changeEvent.target.value)}
              required
              minLength={3}
              autoComplete="username"
              autoFocus
            />
          </Field>

          <Field
            label="Password"
            id="password"
            hint={mode === "register" ? "At least 12 characters." : undefined}
          >
            <input
              id="password"
              type="password"
              className="input"
              value={password}
              onChange={(changeEvent) => setPassword(changeEvent.target.value)}
              required
              minLength={12}
              autoComplete={mode === "login" ? "current-password" : "new-password"}
            />
          </Field>

          {mode === "register" && (
            <Alert tone="info" title="Keys are generated locally">
              Ed25519, X25519 and ML-KEM-768 private keys are created in this browser and
              stored in IndexedDB. Clearing site data destroys them permanently.
            </Alert>
          )}

          {error && <Alert tone="error">{error}</Alert>}

          <button className="btn btn--primary btn--block" disabled={busy}>
            {busy ? "Working…" : mode === "login" ? "Sign in" : "Create secure identity"}
          </button>
        </form>
      </section>
    </main>
  );
}
