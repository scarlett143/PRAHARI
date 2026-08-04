import { useState } from "react";
import { api, setToken } from "../api/client.js";
import { generateIdentity, signBundle, signChallenge } from "../crypto/identity.js";
import { loadIdentity, saveIdentity } from "../storage/keys.js";

export default function AuthPage({ onAuthenticated }) {
  const [mode, setMode] = useState("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      if (mode === "register") {
        const identity = generateIdentity();
        await saveIdentity(username, identity);
        const auth = await api("/api/v2/auth/register", {
          method: "POST",
          body: JSON.stringify({
            username,
            password,
            ed25519_public_key: identity.ed25519Public,
          }),
        });
        setToken(auth.access_token);
        const challenge = await api("/api/v2/auth/challenge", { method: "POST", body: "{}" });
        await api("/api/v2/keys/publish", {
          method: "POST",
          body: JSON.stringify({
            x25519_public_key: identity.x25519Public,
            ml_kem_encapsulation_key: identity.mlKemPublic,
            challenge_signature: signChallenge(identity, challenge.challenge),
            bundle_signature: signBundle(identity),
          }),
        });
      } else {
        const auth = await api("/api/v2/auth/login", {
          method: "POST",
          body: JSON.stringify({ username, password }),
        });
        setToken(auth.access_token);
        if (!auth.key_verified) {
          const identity = await loadIdentity(username);
          if (identity) {
            const challenge = await api("/api/v2/auth/challenge", { method: "POST", body: "{}" });
            await api("/api/v2/keys/publish", {
              method: "POST",
              body: JSON.stringify({
                x25519_public_key: identity.x25519Public,
                ml_kem_encapsulation_key: identity.mlKemPublic,
                challenge_signature: signChallenge(identity, challenge.challenge),
                bundle_signature: signBundle(identity),
              }),
            });
          }
        }
      }
      onAuthenticated(await api("/api/v2/auth/me"));
    } catch (err) {
      setToken("");
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="auth-shell">
      <section className="auth-card">
        <div className="brand-lockup">
          <div className="shield">P</div>
          <div><div className="eyebrow">POST-QUANTUM COMMUNICATION</div><h1>PRAHARI</h1></div>
        </div>
        <p className="muted">Private keys stay in this browser. The server stores encrypted envelopes only.</p>
        <div className="segmented">
          <button className={mode === "login" ? "active" : ""} onClick={() => setMode("login")}>Login</button>
          <button className={mode === "register" ? "active" : ""} onClick={() => setMode("register")}>Register</button>
        </div>
        <form onSubmit={submit} className="stack">
          <label>Username<input value={username} onChange={(e) => setUsername(e.target.value)} required minLength={3} autoComplete="username" /></label>
          <label>Password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={12} autoComplete={mode === "login" ? "current-password" : "new-password"} /></label>
          {mode === "register" && <p className="tiny">Registration generates Ed25519, X25519, and ML-KEM-768 private keys locally.</p>}
          {error && <div className="alert error">{error}</div>}
          <button className="primary" disabled={busy}>{busy ? "Working…" : mode === "login" ? "Login" : "Create secure identity"}</button>
        </form>
      </section>
    </main>
  );
}
