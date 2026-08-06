import { useState } from "react";
import { unlockIdentity } from "../crypto/keylock.js";
import { Alert, Field, Mark } from "../components/ui.jsx";

/**
 * Stands between a signed-in session and the console when the keys on this device are
 * sealed.
 *
 * Being signed in is not the same as being able to read anything: the session token
 * comes from the server, the keys do not. So this is a separate gate rather than part of
 * sign-in, and it reappears on every reload because nothing unlocked is ever persisted.
 */
export default function UnlockRoute({ user, record, onUnlocked, onSignOut }) {
  const [passcode, setPasscode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function unlock(submitEvent) {
    submitEvent.preventDefault();
    setBusy(true);
    setError("");
    try {
      onUnlocked(await unlockIdentity(record, passcode));
    } catch (caught) {
      setError(caught.message);
      setPasscode("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="auth">
      <div className="auth__shell" style={{ gridTemplateColumns: "1fr" }}>
        <section className="auth__card" style={{ margin: "0 auto" }}>
          <div className="row">
            <Mark large />
            <div>
              <div className="eyebrow">Keys are locked</div>
              <h1 className="auth__wordmark">PRAHARI</h1>
            </div>
          </div>

          <p className="muted">
            Signed in as <strong>{user.username}</strong>. Your private keys on this
            device are encrypted — enter your passcode to unseal them for this session.
          </p>

          <form onSubmit={unlock} className="stack">
            <Field
              label="Device passcode"
              id="passcode"
              hint="Set on the security page. It is not your account password."
            >
              <input
                id="passcode"
                type="password"
                className="input"
                value={passcode}
                autoComplete="current-password"
                autoFocus
                onChange={(changeEvent) => setPasscode(changeEvent.target.value)}
              />
            </Field>

            {error && <Alert tone="error">{error}</Alert>}

            <Alert tone="info" title="There is no way around this">
              The passcode is not stored and never reaches the server, so it cannot be
              reset. If it is lost, restore this identity from a backup file instead.
            </Alert>

            <button className="btn btn--primary btn--block" disabled={busy || !passcode}>
              {busy ? "Unsealing…" : "Unlock"}
            </button>
            <button type="button" className="link-btn" onClick={onSignOut}>
              Sign out
            </button>
          </form>
        </section>
      </div>
    </main>
  );
}
