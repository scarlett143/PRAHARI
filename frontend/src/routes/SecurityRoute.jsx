import { useEffect, useState } from "react";
import { opsApi, sessionApi, twoFactorApi } from "../lib/api.js";
import { Alert, Badge, Field, Panel } from "../components/ui.jsx";
import { backupFilename, exportIdentity } from "../crypto/backup.js";
import { MIN_PASSCODE_LENGTH, isLocked, lockIdentity } from "../crypto/keylock.js";
import { loadIdentity, replaceIdentityRecord } from "../storage/keys.js";

/**
 * Two-step verification.
 *
 * Setup deliberately runs in two steps: the secret is issued, and only a code proved
 * against it turns the factor on. Enabling without that check is how people lock
 * themselves out — a mistyped secret or a badly skewed clock would surface at the next
 * sign-in, when it is too late to fix from inside the account.
 */
function TwoFactorPanel({ user, onChanged }) {
  const [enabled, setEnabled] = useState(Boolean(user?.totp_enabled));
  const [setup, setSetup] = useState(null);
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function begin() {
    setBusy(true);
    setError("");
    try {
      setSetup(await twoFactorApi.setup());
    } catch (caught) {
      setError(caught.message);
    } finally {
      setBusy(false);
    }
  }

  async function confirm() {
    setBusy(true);
    setError("");
    try {
      await twoFactorApi.enable(code);
      setEnabled(true);
      setSetup(null);
      setCode("");
      onChanged?.();
    } catch (caught) {
      setError(caught.message);
    } finally {
      setBusy(false);
    }
  }

  async function turnOff() {
    setBusy(true);
    setError("");
    try {
      await twoFactorApi.disable(password, code);
      setEnabled(false);
      setPassword("");
      setCode("");
      onChanged?.();
    } catch (caught) {
      setError(caught.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel
      eyebrow="Access"
      title="Two-step verification"
      description="Asks for a code from your authenticator app as well as your password."
    >
      <div className="stack" style={{ maxWidth: "34rem" }}>
        {enabled ? (
          <Alert tone="good" title="Two-step verification is on">
            Signing in needs your password and a current code.
          </Alert>
        ) : (
          <Alert tone="warning" title="Your password is the only thing needed to sign in">
            A stolen or reused password is enough to reach this account.
          </Alert>
        )}

        {error && <Alert tone="error">{error}</Alert>}

        {!enabled && !setup && (
          <button className="btn btn--primary" disabled={busy} onClick={begin}>
            {busy ? "Preparing…" : "Set up two-step verification"}
          </button>
        )}

        {!enabled && setup && (
          <>
            <p className="subtle">
              Add this secret to your authenticator app, then enter the code it shows to
              confirm the two agree.
            </p>
            <pre className="safety">{setup.formatted_secret}</pre>
            <p className="subtle">
              Or open <a href={setup.otpauth_uri}>this link</a> on the device with your
              authenticator.
            </p>
            <Field label="Code from your app" id="totp-confirm">
              <input
                id="totp-confirm"
                className="input"
                value={code}
                inputMode="numeric"
                maxLength={6}
                autoComplete="one-time-code"
                onChange={(changeEvent) => setCode(changeEvent.target.value.replace(/\D/g, ""))}
              />
            </Field>
            <div className="row" style={{ gap: "var(--sp-3)" }}>
              <button className="btn btn--primary" disabled={busy || code.length < 6} onClick={confirm}>
                {busy ? "Checking…" : "Confirm and turn on"}
              </button>
              <button className="btn" disabled={busy} onClick={() => { setSetup(null); setCode(""); }}>
                Cancel
              </button>
            </div>
          </>
        )}

        {enabled && (
          <>
            <p className="subtle">
              Turning it off asks for both factors again, so an unlocked screen is not
              enough to remove the protection.
            </p>
            <Field label="Account password" id="totp-off-pass">
              <input
                id="totp-off-pass"
                type="password"
                className="input"
                value={password}
                autoComplete="current-password"
                onChange={(changeEvent) => setPassword(changeEvent.target.value)}
              />
            </Field>
            <Field label="Code from your app" id="totp-off-code">
              <input
                id="totp-off-code"
                className="input"
                value={code}
                inputMode="numeric"
                maxLength={6}
                autoComplete="one-time-code"
                onChange={(changeEvent) => setCode(changeEvent.target.value.replace(/\D/g, ""))}
              />
            </Field>
            <button className="btn" disabled={busy || !password || code.length < 6} onClick={turnOff}>
              {busy ? "Working…" : "Turn off"}
            </button>
            <p className="subtle">
              Lost your authenticator? Reset your password from the sign-in screen — that
              is proved with your identity key, which outranks this, and clears it.
            </p>
          </>
        )}
      </div>
    </Panel>
  );
}

/** Browsers report themselves in a format nobody wants to read in full. */
function describeAgent(agent) {
  if (!agent) return "Unknown client";
  const browser =
    /Edg\//.test(agent) ? "Edge"
      : /OPR\//.test(agent) ? "Opera"
      : /Firefox\//.test(agent) ? "Firefox"
      : /Chrome\//.test(agent) ? "Chrome"
      : /Safari\//.test(agent) ? "Safari"
      : "Browser";
  const platform =
    /iPhone|iPad/.test(agent) ? "iOS"
      : /Android/.test(agent) ? "Android"
      : /Mac OS X/.test(agent) ? "macOS"
      : /Windows/.test(agent) ? "Windows"
      : /Linux/.test(agent) ? "Linux"
      : "";
  return platform ? `${browser} on ${platform}` : browser;
}

function whenSeen(value) {
  if (!value) return "just now";
  const seconds = Math.max(0, (Date.now() - new Date(value).getTime()) / 1000);
  if (seconds < 120) return "active now";
  if (seconds < 3600) return `${Math.round(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} h ago`;
  return new Date(value).toLocaleDateString();
}

/**
 * Everywhere this account is signed in, and the means to end any of it.
 *
 * The point of this screen is the case where a device is lost: a token stays valid until
 * it expires no matter what happens to the laptop it is on, so ending it has to be an
 * action someone can take from somewhere else.
 */
function SessionsPanel() {
  const [sessions, setSessions] = useState(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");

  const refresh = () =>
    sessionApi
      .list()
      .then(setSessions)
      .catch((caught) => setError(caught.message));

  useEffect(() => {
    refresh();
  }, []);

  async function end(sessionId) {
    setBusy(sessionId);
    setError("");
    try {
      await sessionApi.revoke(sessionId);
      await refresh();
    } catch (caught) {
      setError(caught.message);
    } finally {
      setBusy("");
    }
  }

  async function endOthers() {
    setBusy("others");
    setError("");
    try {
      await sessionApi.revokeOthers();
      await refresh();
    } catch (caught) {
      setError(caught.message);
    } finally {
      setBusy("");
    }
  }

  const others = (sessions || []).filter((row) => !row.current);

  return (
    <Panel
      eyebrow="Access"
      title="Where you are signed in"
      description="Ending a session stops its token on the next request it makes."
      actions={
        others.length > 0 && (
          <button className="btn" disabled={busy === "others"} onClick={endOthers}>
            {busy === "others" ? "Ending…" : `Sign out ${others.length} other${others.length > 1 ? "s" : ""}`}
          </button>
        )
      }
    >
      {error && <Alert tone="error">{error}</Alert>}
      {sessions === null && !error && <p className="subtle">Loading…</p>}

      <ul className="stack" style={{ gap: "var(--sp-3)" }}>
        {(sessions || []).map((row) => (
          <li key={row.id} className="row" style={{ justifyContent: "space-between", gap: "var(--sp-3)" }}>
            <div>
              <strong>{row.kind === "uav" ? "Aircraft endpoint" : describeAgent(row.user_agent)}</strong>
              <p className="subtle">
                {row.ip_address ? `${row.ip_address} · ` : ""}
                {whenSeen(row.last_seen_at)}
              </p>
            </div>
            {row.current ? (
              <Badge tone="good">this device</Badge>
            ) : (
              <button className="btn" disabled={busy === row.id} onClick={() => end(row.id)}>
                {busy === row.id ? "Ending…" : "Sign out"}
              </button>
            )}
          </li>
        ))}
      </ul>

      {sessions !== null && sessions.length === 1 && (
        <p className="subtle" style={{ marginTop: "var(--sp-3)" }}>
          This is the only place you are signed in.
        </p>
      )}
    </Panel>
  );
}

/**
 * Turn the at-rest lock on, change it, or take it off.
 *
 * Deliberately opt-in, and deliberately preceded by a warning about backups. A passcode
 * that cannot be reset is a second way to lose the account, so pushing everyone into it
 * would trade one kind of permanent loss for another.
 */
function LockPanel({ user, identity }) {
  const [locked, setLocked] = useState(null);
  const [passcode, setPasscode] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [done, setDone] = useState("");

  useEffect(() => {
    if (!user) return;
    loadIdentity(user.username).then((record) => setLocked(isLocked(record)));
  }, [user]);

  if (!identity) return null;

  const mismatch = confirmation.length > 0 && passcode !== confirmation;

  async function applyLock() {
    setBusy(true);
    setError("");
    setDone("");
    try {
      const record = await lockIdentity(identity, user.username, passcode);
      await replaceIdentityRecord(user.username, record);
      setLocked(true);
      setPasscode("");
      setConfirmation("");
      setDone(locked ? "Passcode changed." : "Keys are now encrypted on this device.");
    } catch (caught) {
      setError(caught.message);
    } finally {
      setBusy(false);
    }
  }

  async function removeLock() {
    setBusy(true);
    setError("");
    setDone("");
    try {
      // The identity is already open in memory, so removing the lock is simply storing
      // it back in the clear.
      await replaceIdentityRecord(user.username, identity);
      setLocked(false);
      setDone("Lock removed. Keys are stored unencrypted again.");
    } catch (caught) {
      setError(caught.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel
      eyebrow="Key custody"
      title="Lock keys on this device"
      description="Encrypts your private keys in this browser's storage so a stolen machine is not a stolen identity."
    >
      <div className="stack" style={{ maxWidth: "34rem" }}>
        {locked ? (
          <Alert tone="good" title="Keys are encrypted at rest">
            You will be asked for this passcode each time the app opens.
          </Alert>
        ) : (
          <Alert tone="warning" title="Keys are stored unencrypted">
            Anyone with access to this browser profile can read them directly.
          </Alert>
        )}

        <Alert tone="info" title="Back up first">
          The passcode never reaches the server and cannot be reset. If you forget it, the
          only way back is the encrypted backup file above.
        </Alert>

        <Field
          label={locked ? "New passcode" : "Passcode"}
          id="lock-pass"
          hint={`At least ${MIN_PASSCODE_LENGTH} characters. Not your account password.`}
        >
          <input
            id="lock-pass"
            type="password"
            className="input"
            value={passcode}
            autoComplete="new-password"
            onChange={(changeEvent) => setPasscode(changeEvent.target.value)}
          />
        </Field>

        <Field label="Confirm passcode" id="lock-confirm">
          <input
            id="lock-confirm"
            type="password"
            className="input"
            value={confirmation}
            autoComplete="new-password"
            onChange={(changeEvent) => setConfirmation(changeEvent.target.value)}
          />
        </Field>

        {mismatch && <Alert tone="warning">The two passcodes do not match.</Alert>}
        {error && <Alert tone="error">{error}</Alert>}
        {done && <Alert tone="good">{done}</Alert>}

        <div className="row" style={{ gap: "var(--sp-3)" }}>
          <button
            className="btn btn--primary"
            disabled={busy || passcode.length < MIN_PASSCODE_LENGTH || mismatch || !confirmation}
            onClick={applyLock}
          >
            {busy ? "Sealing…" : locked ? "Change passcode" : "Lock keys"}
          </button>
          {locked && (
            <button className="btn" disabled={busy} onClick={removeLock}>
              Remove lock
            </button>
          )}
        </div>
      </div>
    </Panel>
  );
}

/**
 * Export the identity to a file only the holder can open.
 *
 * Nothing is uploaded. A backup we stored would be a copy of the user's identity in our
 * hands, which is the arrangement this whole product exists to avoid — so the file is
 * handed to the browser's download and never leaves by any other route.
 */
function BackupPanel({ user, identity }) {
  const [passphrase, setPassphrase] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [done, setDone] = useState(false);

  if (!identity) {
    return (
      <Panel eyebrow="Key custody" title="Back up your identity">
        <Alert tone="warning" title="No keys in this browser">
          There is nothing here to back up. Sign in from the browser holding your keys, or
          restore from an existing backup on the sign-in screen.
        </Alert>
      </Panel>
    );
  }

  const mismatch = confirmation.length > 0 && passphrase !== confirmation;

  async function download() {
    setBusy(true);
    setError("");
    setDone(false);
    try {
      const file = await exportIdentity(identity, user.username, passphrase);
      const url = URL.createObjectURL(new Blob([file], { type: "application/json" }));
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = backupFilename(user.username);
      anchor.click();
      URL.revokeObjectURL(url);
      setPassphrase("");
      setConfirmation("");
      setDone(true);
    } catch (caught) {
      setError(caught.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel
      eyebrow="Key custody"
      title="Back up your identity"
      description="Your keys exist only in this browser. This file is the only way to get them back."
    >
      <div className="stack" style={{ maxWidth: "34rem" }}>
        <Alert tone="info" title="Choose a passphrase you will not lose">
          The file is sealed with it using Argon2id. We never see the passphrase or the
          file, so neither can be recovered or reset — if both are lost, so is the
          account.
        </Alert>

        <Field label="Backup passphrase" id="backup-pass" hint="At least 12 characters.">
          <input
            id="backup-pass"
            type="password"
            className="input"
            value={passphrase}
            autoComplete="new-password"
            onChange={(changeEvent) => setPassphrase(changeEvent.target.value)}
          />
        </Field>

        <Field label="Confirm passphrase" id="backup-confirm">
          <input
            id="backup-confirm"
            type="password"
            className="input"
            value={confirmation}
            autoComplete="new-password"
            onChange={(changeEvent) => setConfirmation(changeEvent.target.value)}
          />
        </Field>

        {mismatch && <Alert tone="warning">The two passphrases do not match.</Alert>}
        {error && <Alert tone="error">{error}</Alert>}
        {done && (
          <Alert tone="good" title="Backup downloaded">
            Store it somewhere durable. Anyone holding both this file and its passphrase
            can read your messages, so treat it like the key it is.
          </Alert>
        )}

        <button
          className="btn btn--primary"
          disabled={busy || passphrase.length < 12 || mismatch || !confirmation}
          onClick={download}
        >
          {busy ? "Sealing…" : "Download encrypted backup"}
        </button>
        <p className="subtle">
          Sealing runs a deliberately slow key derivation and takes a few seconds.
        </p>
      </div>
    </Panel>
  );
}

/** An honest statement of what this system does and does not guarantee. The
 *  limitations are listed as prominently as the guarantees on purpose. */
export default function SecurityRoute({ user, identity }) {
  const [health, setHealth] = useState(null);
  const identityAvailable = Boolean(identity);

  useEffect(() => {
    opsApi.health().then(setHealth).catch(() => setHealth(null));
  }, []);

  const guarantees = [
    ["Private identity keys", identityAvailable ? "Held in this browser" : "Missing in this browser", identityAvailable],
    ["Message encryption", "AES-256-GCM, performed in the browser", true],
    ["Key agreement", "X25519 + ML-KEM-768 → HKDF-SHA256", true],
    ["Identity proof", "Ed25519 signed challenge and signed key bundle", true],
    ["Server plaintext access", "Prevented by architecture", true],
    ["Aircraft link", "Identical protocol to human-to-human channels", true],
    ["Server-reported invariant", health ? `server_can_read_messages: ${health.server_can_read_messages}` : "unavailable", health ? health.server_can_read_messages === false : false],
  ];

  const limits = [
    ["Group forward secrecy is per epoch", "Direct chats ratchet, giving a key per message. A group shares one epoch key sealed to each member, so a compromised key exposes that epoch rather than a single message. Rotation is what advances it."],
    ["At-rest encryption is opt-in", "Private keys sit in IndexedDB in the clear unless you set a device passcode below. Even with one, the lock protects a stolen machine — not a session that is already open, where the keys are in memory by definition."],
    ["Browser trust", "IndexedDB keeps private keys off the server, but not away from malicious JavaScript running in this origin. XSS defeats it."],
    ["Metadata is visible", "The server necessarily sees accounts, membership, channel ids, timestamps, ciphertext sizes, and delivery events. End-to-end encryption protects content, not all metadata."],
    ["ML-KEM side channels", "Neither the browser nor the pure-Python ML-KEM implementation is claimed constant-time. Use liboqs for anything deployed."],
    ["Quantum module is a demo", "QRNG output is an entropy-diversity input only, and BB84 here is a simulation. Cloud-delivered quantum bits are visible to the provider."],
  ];

  return (
    <div className="view__inner">
      <Panel
        eyebrow="Security posture"
        title="What PRAHARI guarantees"
        description="Deliberately scoped claims. Everything below is implemented and tested in this repository."
      >
        <ul className="stack">
          {guarantees.map(([name, detail, ok]) => (
            <li key={name} className="row" style={{ alignItems: "flex-start" }}>
              <Badge tone={ok ? "good" : "warning"}>{ok ? "yes" : "check"}</Badge>
              <div>
                <strong>{name}</strong>
                <p className="subtle">{detail}</p>
              </div>
            </li>
          ))}
        </ul>
      </Panel>

      <BackupPanel user={user} identity={identity} />

      <LockPanel user={user} identity={identity} />

      <TwoFactorPanel user={user} />

      <SessionsPanel />

      <Panel eyebrow="Scope discipline" title="What it does not guarantee">
        <ul className="stack">
          {limits.map(([name, detail]) => (
            <li key={name}>
              <strong>{name}</strong>
              <p className="subtle">{detail}</p>
            </li>
          ))}
        </ul>
      </Panel>

      <Alert tone="warning" title="Deployment note">
        The pure-Python ML-KEM backend is research grade and not constant-time. Set
        <code> PQC_BACKEND=liboqs</code> and generate a strong <code>JWT_SECRET</code> before
        exposing this to anything real.
      </Alert>
    </div>
  );
}
