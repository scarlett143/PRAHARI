import { useCallback, useEffect, useState } from "react";
import { opsApi, passkeyApi, sessionApi, twoFactorApi } from "../lib/api.js";
import { Alert, Badge, Field, Panel } from "../components/ui.jsx";
import { backupFilename, exportIdentity } from "../crypto/backup.js";
import { MIN_PASSCODE_LENGTH, isLocked, lockIdentity } from "../crypto/keylock.js";
import { loadIdentity, replaceIdentityRecord } from "../storage/keys.js";
import { createPasskey, passkeysSupported } from "../crypto/passkey.js";
import { relativeTime } from "../lib/format.js";

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
 * Register and remove passkeys.
 *
 * Presented as an additional way in rather than a replacement, because that is what it is:
 * the identity key still outranks it, and recovering the account with that key deletes
 * every passkey here. Saying so next to the button matters — someone who believes a
 * passkey is their last line of defence will treat losing the device very differently from
 * someone who knows recovery still works.
 */
function PasskeyPanel() {
  const [keys, setKeys] = useState([]);
  const [label, setLabel] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [done, setDone] = useState("");

  const supported = passkeysSupported();

  const load = useCallback(async () => {
    try {
      setKeys(await passkeyApi.list());
    } catch (caught) {
      setError(caught.message);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function register() {
    setBusy(true);
    setError("");
    setDone("");
    try {
      const options = await passkeyApi.registerChallenge();
      const created = await createPasskey(options);
      await passkeyApi.register({ ...created, label: label.trim() });
      setLabel("");
      setDone("Passkey registered.");
      await load();
    } catch (caught) {
      // A cancelled prompt throws here too, and reporting that as a failure would be
      // misleading — nothing went wrong, the person changed their mind.
      setError(caught.name === "NotAllowedError" ? "" : caught.message);
    } finally {
      setBusy(false);
    }
  }

  async function remove(id) {
    setBusy(true);
    setError("");
    try {
      await passkeyApi.remove(id);
      setDone("Passkey removed.");
      await load();
    } catch (caught) {
      setError(caught.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel
      eyebrow="Access"
      title="Passkeys"
      description="Sign in with a device key instead of a password. The site's origin is inside the signed assertion, so a passkey cannot be used on a look-alike page."
    >
      <div className="stack" style={{ maxWidth: "34rem" }}>
        {!supported && (
          <Alert tone="warning" title="This browser cannot use passkeys">
            Everything else on this page still works.
          </Alert>
        )}

        {keys.length === 0 ? (
          <Alert tone="info" title="No passkeys registered">
            You sign in with your password{" "}
            {/* Deliberately does not claim the account is less safe without one. */}
            and, if enabled, a verification code.
          </Alert>
        ) : (
          <ul className="stack" style={{ gap: "var(--sp-2)" }}>
            {keys.map((key) => (
              <li key={key.id} className="row row--between" style={{ gap: "var(--sp-3)" }}>
                <div>
                  <strong>{key.label || "Unnamed passkey"}</strong>
                  <p className="subtle">
                    Added {relativeTime(key.created_at)} ·{" "}
                    {key.last_used_at ? `last used ${relativeTime(key.last_used_at)}` : "never used"}
                  </p>
                </div>
                <button className="link-btn" disabled={busy} onClick={() => remove(key.id)}>
                  Remove
                </button>
              </li>
            ))}
          </ul>
        )}

        <Alert tone="info" title="A passkey cannot lock you out">
          Your identity key still outranks it. Resetting the password with that key deletes
          every passkey listed here — deliberately, so a key someone else enrolled cannot
          survive a recovery, and so losing your device never strands you.
        </Alert>

        {error && <Alert tone="error">{error}</Alert>}
        {done && <Alert tone="good">{done}</Alert>}

        <Field label="Name this device (optional)" id="passkey-label">
          <input
            id="passkey-label"
            className="input"
            value={label}
            placeholder="Work laptop"
            onChange={(changeEvent) => setLabel(changeEvent.target.value)}
          />
        </Field>

        <button className="btn btn--primary" disabled={busy || !supported} onClick={register}>
          {busy ? "Waiting for your device…" : "Register a passkey"}
        </button>
      </div>
    </Panel>
  );
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
  const [duress, setDuress] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [done, setDone] = useState("");

  useEffect(() => {
    if (!user) return;
    loadIdentity(user.username).then((record) => setLocked(isLocked(record)));
  }, [user]);

  if (!identity) return null;

  const mismatch = confirmation.length > 0 && passcode !== confirmation;
  const duressTooShort = duress.length > 0 && duress.length < MIN_PASSCODE_LENGTH;
  const duressClashes = duress.length > 0 && duress === passcode;

  async function applyLock() {
    setBusy(true);
    setError("");
    setDone("");
    try {
      const record = await lockIdentity(identity, user.username, passcode, duress);
      await replaceIdentityRecord(user.username, record);
      setLocked(true);
      setPasscode("");
      setConfirmation("");
      setDuress("");
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

        <Field
          label="Duress passcode (optional)"
          id="lock-duress"
          hint="Leave blank if you do not want one. Setting it later means re-entering both."
        >
          <input
            id="lock-duress"
            type="password"
            className="input"
            value={duress}
            autoComplete="new-password"
            onChange={(changeEvent) => setDuress(changeEvent.target.value)}
          />
        </Field>

        <Alert tone="warning" title="What the duress passcode does">
          Entering it at the lock screen erases every key, cached message and trust record
          in this browser, then signs out. There is no confirmation and no warning — that
          is the point, since anyone forcing you to unlock is watching the screen.
          <br />
          <br />
          It reaches this browser only. It cannot recall messages from the server, reach
          your other devices, or destroy a backup file you exported. And it cannot help if
          your keys are not locked in the first place: with no lock screen there is nothing
          to type it into.
        </Alert>

        {mismatch && <Alert tone="warning">The two passcodes do not match.</Alert>}
        {duressTooShort && (
          <Alert tone="warning">
            The duress passcode needs at least {MIN_PASSCODE_LENGTH} characters.
          </Alert>
        )}
        {duressClashes && (
          <Alert tone="warning">
            The duress passcode must differ from the unlock passcode, or unlocking would
            wipe the device.
          </Alert>
        )}
        {error && <Alert tone="error">{error}</Alert>}
        {done && <Alert tone="good">{done}</Alert>}

        <div className="row" style={{ gap: "var(--sp-3)" }}>
          <button
            className="btn btn--primary"
            disabled={
              busy ||
              passcode.length < MIN_PASSCODE_LENGTH ||
              mismatch ||
              !confirmation ||
              duressTooShort ||
              duressClashes
            }
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
    ["Endpoint containment", "A compromised aircraft can be quarantined or revoked: sessions revoked, live sockets closed, enrolment path destroyed", true],
    ["Duress passcode", "An optional second passcode that erases this browser's keys instead of unlocking them. Its presence is not observable in stored data", true],
    ["Firmware drift detection", "An operator pins the approved digest; an endpoint reporting a different one is flagged and audited", true],
    ["Key transparency", "Every published key bundle is appended to a per-user hash chain, recomputed in your browser — the record of a key cannot be rewritten after the fact", true],
    ["Passkeys", "Hardware-backed sign-in. The origin is inside the signed assertion, so a passkey cannot be phished onto a look-alike site", true],
    ["Hybrid certificate chain", "Every certificate is signed twice, Ed25519 and ML-DSA-65, over identical bytes — and both must verify, so forging one means breaking two unrelated problems", true],
    ["Signed firmware releases", "An image is approved by an Ed25519 signature over its digest, bound to fleet and version — endpoints verify before installing, from any mirror", true],
    ["Post-quantum VPN keying", "WireGuard pre-shared keys are generated in your browser and sealed to the gateway with X25519 + ML-KEM-768 — the control plane stores ciphertext it cannot open", true],
    ["Tamper-evident audit log", "Sealed entries are hash-chained and committed to by checkpoints — editing, reordering or truncating past events is detectable", true],
    ["Server-reported invariant", health ? `server_can_read_messages: ${health.server_can_read_messages}` : "unavailable", health ? health.server_can_read_messages === false : false],
  ];

  const limits = [
    ["Group forward secrecy is per epoch", "Direct chats ratchet, giving a key per message. A group shares one epoch key sealed to each member, so a compromised key exposes that epoch rather than a single message. Rotation is what advances it."],
    ["At-rest encryption is opt-in", "Private keys sit in IndexedDB in the clear unless you set a device passcode below. Even with one, the lock protects a stolen machine — not a session that is already open, where the keys are in memory by definition."],
    ["Browser trust", "IndexedDB keeps private keys off the server, but not away from malicious JavaScript running in this origin. XSS defeats it."],
    ["Metadata is visible", "The server necessarily sees accounts, membership, channel ids, timestamps, ciphertext sizes, and delivery events. End-to-end encryption protects content, not all metadata."],
    ["This server cannot issue a certificate", "It stores, verifies and serves them; certificates arrive already signed by whoever holds the issuing keys. That is deliberate — a relay able to issue could impersonate everyone the chain vouches for. It follows that trust in a root is an administrator's decision here, never something a submitted certificate can claim for itself, and that key custody and expiry are handled wherever the issuing keys actually live."],
    ["Firmware images are not stored here", "This service publishes a signed digest, not the image. That is what lets an endpoint fetch bytes from any mirror and still refuse anything the operator did not approve — but it also means withdrawing a release only stops endpoints that check before installing. It does nothing to one already running the image; getting a fleet off a bad build still means shipping a newer release."],
    ["The VPN is a control plane, not a tunnel", "PRAHARI decides who may join, allocates addresses, carries sealed pre-shared keys and revokes access. It does not carry packets — WireGuard runs elsewhere, because a data plane is sustained CPU on a host shared with other services. It follows that revoking a peer takes effect when the gateway next applies its configuration; a session already established stays up until the gateway reloads. And this does not make WireGuard post-quantum: it distributes the pre-shared key that gives WireGuard post-quantum resistance, over a channel that already has it."],
    ["The audit log is only sealed when asked", "Hashing every entry as it is written would make two simultaneous requests contend over the chain's tail, so a request could fail because of its own audit write. The chain is stamped by a separate sealing pass instead — which means anything written since the last seal can still be deleted without trace. Checkpoints are worth exporting off this machine: held only here, they can be rewritten by anyone who can rewrite the log."],
    ["Passkeys are a way in, not a way to lock others out", "A passkey never outranks the identity key. Recovering the account with that key deletes every registered passkey along with TOTP — deliberately, so a credential an attacker enrolled cannot survive the recovery, and so losing your authenticator never strands you. Attestation statements are not checked either: the server does not verify which authenticator model created a credential, so it cannot enforce a hardware allow-list."],
    ["Transparency catches a changed answer, not a first one", "The key chain makes it impossible to rewrite, reorder or drop a past key bundle without every following hash failing. It does not help on first contact — with no earlier state to compare against there is nothing to detect — and it cannot stop a relay simply declining to serve a history. Comparing safety numbers once, in person or on a call you trust, is still what establishes who you are talking to."],
    ["Attestation is self-reported, not proved", "A firmware measurement arrives over an authenticated channel, so it proves the endpoint holds its enrolment key — not that it is running the software it names. An attacker in control of the airframe can report the digest you pinned while running anything. This catches downgrades, mis-flashed images and unapproved builds; catching a hostile endpoint would need a hardware root of trust signing the measurement with a key the main processor cannot read, which this fleet does not assume."],
    ["The duress passcode is local and needs the lock", "It erases this browser and nothing else — not the server's copies, not your other devices, and not a backup file you exported. It only works if the keys are locked in the first place, because with no lock screen there is nowhere to type it. And an attacker who images the disk before you type it keeps that image."],
    ["Revocation does not reach the endpoint", "Quarantining or revoking an aircraft stops it authenticating to this relay and closes the sockets it holds. It does not travel to the airframe, does not erase the keys already on it, and does not make ciphertext an attacker has captured unreadable. Rotate the channel epoch to close what a revoked endpoint could still decrypt."],
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

      <PasskeyPanel />

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
