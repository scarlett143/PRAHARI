import { useEffect, useState } from "react";
import { opsApi } from "../lib/api.js";
import { Alert, Badge, Field, Panel } from "../components/ui.jsx";
import { backupFilename, exportIdentity } from "../crypto/backup.js";

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
    ["Keys are not yet encrypted at rest", "Private keys sit in IndexedDB in the clear. Anyone with the unlocked device, or malicious JavaScript in this origin, can read them. A passphrase lock is the next capability in this stage."],
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
