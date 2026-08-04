import { useEffect, useState } from "react";
import { opsApi } from "../lib/api.js";
import { Alert, Badge, Panel } from "../components/ui.jsx";

/** An honest statement of what this system does and does not guarantee. The
 *  limitations are listed as prominently as the guarantees on purpose. */
export default function SecurityRoute({ identityAvailable }) {
  const [health, setHealth] = useState(null);

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
    ["No Double Ratchet", "Epoch rotation gives fresh sessions, but not per-message forward secrecy, skipped-message keys, or break-in recovery. This is not Signal Protocol, PQXDH, or ML-KEM Braid."],
    ["Two-party sessions only", "A channel holds exactly two peers. Group messaging would need a real group-key protocol, not one two-party key reused across members."],
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
