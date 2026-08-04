export default function SecurityPage({ identityAvailable }) {
  const checks = [
    ["Private identity keys", identityAvailable ? "Available in this browser" : "Missing in this browser", identityAvailable],
    ["Message encryption", "AES-256-GCM in browser", true],
    ["Session establishment", "X25519 + ML-KEM-768 + HKDF-SHA256", true],
    ["Identity ownership", "Ed25519 signed challenge + signed key bundle", true],
    ["Server plaintext access", "Disabled by architecture", true],
    ["Rekey model", "Epoch rotation, not Signal Double Ratchet", true],
  ];
  return <section className="panel page-panel"><div className="eyebrow">SECURITY POSTURE</div><h2>What PRAHARI actually guarantees</h2><p className="muted">This MVP deliberately avoids calling itself Signal, PQXDH, or ML-KEM Braid. It implements a smaller, testable hybrid E2EE design.</p><div className="check-list">{checks.map(([name, value, good]) => <div key={name}><span className={`check ${good ? "good" : "bad"}`}>{good ? "✓" : "!"}</span><div><strong>{name}</strong><p>{value}</p></div></div>)}</div><div className="alert warning">Browser IndexedDB protects keys from the server, but not from malicious JavaScript/XSS running in the same origin. See docs/threat-model.md.</div></section>;
}
