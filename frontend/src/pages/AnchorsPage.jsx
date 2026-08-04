import { useEffect, useState } from "react";
import { api } from "../api/client.js";

export default function AnchorsPage() {
  const [batches, setBatches] = useState([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function refresh() {
    try { setBatches(await api("/api/v2/anchors")); } catch (err) { setError(err.message); }
  }
  useEffect(() => { refresh(); }, []);

  async function buildBatch() {
    setBusy(true); setError("");
    try { await api("/api/v2/anchors/batch", { method: "POST", body: "{}" }); await refresh(); }
    catch (err) { setError(err.message); }
    finally { setBusy(false); }
  }

  return <section className="panel page-panel"><div className="page-heading"><div><div className="eyebrow">DAY 6 PROOF LAYER</div><h2>Merkle Anchors</h2><p>Batches message hashes under one Merkle root. No per-message blockchain metadata.</p></div><button className="primary" onClick={buildBatch} disabled={busy}>{busy ? "Building…" : "Anchor pending batch"}</button></div>{error && <div className="alert error">{error}</div>}<div className="data-grid">{batches.map((batch) => <article className="data-card" key={batch.id}><div className="status-row"><span className={`badge ${batch.confirmed ? "good" : "neutral"}`}>{batch.status}</span><span>{batch.leaf_count} leaves</span></div><code>{batch.merkle_root}</code><p className="tiny">{batch.transaction_hash || "No chain transaction configured"}</p></article>)}</div>{!batches.length && <div className="empty-message">No batches yet.</div>}</section>;
}
