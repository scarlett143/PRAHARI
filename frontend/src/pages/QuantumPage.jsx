import { useEffect, useState } from "react";
import { api } from "../api/client.js";

export default function QuantumPage() {
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [interceptRate, setInterceptRate] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function loadHistory() { try { setHistory(await api("/api/v2/quantum/experiments")); } catch {} }
  useEffect(() => { loadHistory(); }, []);

  async function run() {
    setBusy(true); setError("");
    try {
      const data = await api("/api/v2/quantum/experiment", { method: "POST", body: JSON.stringify({ shots: 1024, bb84_rounds: 2048, intercept_rate: Number(interceptRate) }) });
      setResult(data); await loadHistory();
    } catch (err) { setError(err.message); }
    finally { setBusy(false); }
  }

  return <section className="panel page-panel"><div className="page-heading"><div><div className="eyebrow">RESEARCH / DEMO ONLY</div><h2>Quantum Security Lab</h2><p>QRNG metrics when Qiskit Aer is installed, plus a BB84 protocol simulation and QBER check.</p></div><button className="primary" onClick={run} disabled={busy}>{busy ? "Running…" : "Run experiment"}</button></div><label className="range-label">Simulated intercept-resend rate <strong>{Math.round(interceptRate * 100)}%</strong><input type="range" min="0" max="1" step="0.05" value={interceptRate} onChange={(e) => setInterceptRate(e.target.value)} /></label>{error && <div className="alert error">{error}</div>}{result && <div className="lab-grid"><article className="metric-card"><span>Result</span><strong className={result.passed ? "pass" : "fail"}>{result.passed ? "PASS" : "FAIL"}</strong></article><article className="metric-card"><span>Backend</span><strong>{result.backend}</strong></article><article className="metric-card"><span>QBER</span><strong>{(result.bb84.qber * 100).toFixed(2)}%</strong></article><article className="metric-card"><span>QRNG bias</span><strong>{result.qrng.observed_bias == null ? "N/A" : result.qrng.observed_bias.toFixed(4)}</strong></article><article className="lab-note"><strong>{result.algorithm}</strong><p>{result.security_note}</p></article></div>}<h3>Experiment log</h3><div className="history-list">{history.map((item) => <div key={item.id}><span className={`badge ${item.passed ? "good" : "bad"}`}>{item.passed ? "PASS" : "FAIL"}</span><strong>{item.backend}</strong><span>QBER {item.qber ?? "n/a"}</span></div>)}</div></section>;
}
