import { useCallback, useEffect, useState } from "react";
import { quantumApi } from "../lib/api.js";
import { Alert, Badge, EmptyState, Field, Panel, StatTile } from "../components/ui.jsx";
import { num } from "../lib/format.js";

/**
 * Research surface. Presented as an experiment, not as a security control:
 * the QRNG output is an entropy-diversity input mixed with the local CSPRNG,
 * and BB84 here is a protocol simulation, not a deployed quantum channel.
 */
export default function QuantumRoute() {
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [interceptRate, setInterceptRate] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const loadHistory = useCallback(async () => {
    try {
      setHistory(await quantumApi.history());
    } catch {
      /* history is supplementary; a failure here should not block the page */
    }
  }, []);

  useEffect(() => {
    loadHistory();
  }, [loadHistory]);

  async function run() {
    setBusy(true);
    setError("");
    try {
      setResult(
        await quantumApi.run({
          shots: 1024,
          bb84_rounds: 2048,
          intercept_rate: Number(interceptRate),
        }),
      );
      await loadHistory();
    } catch (caught) {
      setError(caught.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="view__inner">
      <Panel
        eyebrow="Research / demonstration"
        title="Quantum security lab"
        description="QRNG statistics when Qiskit Aer is installed, plus a BB84 protocol simulation with a quantum bit-error-rate check."
        actions={
          <button className="btn btn--primary" onClick={run} disabled={busy}>
            {busy ? "Running…" : "Run experiment"}
          </button>
        }
      >
        <div className="stack">
          <Field
            label={`Simulated intercept-resend rate — ${Math.round(interceptRate * 100)}%`}
            id="intercept"
            hint="Eavesdropping raises the observed QBER; above 11% the key is rejected."
          >
            <input
              id="intercept"
              type="range"
              min="0"
              max="1"
              step="0.05"
              value={interceptRate}
              onChange={(changeEvent) => setInterceptRate(changeEvent.target.value)}
            />
          </Field>

          {error && <Alert tone="error">{error}</Alert>}

          {result && (
            <>
              <div className="tile-grid">
                <StatTile
                  label="Verdict"
                  value={result.passed ? "PASS" : "FAIL"}
                  tone={result.passed ? "good" : "critical"}
                />
                <StatTile label="QBER" value={num(result.bb84.qber * 100, 2)} unit="%" meta="threshold 11%" />
                <StatTile label="Sifted bits" value={result.bb84.sifted_bits} />
                <StatTile
                  label="QRNG bias"
                  value={result.qrng.observed_bias == null ? "n/a" : num(result.qrng.observed_bias, 4)}
                  meta={result.qrng.status}
                />
              </div>
              <Alert tone="info" title={result.algorithm}>
                {result.security_note}
              </Alert>
            </>
          )}
        </div>
      </Panel>

      <Panel title="Experiment log">
        {!history.length ? (
          <EmptyState title="No experiments run yet" />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Result</th>
                  <th scope="col">Backend</th>
                  <th scope="col">Shots</th>
                  <th scope="col">QBER</th>
                </tr>
              </thead>
              <tbody>
                {history.map((row) => (
                  <tr key={row.id}>
                    <td>
                      {row.passed ? <Badge tone="good">pass</Badge> : <Badge tone="critical">fail</Badge>}
                    </td>
                    <td className="mono truncate" style={{ maxWidth: "320px" }}>{row.backend}</td>
                    <td className="num">{row.shots}</td>
                    <td className="num">{row.qber ? num(Number(row.qber) * 100, 2) + "%" : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
