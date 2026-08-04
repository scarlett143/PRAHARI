import { useCallback, useEffect, useState } from "react";
import { proofApi } from "../lib/api.js";
import { Alert, Badge, EmptyState, Panel, StatTile } from "../components/ui.jsx";
import { dateTime, integer, shortHash } from "../lib/format.js";

/** Merkle batching over message content hashes, with optional Polygon anchoring. */
export default function ProofsRoute() {
  const [batches, setBatches] = useState([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setBatches(await proofApi.batches());
      setError("");
    } catch (caught) {
      setError(caught.message);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const confirmed = batches.filter((batch) => batch.confirmed).length;
  const leaves = batches.reduce((total, batch) => total + batch.leaf_count, 0);

  return (
    <div className="view__inner">
      <div className="tile-grid">
        <StatTile label="Batches" value={integer(batches.length)} />
        <StatTile label="Messages anchored" value={integer(leaves)} />
        <StatTile label="Chain confirmed" value={integer(confirmed)} meta="requires Polygon config" />
      </div>

      <Panel
        eyebrow="Proof layer"
        title="Merkle anchors"
        description="Message hashes are batched under one root. If Polygon is not configured, batches stay locally verifiable and are labelled as such — no transaction hash is ever fabricated."
        actions={
          <button
            className="btn btn--primary"
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              setError("");
              try {
                await proofApi.build();
                await load();
              } catch (caught) {
                setError(caught.message);
              } finally {
                setBusy(false);
              }
            }}
          >
            {busy ? "Building…" : "Anchor pending batch"}
          </button>
        }
      >
        {error && <Alert tone="error">{error}</Alert>}

        {!batches.length ? (
          <EmptyState title="No batches yet">
            Send some encrypted messages, then build a batch to produce inclusion proofs.
          </EmptyState>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Merkle root</th>
                  <th scope="col">Leaves</th>
                  <th scope="col">Status</th>
                  <th scope="col">Transaction</th>
                  <th scope="col">Created</th>
                </tr>
              </thead>
              <tbody>
                {batches.map((batch) => (
                  <tr key={batch.id}>
                    <td className="mono" title={batch.merkle_root}>{shortHash(batch.merkle_root, 12, 8)}</td>
                    <td className="num">{batch.leaf_count}</td>
                    <td>
                      {batch.confirmed ? (
                        <Badge tone="good">chain confirmed</Badge>
                      ) : batch.status === "chain_failed" ? (
                        <Badge tone="critical">chain failed</Badge>
                      ) : (
                        <Badge tone="neutral">locally verified</Badge>
                      )}
                    </td>
                    <td className="mono">
                      {batch.transaction_hash ? shortHash(batch.transaction_hash, 10, 6) : "—"}
                    </td>
                    <td>{dateTime(batch.created_at)}</td>
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
