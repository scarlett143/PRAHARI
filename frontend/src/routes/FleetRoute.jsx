import { useCallback, useEffect, useMemo, useState } from "react";
import { fleetApi } from "../lib/api.js";
import { Alert, Badge, EmptyState, Field, Panel, StatTile } from "../components/ui.jsx";
import { integer, relativeTime } from "../lib/format.js";

const PAGE_SIZE = 50;

/** Fleet registry. Paginated because the deployment target is 1000 endpoints and
 *  no operator screen should try to hold them all at once. */
export default function FleetRoute({ onOpenConsole }) {
  const [page, setPage] = useState(0);
  const [data, setData] = useState({ total: 0, returned: 0, endpoints: [] });
  const [filter, setFilter] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // Typing should not fire a request per keystroke on a box this size.
  const [appliedFilter, setAppliedFilter] = useState("");
  useEffect(() => {
    const timer = setTimeout(() => setAppliedFilter(filter.trim()), 250);
    return () => clearTimeout(timer);
  }, [filter]);

  // A new search starts at the beginning; staying on page 4 of the previous result is
  // how a search appears to return nothing.
  useEffect(() => {
    setPage(0);
  }, [appliedFilter]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setData(
        await fleetApi.list({
          limit: PAGE_SIZE,
          offset: page * PAGE_SIZE,
          query: appliedFilter || undefined,
        }),
      );
      setError("");
    } catch (caught) {
      setError(caught.message);
    } finally {
      setLoading(false);
    }
  }, [page, appliedFilter]);

  useEffect(() => {
    load();
  }, [load]);

  // The server has already applied the search across the whole registry.
  const visible = data.endpoints;

  const summary = useMemo(() => {
    const enrolled = data.endpoints.filter((item) => item.enrolled_at).length;
    const linked = data.endpoints.filter((item) => item.link_channel_id).length;
    const pending = data.endpoints.filter((item) => !item.enrolled_at).length;
    return { enrolled, linked, pending };
  }, [data.endpoints]);

  const pageCount = Math.max(1, Math.ceil(data.total / PAGE_SIZE));

  return (
    <div className="view__inner">
      <div className="tile-grid">
        <StatTile label="Endpoints" value={integer(data.total)} meta="provisioned in this fleet" />
        <StatTile label="Enrolled" value={integer(summary.enrolled)} meta="on this page" />
        <StatTile label="Linked" value={integer(summary.linked)} meta="encrypted channel open" />
        <StatTile label="Awaiting enrolment" value={integer(summary.pending)} meta="token unredeemed" />
      </div>

      <ProvisionPanel onProvisioned={load} />

      <Panel
        title="Fleet registry"
        description="Every aircraft holds its own keys and speaks the same two-party hybrid session as a human peer."
        actions={
          <div className="row">
            <input
              className="input"
              style={{ width: "220px" }}
              placeholder="Filter this page…"
              value={filter}
              aria-label="Filter endpoints"
              onChange={(changeEvent) => setFilter(changeEvent.target.value)}
            />
            <button className="btn btn--sm" onClick={load} disabled={loading}>
              {loading ? "Loading…" : "Refresh"}
            </button>
          </div>
        }
      >
        {error && <Alert tone="error">{error}</Alert>}

        {!data.total && !loading ? (
          <EmptyState title="No aircraft provisioned">
            Provision an endpoint above to receive a single-use enrolment token.
          </EmptyState>
        ) : (
          <>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th scope="col">Callsign</th>
                    <th scope="col">Airframe</th>
                    <th scope="col">Fleet</th>
                    <th scope="col">Identity</th>
                    <th scope="col">Link</th>
                    <th scope="col">Last seen</th>
                    <th scope="col"><span className="sr-only">Actions</span></th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map((endpoint) => (
                    <tr key={endpoint.callsign}>
                      <td className="mono">{endpoint.callsign}</td>
                      <td>{endpoint.airframe || "—"}</td>
                      <td>{endpoint.fleet}</td>
                      <td>
                        {endpoint.key_verified ? (
                          <Badge tone="good">verified</Badge>
                        ) : endpoint.enrolled_at ? (
                          <Badge tone="warning">no key bundle</Badge>
                        ) : (
                          <Badge tone="neutral">pending enrolment</Badge>
                        )}
                      </td>
                      <td>
                        {endpoint.link_channel_id ? (
                          <Badge tone="accent">channel open</Badge>
                        ) : (
                          <Badge tone="neutral">not linked</Badge>
                        )}
                      </td>
                      <td className="num">{relativeTime(endpoint.last_seen_at)}</td>
                      <td>
                        <LinkAction endpoint={endpoint} onDone={load} onOpenConsole={onOpenConsole} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="row row--between" style={{ marginTop: "var(--sp-4)" }}>
              <p className="subtle">
                Showing {visible.length} of {integer(data.total)} · page {page + 1} of {pageCount}
              </p>
              <div className="row">
                <button className="btn btn--sm" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
                  Previous
                </button>
                <button
                  className="btn btn--sm"
                  disabled={page + 1 >= pageCount}
                  onClick={() => setPage((p) => p + 1)}
                >
                  Next
                </button>
              </div>
            </div>
          </>
        )}
      </Panel>
    </div>
  );
}

function LinkAction({ endpoint, onDone, onOpenConsole }) {
  const [busy, setBusy] = useState(false);

  if (endpoint.link_channel_id) {
    return (
      <button
        className="btn btn--sm"
        onClick={() => onOpenConsole({ callsign: endpoint.callsign, channelId: endpoint.link_channel_id })}
      >
        Open console
      </button>
    );
  }

  return (
    <button
      className="btn btn--sm"
      disabled={busy || !endpoint.key_verified}
      title={endpoint.key_verified ? "Create the encrypted link channel" : "Aircraft must publish its key bundle first"}
      onClick={async () => {
        setBusy(true);
        try {
          await fleetApi.link(endpoint.callsign);
          await onDone();
        } finally {
          setBusy(false);
        }
      }}
    >
      {busy ? "Linking…" : "Establish link"}
    </button>
  );
}

function ProvisionPanel({ onProvisioned }) {
  const [callsign, setCallsign] = useState("");
  const [airframe, setAirframe] = useState("");
  const [fleet, setFleet] = useState("default");
  const [bulkCount, setBulkCount] = useState(1);
  const [issued, setIssued] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function provision() {
    setBusy(true);
    setError("");
    setIssued(null);
    try {
      const result =
        bulkCount > 1
          ? await fleetApi.provisionBulk({
              callsign_prefix: callsign,
              count: Number(bulkCount),
              airframe: airframe || null,
              fleet,
            })
          : await fleetApi.provision({ callsign, airframe: airframe || null, fleet });

      setIssued(result.endpoints ?? [{ callsign: result.callsign, enrollment_token: result.enrollment_token }]);
      setCallsign("");
      await onProvisioned();
    } catch (caught) {
      setError(caught.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel
      eyebrow="Provisioning"
      title="Add endpoints"
      description="Each aircraft receives a single-use enrolment token. The server stores only its hash."
    >
      <div className="stack">
        <div className="row row--wrap" style={{ alignItems: "flex-end" }}>
          <Field label={bulkCount > 1 ? "Callsign prefix" : "Callsign"} id="callsign">
            <input
              id="callsign"
              className="input"
              value={callsign}
              placeholder={bulkCount > 1 ? "FLEET" : "UAV-001"}
              onChange={(changeEvent) => setCallsign(changeEvent.target.value)}
            />
          </Field>
          <Field label="Airframe" id="airframe">
            <input
              id="airframe"
              className="input"
              value={airframe}
              placeholder="quad-x"
              onChange={(changeEvent) => setAirframe(changeEvent.target.value)}
            />
          </Field>
          <Field label="Fleet" id="fleet">
            <input
              id="fleet"
              className="input"
              value={fleet}
              onChange={(changeEvent) => setFleet(changeEvent.target.value)}
            />
          </Field>
          <Field label="Count" id="count" hint="Up to 1000 in one batch">
            <input
              id="count"
              type="number"
              min="1"
              max="1000"
              className="input"
              style={{ width: "110px" }}
              value={bulkCount}
              onChange={(changeEvent) => setBulkCount(changeEvent.target.value)}
            />
          </Field>
          <button className="btn btn--primary" onClick={provision} disabled={busy || !callsign}>
            {busy ? "Provisioning…" : "Provision"}
          </button>
        </div>

        {error && <Alert tone="error">{error}</Alert>}

        {issued && (
          <Alert tone="warning" title="Enrolment tokens — shown once">
            <p className="subtle">
              Copy these now. The server keeps only a hash and cannot show them again.
            </p>
            <div className="table-wrap" style={{ maxHeight: "220px", overflowY: "auto", marginTop: "var(--sp-2)" }}>
              <table className="table">
                <thead>
                  <tr>
                    <th scope="col">Callsign</th>
                    <th scope="col">Enrolment token</th>
                  </tr>
                </thead>
                <tbody>
                  {issued.map((item) => (
                    <tr key={item.callsign}>
                      <td className="mono">{item.callsign}</td>
                      <td className="mono break-all">{item.enrollment_token}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Alert>
        )}
      </div>
    </Panel>
  );
}
