import { useCallback, useEffect, useMemo, useState } from "react";
import { fleetApi } from "../lib/api.js";
import { bytesToBase64 } from "../crypto/bytes.js";
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
    const contained = data.endpoints.filter(
      (item) => item.security_state && item.security_state !== "active",
    ).length;
    const drifted = data.endpoints.filter(
      (item) => item.attestation_state === "drifted",
    ).length;
    return { enrolled, linked, pending, contained, drifted };
  }, [data.endpoints]);

  const pageCount = Math.max(1, Math.ceil(data.total / PAGE_SIZE));

  return (
    <div className="view__inner">
      <div className="tile-grid">
        <StatTile label="Endpoints" value={integer(data.total)} meta="provisioned in this fleet" />
        <StatTile label="Enrolled" value={integer(summary.enrolled)} meta="on this page" />
        <StatTile label="Linked" value={integer(summary.linked)} meta="encrypted channel open" />
        <StatTile label="Awaiting enrolment" value={integer(summary.pending)} meta="token unredeemed" />
        <StatTile
          label="Contained"
          value={integer(summary.contained)}
          meta="quarantined or revoked"
          tone={summary.contained ? "critical" : undefined}
        />
        <StatTile
          label="Firmware drift"
          value={integer(summary.drifted)}
          meta="reported digest differs from pin"
          tone={summary.drifted ? "critical" : undefined}
        />
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
                    <th scope="col">State</th>
                    <th scope="col">Attestation</th>
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
                        <ContainmentBadge endpoint={endpoint} />
                      </td>
                      <td>
                        <AttestationCell endpoint={endpoint} onDone={load} />
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
                        <div className="row" style={{ gap: "var(--sp-2)" }}>
                          <LinkAction endpoint={endpoint} onDone={load} onOpenConsole={onOpenConsole} />
                          <ContainmentAction endpoint={endpoint} onDone={load} />
                        </div>
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

const ATTESTATION_TONES = {
  trusted: ["good", "matches pin"],
  drifted: ["critical", "does not match the pinned firmware"],
  unreported: ["warning", "pinned, but nothing reported yet"],
  unpinned: ["neutral", "no approved firmware recorded"],
};

/**
 * Pin the firmware digest an endpoint should report, and show whether it does.
 *
 * The digest is computed here, in the browser, from the image the operator selects. That
 * keeps a possibly large firmware file off the network and off the server entirely -- all
 * that is ever uploaded is 32 bytes.
 */
function AttestationCell({ endpoint, onDone }) {
  const [open, setOpen] = useState(false);
  const [digest, setDigest] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const state = endpoint.attestation_state || "unpinned";
  const [tone, hint] = ATTESTATION_TONES[state] ?? ATTESTATION_TONES.unpinned;

  async function hashFile(file) {
    setError("");
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
      setDigest(bytesToBase64(hash));
    } catch (caught) {
      setError(`Could not read that file: ${caught.message}`);
    }
  }

  async function save(value) {
    setBusy(true);
    setError("");
    try {
      await fleetApi.pinMeasurement(endpoint.callsign, value);
      setOpen(false);
      setDigest("");
      await onDone();
    } catch (caught) {
      setError(caught.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="stack" style={{ gap: "var(--sp-1)" }}>
      <Badge tone={tone} title={hint}>{state}</Badge>

      {state === "drifted" && (
        <span className="subtle mono" title="pinned → reported">
          {endpoint.expected_measurement} → {endpoint.last_measurement}
        </span>
      )}

      {open ? (
        <div className="stack reveal" style={{ gap: "var(--sp-2)", minWidth: "240px" }}>
          <input
            type="file"
            className="input"
            aria-label="Firmware image to hash"
            onChange={(changeEvent) => {
              const file = changeEvent.target.files?.[0];
              if (file) hashFile(file);
            }}
          />
          <input
            className="input mono"
            placeholder="or paste the base64 SHA-256"
            aria-label="Firmware digest, base64 SHA-256"
            value={digest}
            onChange={(changeEvent) => setDigest(changeEvent.target.value.trim())}
          />
          <p className="subtle">
            Hashed in this browser; only the 32-byte digest is uploaded. A self-reported
            measurement proves the endpoint holds its key, not what it is running.
          </p>
          {error && <Alert tone="error">{error}</Alert>}
          <div className="row" style={{ gap: "var(--sp-2)" }}>
            <button className="btn btn--sm" disabled={busy || !digest} onClick={() => save(digest)}>
              {busy ? "Saving…" : "Pin"}
            </button>
            {endpoint.expected_measurement && (
              <button className="link-btn" disabled={busy} onClick={() => save("")}>
                Clear pin
              </button>
            )}
            <button
              className="link-btn"
              disabled={busy}
              onClick={() => {
                setOpen(false);
                setError("");
              }}
            >
              Cancel
            </button>
          </div>
        </div>
      ) : (
        <button className="link-btn" onClick={() => setOpen(true)}>
          {endpoint.expected_measurement ? "Re-pin firmware" : "Pin firmware"}
        </button>
      )}
    </div>
  );
}

function ContainmentBadge({ endpoint }) {
  const state = endpoint.security_state || "active";
  if (state === "revoked") {
    return (
      <Badge tone="critical" glyph="⊘" title={endpoint.security_state_reason || undefined}>
        revoked
      </Badge>
    );
  }
  if (state === "quarantined") {
    return (
      <Badge tone="warning" glyph="⏻" title={endpoint.security_state_reason || undefined}>
        quarantined
      </Badge>
    );
  }
  return <Badge tone="neutral">in service</Badge>;
}

/**
 * Cut an endpoint off, or bring a suspended one back.
 *
 * Revocation asks for the callsign to be typed out. That is not ceremony: it is the one
 * action here with no undo, it destroys the enrolment path, and the button sits in a
 * dense table one row away from "Establish link".
 */
function ContainmentAction({ endpoint, onDone }) {
  const [mode, setMode] = useState(null);
  const [reason, setReason] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const state = endpoint.security_state || "active";

  function close() {
    setMode(null);
    setReason("");
    setConfirm("");
    setError("");
  }

  async function run(action) {
    setBusy(true);
    setError("");
    try {
      await action();
      close();
      await onDone();
    } catch (caught) {
      setError(caught.message);
    } finally {
      setBusy(false);
    }
  }

  if (state === "revoked") {
    return <span className="subtle">no route back</span>;
  }

  if (mode) {
    const revoking = mode === "revoke";
    return (
      <div className="stack reveal" style={{ gap: "var(--sp-2)", minWidth: "220px" }}>
        <input
          className="input"
          placeholder="Reason (recorded in the audit log)"
          aria-label="Containment reason"
          value={reason}
          onChange={(changeEvent) => setReason(changeEvent.target.value)}
        />
        {revoking && (
          <>
            <p className="subtle">
              Permanent. The enrolment path is destroyed and this callsign cannot return to
              service. Rotate the channel epoch as well — revocation stops the endpoint
              authenticating, it does not make what it already holds unreadable.
            </p>
            <input
              className="input mono"
              placeholder={`Type ${endpoint.callsign} to confirm`}
              aria-label={`Type ${endpoint.callsign} to confirm revocation`}
              value={confirm}
              onChange={(changeEvent) => setConfirm(changeEvent.target.value)}
            />
          </>
        )}
        {error && <Alert tone="error">{error}</Alert>}
        <div className="row" style={{ gap: "var(--sp-2)" }}>
          <button
            className={revoking ? "btn btn--sm btn--danger" : "btn btn--sm"}
            disabled={busy || (revoking && confirm !== endpoint.callsign)}
            onClick={() =>
              run(() =>
                revoking
                  ? fleetApi.revoke(endpoint.callsign, reason)
                  : fleetApi.quarantine(endpoint.callsign, reason),
              )
            }
          >
            {busy ? "Working…" : revoking ? "Revoke permanently" : "Quarantine"}
          </button>
          <button className="link-btn" onClick={close} disabled={busy}>
            Cancel
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="row" style={{ gap: "var(--sp-2)" }}>
      {state === "quarantined" ? (
        <button
          className="btn btn--sm"
          disabled={busy}
          title="Return this endpoint to service. It must re-authenticate."
          onClick={() => run(() => fleetApi.restore(endpoint.callsign))}
        >
          {busy ? "Working…" : "Restore"}
        </button>
      ) : (
        <button
          className="btn btn--sm"
          title="Suspend this endpoint. Reversible."
          onClick={() => setMode("quarantine")}
        >
          Quarantine
        </button>
      )}
      <button
        className="link-btn"
        title="Permanently cut off a captured or cloned endpoint"
        onClick={() => setMode("revoke")}
      >
        Revoke
      </button>
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
