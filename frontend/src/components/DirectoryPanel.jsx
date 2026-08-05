import { useCallback, useEffect, useRef, useState } from "react";
import { inviteApi, linkApi, workspaceApi } from "../lib/api.js";
import { Alert, Badge, EmptyState, Field, Panel } from "./ui.jsx";

/** Keystrokes are cheap; directory queries are not. */
const SEARCH_DEBOUNCE_MS = 220;

function PresenceDot({ online }) {
  return (
    <span
      className={online ? "dot dot--pulse" : "dot"}
      style={{ color: online ? "var(--good)" : "var(--muted)" }}
      aria-hidden="true"
    />
  );
}

/**
 * Live operator directory.
 *
 * Searches the server as you type and reflects presence pushed over the WebSocket, so a
 * peer coming online updates here without a reload. `link_state` comes back with each
 * row, which is what decides whether this offers "Link", "Requested", or "Open".
 */
export function PeerDirectory({ presence, refreshToken, onLinked, onOpenChannel }) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [busyId, setBusyId] = useState("");
  const [note, setNote] = useState("");
  const requestSeq = useRef(0);

  const search = useCallback(async (value) => {
    const seq = ++requestSeq.current;
    setLoading(true);
    try {
      const rows = await workspaceApi.searchUsers(value);
      // A slow earlier query must not overwrite a fast later one.
      if (seq === requestSeq.current) {
        setResults(rows);
        setError("");
      }
    } catch (caught) {
      if (seq === requestSeq.current) setError(caught.message);
    } finally {
      if (seq === requestSeq.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = setTimeout(() => search(query), SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [query, search, refreshToken]);

  async function requestLink(row) {
    setBusyId(row.id);
    setError("");
    setNote("");
    try {
      const result = await linkApi.request(row.username);
      if (result.status === "already_linked") {
        setNote(`Already linked with ${row.username}.`);
        onOpenChannel?.(result.channel_id);
      } else if (result.status === "reciprocal_pending") {
        setNote(result.message);
      } else {
        setNote(`Link request sent to ${row.username}.`);
      }
      await search(query);
      onLinked?.();
    } catch (caught) {
      setError(caught.message);
    } finally {
      setBusyId("");
    }
  }

  return (
    <Panel title="Operators" description="Search the directory and open an encrypted link.">
      <div className="stack">
        <Field label="Find an operator" id="peer-search">
          <input
            id="peer-search"
            className="input"
            value={query}
            placeholder="type a username…"
            autoComplete="off"
            onChange={(changeEvent) => setQuery(changeEvent.target.value)}
          />
        </Field>

        {note && <Alert tone="info">{note}</Alert>}
        {error && <Alert tone="error">{error}</Alert>}

        <ul className="stack" style={{ gap: "var(--sp-2)" }}>
          {results.map((row) => {
            const online = presence[row.id] ?? row.online;
            return (
              <li key={row.id} className="row row--between">
                <span className="row" style={{ gap: "var(--sp-2)", minWidth: 0 }}>
                  <PresenceDot online={online} />
                  <span className="truncate">{row.username}</span>
                  {!row.key_verified && <Badge tone="warning">no keys</Badge>}
                </span>

                {row.link_state === "linked" ? (
                  <Badge tone="good">linked</Badge>
                ) : row.link_state === "outgoing_pending" ? (
                  <Badge tone="warning">requested</Badge>
                ) : row.link_state === "incoming_pending" ? (
                  <Badge tone="accent">wants to link</Badge>
                ) : (
                  <button
                    className="btn btn--sm"
                    disabled={busyId === row.id || !row.key_verified}
                    onClick={() => requestLink(row)}
                  >
                    {busyId === row.id ? "…" : "Link"}
                  </button>
                )}
              </li>
            );
          })}
        </ul>

        {!results.length && !loading && (
          <p className="muted">
            {query
              ? "No operator matches that name."
              : "No other operators with published keys yet."}
          </p>
        )}
      </div>
    </Panel>
  );
}

/** Pending link requests in both directions. */
export function LinkRequests({ links, onChanged, onOpenChannel }) {
  const [busyId, setBusyId] = useState("");
  const [error, setError] = useState("");

  async function act(linkId, action) {
    setBusyId(linkId);
    setError("");
    try {
      const result = await linkApi[action](linkId);
      if (action === "accept" && result.channel_id) onOpenChannel?.(result.channel_id);
      await onChanged?.();
    } catch (caught) {
      setError(caught.message);
    } finally {
      setBusyId("");
    }
  }

  const incoming = links?.incoming ?? [];
  const outgoing = links?.outgoing ?? [];
  if (!incoming.length && !outgoing.length) return null;

  return (
    <Panel title="Link requests">
      <div className="stack">
        {error && <Alert tone="error">{error}</Alert>}

        {incoming.map((row) => (
          <div key={row.id} className="stack" style={{ gap: "var(--sp-2)" }}>
            <span className="row" style={{ gap: "var(--sp-2)" }}>
              <Badge tone="accent">incoming</Badge>
              <strong className="truncate">{row.requester}</strong>
            </span>
            {row.note && <p className="muted">{row.note}</p>}
            <div className="row" style={{ gap: "var(--sp-2)" }}>
              <button
                className="btn btn--sm btn--primary"
                disabled={busyId === row.id}
                onClick={() => act(row.id, "accept")}
              >
                Accept
              </button>
              <button
                className="btn btn--sm"
                disabled={busyId === row.id}
                onClick={() => act(row.id, "decline")}
              >
                Decline
              </button>
            </div>
          </div>
        ))}

        {outgoing.map((row) => (
          <div key={row.id} className="row row--between">
            <span className="row" style={{ gap: "var(--sp-2)", minWidth: 0 }}>
              <Badge tone="warning">sent</Badge>
              <span className="truncate">{row.target}</span>
            </span>
            <button
              className="btn btn--sm"
              disabled={busyId === row.id}
              onClick={() => act(row.id, "cancel")}
            >
              Cancel
            </button>
          </div>
        ))}
      </div>
    </Panel>
  );
}

/**
 * Invite link creation.
 *
 * The server returns the plaintext code exactly once, so this holds it in component
 * state for copying and never claims it can show it again.
 */
export function InvitePanel({ workspace }) {
  const [issued, setIssued] = useState(null);
  const [invites, setInvites] = useState([]);
  const [maxUses, setMaxUses] = useState(1);
  const [hours, setHours] = useState(24);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);

  const refresh = useCallback(async () => {
    if (!workspace) return;
    try {
      setInvites(await inviteApi.list(workspace.id));
    } catch (caught) {
      setError(caught.message);
    }
  }, [workspace]);

  useEffect(() => {
    setIssued(null);
    refresh();
  }, [refresh]);

  const joinUrl = issued ? `${window.location.origin}/join/${issued.code}` : "";

  async function copy() {
    try {
      await navigator.clipboard.writeText(joinUrl);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setError("Clipboard blocked — select the link and copy it manually.");
    }
  }

  return (
    <Panel title="Invite link" description="Anyone with this link can join this workspace.">
      <div className="stack">
        <div className="row" style={{ gap: "var(--sp-2)" }}>
          <Field label="Uses" id="invite-uses">
            <input
              id="invite-uses"
              className="input"
              type="number"
              min="1"
              max="100"
              value={maxUses}
              onChange={(changeEvent) => setMaxUses(Number(changeEvent.target.value))}
            />
          </Field>
          <Field label="Expires (hours)" id="invite-hours">
            <input
              id="invite-hours"
              className="input"
              type="number"
              min="1"
              max="720"
              value={hours}
              onChange={(changeEvent) => setHours(Number(changeEvent.target.value))}
            />
          </Field>
        </div>

        {error && <Alert tone="error">{error}</Alert>}

        <button
          className="btn btn--primary"
          disabled={busy || !workspace}
          onClick={async () => {
            setBusy(true);
            setError("");
            try {
              const created = await inviteApi.create({
                server_id: workspace.id,
                max_uses: maxUses,
                expires_in_hours: hours,
              });
              setIssued(created);
              await refresh();
            } catch (caught) {
              setError(caught.message);
            } finally {
              setBusy(false);
            }
          }}
        >
          {busy ? "Generating…" : "Generate invite link"}
        </button>

        {issued && (
          <div className="stack" style={{ gap: "var(--sp-2)" }}>
            <Alert tone="warning">
              Copy this now — the code is stored hashed and cannot be shown again.
            </Alert>
            <input className="input" readOnly value={joinUrl} onFocus={(e) => e.target.select()} />
            <button className="btn btn--sm" onClick={copy}>
              {copied ? "Copied ✓" : "Copy link"}
            </button>
          </div>
        )}

        {invites.length > 0 && (
          <div>
            <div className="eyebrow">Issued</div>
            <ul className="stack" style={{ gap: "var(--sp-2)", marginTop: "var(--sp-2)" }}>
              {invites.map((invite) => (
                <li key={invite.id} className="row row--between">
                  <span className="row" style={{ gap: "var(--sp-2)", minWidth: 0 }}>
                    <code className="truncate">{invite.code_hint}…</code>
                    <Badge tone={invite.state === "active" ? "good" : "neutral"}>
                      {invite.state}
                    </Badge>
                    <span className="muted">
                      {invite.use_count}/{invite.max_uses}
                    </span>
                  </span>
                  {invite.state === "active" && (
                    <button
                      className="btn btn--sm"
                      onClick={async () => {
                        try {
                          await inviteApi.revoke(invite.id);
                          await refresh();
                        } catch (caught) {
                          setError(caught.message);
                        }
                      }}
                    >
                      Revoke
                    </button>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}

        {!invites.length && !issued && (
          <EmptyState title="No invites issued">
            Generate one to bring another operator into this workspace.
          </EmptyState>
        )}
      </div>
    </Panel>
  );
}
