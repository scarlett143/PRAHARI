import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { workspaceApi } from "../lib/api.js";
import { decryptMessage, encryptMessage } from "../crypto/aead.js";
import { ensureSession, getStoredSessionKey } from "../crypto/session.js";
import { Alert, Badge, EmptyState, Panel, StatTile } from "../components/ui.jsx";
import { SeriesTable, TimeSeriesChart } from "../components/charts.jsx";
import { TacticalMap } from "../components/TacticalMap.jsx";
import { clockTime, coordinate, integer, num, relativeTime } from "../lib/format.js";

const MAX_POINTS = 240;

/**
 * Ground control console for one aircraft.
 *
 * Every frame shown here was decrypted in this browser. The server relayed
 * opaque envelopes and never held the session key, so the telemetry on screen
 * is not something the backend could have rendered on our behalf.
 */
export default function LinkConsoleRoute({ target, user, identity, socketEvent, onBack }) {
  const [channel, setChannel] = useState(null);
  const [frames, setFrames] = useState([]);
  const [session, setSession] = useState({ tone: "neutral", text: "Establishing session…" });
  const [error, setError] = useState("");
  const [commandNote, setCommandNote] = useState("");
  const seenRef = useRef(new Set());

  const ingest = useCallback(
    async (details) => {
      const rows = await workspaceApi.messages(details.id, 200);
      const decoded = [];
      for (const message of rows) {
        if (message.sender_id === user.id) continue; // our own uplink
        if (seenRef.current.has(message.id)) continue;
        try {
          let key = await getStoredSessionKey(details.id, message.key_epoch);
          if (!key && message.key_epoch === details.key_epoch) {
            key = await ensureSession(details, user, identity, message.key_epoch);
          }
          if (!key) continue;
          const plaintext = await decryptMessage(key, message.envelope_b64, {
            senderId: message.sender_id,
            channelId: details.id,
            epoch: message.key_epoch,
          });
          const frame = JSON.parse(plaintext);
          seenRef.current.add(message.id);
          decoded.push({ ...frame, receivedAt: message.created_at, id: message.id });
        } catch {
          // A frame from an epoch whose key we no longer hold is expected after
          // rotation; it is not an error worth surfacing to the operator.
        }
      }
      if (decoded.length) {
        setFrames((current) => [...current, ...decoded].slice(-MAX_POINTS));
      }
    },
    [user, identity],
  );

  const open = useCallback(async () => {
    setError("");
    try {
      const details = await workspaceApi.channel(target.channelId);
      setChannel(details);
      await ensureSession(details, user, identity);
      setSession({ tone: "good", text: `Encrypted · epoch ${details.key_epoch}` });
      await ingest(details);
    } catch (caught) {
      setSession({ tone: "warning", text: caught.message });
      setError(caught.message);
    }
  }, [target.channelId, user, identity, ingest]);

  useEffect(() => {
    seenRef.current = new Set();
    setFrames([]);
    open();
  }, [open]);

  // Live push; the poll is a safety net for a dropped socket.
  useEffect(() => {
    if (!channel) return undefined;
    if (socketEvent?.channel_id === channel.id) {
      if (socketEvent.type === "channel.epoch_rotated") open();
      else ingest(channel).catch(() => {});
    }
    const timer = setInterval(() => ingest(channel).catch(() => {}), 3000);
    return () => clearInterval(timer);
  }, [channel, socketEvent, ingest, open]);

  const telemetry = useMemo(() => {
    const positions = frames
      .map((frame) => normalise(frame))
      .filter((frame) => frame !== null);
    return {
      track: positions,
      altitude: positions.map((p) => ({ t: p.t, v: p.alt_m })).filter((p) => Number.isFinite(p.v)),
      speed: positions.map((p) => ({ t: p.t, v: p.groundspeed_ms })).filter((p) => Number.isFinite(p.v)),
      battery: positions.map((p) => ({ t: p.t, v: p.battery_pct })).filter((p) => Number.isFinite(p.v)),
      latest: positions[positions.length - 1] ?? null,
    };
  }, [frames]);

  async function sendCommand(command) {
    if (!channel) return;
    setCommandNote("");
    try {
      const key = await ensureSession(channel, user, identity);
      const envelope = await encryptMessage(key, JSON.stringify(command), {
        senderId: user.id,
        channelId: channel.id,
        epoch: channel.key_epoch,
      });
      await workspaceApi.send({
        client_message_id: crypto.randomUUID(),
        channel_id: channel.id,
        key_epoch: channel.key_epoch,
        envelope_b64: envelope,
      });
      setCommandNote(`${command.command} encrypted and uplinked`);
    } catch (caught) {
      setError(caught.message);
    }
  }

  const latest = telemetry.latest;

  return (
    <div className="view__inner">
      <div className="row row--between">
        <div>
          <div className="eyebrow">Ground control link</div>
          <h2 className="mono">{target.callsign}</h2>
        </div>
        <div className="row">
          <Badge tone={session.tone}>{session.text}</Badge>
          <button className="btn btn--sm" onClick={onBack}>Back to fleet</button>
        </div>
      </div>

      {error && <Alert tone="error">{error}</Alert>}
      {commandNote && <Alert tone="good">{commandNote}</Alert>}

      <div className="tile-grid">
        <StatTile label="Altitude" value={num(latest?.alt_m, 1)} unit=" m" meta="above launch" />
        <StatTile label="Groundspeed" value={num(latest?.groundspeed_ms, 1)} unit=" m/s" />
        <StatTile label="Heading" value={num(latest?.heading_deg, 0)} unit="°" />
        <StatTile
          label="Battery"
          value={num(latest?.battery_pct, 0)}
          unit="%"
          tone={latest?.battery_pct < 20 ? "critical" : latest?.battery_pct < 40 ? "warning" : undefined}
        />
        <StatTile label="Frames decrypted" value={integer(frames.length)} meta="this session" />
      </div>

      <div className="console-grid">
        <Panel
          title="Track"
          description="Rendered from decrypted position fixes. No external map service is contacted."
          actions={latest && <span className="mono subtle">{coordinate(latest.lat)}, {coordinate(latest.lon)}</span>}
        >
          <TacticalMap track={telemetry.track} />
        </Panel>

        <div className="stack">
          <Panel title="Command uplink" description="Commands are encrypted here before upload, exactly like telemetry.">
            <div className="command-grid">
              <button className="btn" onClick={() => sendCommand({ type: "command", command: "ARM" })}>Arm</button>
              <button className="btn" onClick={() => sendCommand({ type: "command", command: "DISARM" })}>Disarm</button>
              <button className="btn" onClick={() => sendCommand({ type: "command", command: "SET_MODE", mode: "GUIDED" })}>Guided</button>
              <button className="btn" onClick={() => sendCommand({ type: "command", command: "SET_MODE", mode: "AUTO" })}>Auto</button>
              <button className="btn btn--danger" onClick={() => sendCommand({ type: "command", command: "RTL" })}>Return to launch</button>
            </div>
          </Panel>

          <Panel title="Link state">
            <dl className="stack" style={{ gap: "var(--sp-2)" }}>
              <Row label="Key epoch" value={channel ? `E${channel.key_epoch}` : "—"} />
              <Row label="Messages this epoch" value={integer(channel?.epoch_message_count ?? 0)} />
              <Row label="Cipher" value="AES-256-GCM" />
              <Row label="Key agreement" value="X25519 + ML-KEM-768" />
              <Row label="Last frame" value={relativeTime(latest?.receivedAt)} />
            </dl>
            <button
              className="btn btn--sm"
              style={{ marginTop: "var(--sp-3)" }}
              disabled={!channel}
              onClick={async () => {
                await workspaceApi.rotateEpoch(channel.id);
                await open();
              }}
            >
              Rotate epoch
            </button>
          </Panel>
        </div>
      </div>

      <Panel title="Telemetry" description="Each measure has its own axis — never two scales on one chart.">
        {telemetry.altitude.length < 2 ? (
          <EmptyState title="Waiting for telemetry">
            Start the bridge for {target.callsign} to stream encrypted frames.
          </EmptyState>
        ) : (
          <div className="stack">
            <TimeSeriesChart title="Altitude" series={telemetry.altitude} unit=" m" color="var(--series-1)" />
            <TimeSeriesChart title="Groundspeed" series={telemetry.speed} unit=" m/s" color="var(--series-3)" />
            <TimeSeriesChart title="Battery" series={telemetry.battery} unit="%" digits={0} color="var(--series-4)" />
            <div className="row row--wrap">
              <SeriesTable title="Altitude" series={telemetry.altitude} unit="m" />
              <SeriesTable title="Groundspeed" series={telemetry.speed} unit="m/s" />
              <SeriesTable title="Battery" series={telemetry.battery} unit="%" digits={0} />
            </div>
          </div>
        )}
      </Panel>

      <Panel title="Decrypted frame log" flush>
        <div className="table-wrap" style={{ maxHeight: "300px", overflowY: "auto" }}>
          <table className="table">
            <thead>
              <tr>
                <th scope="col">Received</th>
                <th scope="col">Type</th>
                <th scope="col">Message</th>
                <th scope="col">Detail</th>
              </tr>
            </thead>
            <tbody>
              {[...frames].reverse().slice(0, 60).map((frame) => (
                <tr key={frame.id}>
                  <td className="num">{clockTime(frame.receivedAt)}</td>
                  <td>{frame.type ?? "—"}</td>
                  <td className="mono">{frame.message ?? frame.source ?? "telemetry"}</td>
                  <td className="subtle truncate" style={{ maxWidth: "420px" }}>
                    {summarise(frame)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}

function Row({ label, value }) {
  return (
    <div className="row row--between">
      <dt className="subtle">{label}</dt>
      <dd className="mono" style={{ margin: 0 }}>{value}</dd>
    </div>
  );
}

/** Both bridge sources are supported: synthetic frames carry flat fields, real
 *  MAVLink frames nest them under `fields` with autopilot units. */
function normalise(frame) {
  const t = frame.t ?? Date.now() / 1000;
  if (frame.type === "telemetry") {
    return { ...frame, t };
  }
  if (frame.type === "mavlink" && frame.fields) {
    const f = frame.fields;
    if (frame.message === "GLOBAL_POSITION_INT") {
      return {
        ...frame,
        t,
        lat: f.lat / 1e7,
        lon: f.lon / 1e7,
        alt_m: f.relative_alt / 1000,
        heading_deg: f.hdg / 100,
        groundspeed_ms: Math.hypot(f.vx ?? 0, f.vy ?? 0) / 100,
      };
    }
    if (frame.message === "VFR_HUD") {
      return { ...frame, t, alt_m: f.alt, groundspeed_ms: f.groundspeed, heading_deg: f.heading };
    }
    if (frame.message === "SYS_STATUS") {
      return { ...frame, t, battery_pct: f.battery_remaining };
    }
  }
  return null;
}

function summarise(frame) {
  if (frame.type === "telemetry") {
    return `alt ${num(frame.alt_m)} m · gs ${num(frame.groundspeed_ms)} m/s · batt ${num(frame.battery_pct, 0)}%`;
  }
  if (frame.fields) {
    return Object.entries(frame.fields)
      .slice(0, 4)
      .map(([key, value]) => `${key}=${value}`)
      .join(" · ");
  }
  return "—";
}
