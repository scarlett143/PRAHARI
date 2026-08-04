import { useMemo } from "react";
import { coordinate } from "../lib/format.js";

/**
 * A self-contained track display.
 *
 * Deliberately draws no external map tiles. A ground control station is
 * routinely operated on an isolated or air-gapped network, and reaching out to
 * a tile CDN would both fail there and leak the operating area to a third
 * party. What matters operationally -- track history, heading, home offset and
 * scale -- is all derivable from the telemetry we already hold.
 *
 * Positions are projected to a local east/north plane in metres around the
 * first fix, which is accurate well beyond the range of a single sortie.
 */

const METRES_PER_DEG_LAT = 111_320;

export function TacticalMap({ track = [], height = 340 }) {
  const width = 640;
  const model = useMemo(() => {
    const fixes = track.filter(
      (point) => Number.isFinite(point.lat) && Number.isFinite(point.lon),
    );
    if (!fixes.length) return null;

    const origin = fixes[0];
    const lonScale = METRES_PER_DEG_LAT * Math.cos((origin.lat * Math.PI) / 180);
    const projected = fixes.map((fix) => ({
      ...fix,
      east: (fix.lon - origin.lon) * lonScale,
      north: (fix.lat - origin.lat) * METRES_PER_DEG_LAT,
    }));

    const easts = projected.map((point) => point.east);
    const norths = projected.map((point) => point.north);
    const span = Math.max(
      Math.max(...easts) - Math.min(...easts),
      Math.max(...norths) - Math.min(...norths),
      200,
    ) * 1.3;

    const centreEast = (Math.max(...easts) + Math.min(...easts)) / 2;
    const centreNorth = (Math.max(...norths) + Math.min(...norths)) / 2;
    const scale = Math.min(width, height) / span;

    const toScreen = (point) => ({
      x: width / 2 + (point.east - centreEast) * scale,
      // North is up, so the screen y axis is inverted.
      y: height / 2 - (point.north - centreNorth) * scale,
    });

    return {
      points: projected.map((point) => ({ ...point, ...toScreen(point) })),
      home: toScreen({ east: 0, north: 0 }),
      span,
      scale,
    };
  }, [track, height]);

  if (!model) {
    return (
      <div className="map-frame" style={{ height, display: "grid", placeItems: "center" }}>
        <p className="subtle">No position fixes decrypted yet</p>
      </div>
    );
  }

  const current = model.points[model.points.length - 1];
  const path = model.points.map((p, i) => `${i === 0 ? "M" : "L"}${p.x},${p.y}`).join(" ");
  // A round-ish number of metres for the scale bar.
  const barMetres = [50, 100, 250, 500, 1000, 2000, 5000].find((m) => m * model.scale > 60) ?? 5000;
  const barPixels = barMetres * model.scale;

  return (
    <div className="map-frame">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        width="100%"
        height={height}
        role="img"
        aria-label={`Track display. Current position ${coordinate(current.lat)}, ${coordinate(current.lon)}.`}
      >
        <defs>
          <pattern id="tac-grid" width="40" height="40" patternUnits="userSpaceOnUse">
            <path d="M40 0 L0 0 0 40" fill="none" stroke="var(--gridline)" strokeWidth="1" />
          </pattern>
        </defs>

        <rect width={width} height={height} fill="var(--surface-sunken)" />
        <rect width={width} height={height} fill="url(#tac-grid)" />

        {/* Home marker: where the first decrypted fix put the aircraft. */}
        <g transform={`translate(${model.home.x}, ${model.home.y})`}>
          <circle r="6" fill="none" stroke="var(--ink-muted)" strokeWidth="1.5" />
          <line x1="-9" x2="9" y1="0" y2="0" stroke="var(--ink-muted)" strokeWidth="1.5" />
          <line x1="0" x2="0" y1="-9" y2="9" stroke="var(--ink-muted)" strokeWidth="1.5" />
          <text x="12" y="4" fontSize="10" fill="var(--ink-muted)">HOME</text>
        </g>

        <path d={path} fill="none" stroke="var(--series-1)" strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" opacity="0.85" />

        {/* Aircraft: a heading-oriented chevron, so attitude is readable at a glance. */}
        <g transform={`translate(${current.x}, ${current.y}) rotate(${current.heading_deg ?? 0})`}>
          <path d="M0,-11 L7,8 L0,4 L-7,8 Z" fill="var(--accent)" stroke="var(--surface)" strokeWidth="1.5" />
        </g>

        <g transform={`translate(16, ${height - 18})`}>
          <line x1="0" x2={barPixels} y1="0" y2="0" stroke="var(--ink-secondary)" strokeWidth="2" />
          <line x1="0" x2="0" y1="-4" y2="4" stroke="var(--ink-secondary)" strokeWidth="2" />
          <line x1={barPixels} x2={barPixels} y1="-4" y2="4" stroke="var(--ink-secondary)" strokeWidth="2" />
          <text x={barPixels / 2} y="-8" textAnchor="middle" fontSize="10" fill="var(--ink-secondary)">
            {barMetres >= 1000 ? `${barMetres / 1000} km` : `${barMetres} m`}
          </text>
        </g>

        <text x={width - 16} y="22" textAnchor="end" fontSize="10" fill="var(--ink-muted)">
          {model.points.length} fixes decrypted
        </text>
      </svg>
    </div>
  );
}
