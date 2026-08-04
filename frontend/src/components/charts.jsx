import { useId, useMemo, useRef, useState } from "react";

/**
 * Telemetry charts.
 *
 * Altitude, groundspeed, battery and link quality live on different scales, so
 * each gets its own chart with its own axis. A dual-axis chart would let the
 * viewer read a crossing point that means nothing, so there is deliberately no
 * option for one here -- small multiples instead.
 *
 * Each chart carries a single series, so identity comes from the title rather
 * than a legend, and the latest value is direct-labelled (which also satisfies
 * the relief rule for the lighter series colours on the light surface).
 */

function extent(values) {
  let min = Infinity;
  let max = -Infinity;
  for (const value of values) {
    if (!Number.isFinite(value)) continue;
    if (value < min) min = value;
    if (value > max) max = value;
  }
  if (min === Infinity) return [0, 1];
  if (min === max) return [min - 1, max + 1];
  const pad = (max - min) * 0.12;
  return [min - pad, max + pad];
}

function buildPath(points) {
  return points.map((point, index) => `${index === 0 ? "M" : "L"}${point.x},${point.y}`).join(" ");
}

export function Sparkline({ values, stroke = "var(--series-1)", width = 120, height = 32 }) {
  const path = useMemo(() => {
    const usable = values.filter(Number.isFinite);
    if (usable.length < 2) return "";
    const [min, max] = extent(usable);
    const span = max - min || 1;
    return buildPath(
      usable.map((value, index) => ({
        x: (index / (usable.length - 1)) * width,
        y: height - ((value - min) / span) * height,
      })),
    );
  }, [values, width, height]);

  if (!path) return <div style={{ width, height }} aria-hidden="true" />;

  return (
    <svg width={width} height={height} className="chart__svg" aria-hidden="true" focusable="false">
      <path d={path} fill="none" stroke={stroke} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function TimeSeriesChart({
  title,
  series,
  color = "var(--series-1)",
  unit = "",
  digits = 1,
  height = 150,
  formatX = (point) => new Date(point.t * 1000).toLocaleTimeString(),
}) {
  const clipId = useId();
  const svgRef = useRef(null);
  const [hover, setHover] = useState(null);

  const width = 600;
  const pad = { top: 12, right: 16, bottom: 22, left: 46 };
  const plotWidth = width - pad.left - pad.right;
  const plotHeight = height - pad.top - pad.bottom;

  const model = useMemo(() => {
    const points = (series ?? []).filter((point) => Number.isFinite(point.v));
    if (points.length < 2) return null;
    const [min, max] = extent(points.map((point) => point.v));
    const span = max - min || 1;
    const scaled = points.map((point, index) => ({
      ...point,
      x: pad.left + (index / (points.length - 1)) * plotWidth,
      y: pad.top + plotHeight - ((point.v - min) / span) * plotHeight,
    }));
    return { points: scaled, min, max };
  }, [series, plotWidth, plotHeight, pad.left, pad.top]);

  function handleMove(mouseEvent) {
    if (!model || !svgRef.current) return;
    const box = svgRef.current.getBoundingClientRect();
    const ratio = (mouseEvent.clientX - box.left) / box.width;
    const x = ratio * width;
    let nearest = model.points[0];
    for (const point of model.points) {
      if (Math.abs(point.x - x) < Math.abs(nearest.x - x)) nearest = point;
    }
    setHover(nearest);
  }

  const latest = model?.points[model.points.length - 1];
  const ticks = model ? [model.max, (model.max + model.min) / 2, model.min] : [];

  return (
    <figure className="chart">
      <figcaption className="chart__head">
        <span className="chart__title">{title}</span>
        {latest && (
          <span className="chart__latest" style={{ color }}>
            {latest.v.toFixed(digits)}
            {unit}
          </span>
        )}
      </figcaption>

      {!model ? (
        <div className="subtle" style={{ height, display: "grid", placeItems: "center" }}>
          Waiting for telemetry…
        </div>
      ) : (
        <svg
          ref={svgRef}
          className="chart__svg"
          viewBox={`0 0 ${width} ${height}`}
          role="img"
          aria-label={`${title}: latest ${latest.v.toFixed(digits)}${unit}`}
          onMouseMove={handleMove}
          onMouseLeave={() => setHover(null)}
        >
          <defs>
            <clipPath id={clipId}>
              <rect x={pad.left} y={pad.top} width={plotWidth} height={plotHeight} />
            </clipPath>
            <linearGradient id={`${clipId}-fill`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={color} stopOpacity="0.22" />
              <stop offset="100%" stopColor={color} stopOpacity="0" />
            </linearGradient>
          </defs>

          {/* Recessive grid: present for reading values, never competing with the data. */}
          {ticks.map((value, index) => {
            const y = pad.top + (index / (ticks.length - 1)) * plotHeight;
            return (
              <g key={value}>
                <line
                  x1={pad.left}
                  x2={width - pad.right}
                  y1={y}
                  y2={y}
                  stroke="var(--gridline)"
                  strokeWidth="1"
                />
                <text
                  x={pad.left - 8}
                  y={y + 4}
                  textAnchor="end"
                  fontSize="10"
                  fill="var(--ink-muted)"
                  style={{ fontVariantNumeric: "tabular-nums" }}
                >
                  {value.toFixed(digits)}
                </text>
              </g>
            );
          })}

          <g clipPath={`url(#${clipId})`}>
            <path
              d={`${buildPath(model.points)} L${model.points[model.points.length - 1].x},${
                pad.top + plotHeight
              } L${model.points[0].x},${pad.top + plotHeight} Z`}
              fill={`url(#${clipId}-fill)`}
            />
            <path
              d={buildPath(model.points)}
              fill="none"
              stroke={color}
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </g>

          <line
            x1={pad.left}
            x2={width - pad.right}
            y1={pad.top + plotHeight}
            y2={pad.top + plotHeight}
            stroke="var(--axis)"
            strokeWidth="1"
          />

          {/* Latest point is direct-labelled above; the marker anchors it. */}
          <circle cx={latest.x} cy={latest.y} r="4" fill={color} stroke="var(--surface)" strokeWidth="2" />

          {hover && (
            <g>
              <line
                x1={hover.x}
                x2={hover.x}
                y1={pad.top}
                y2={pad.top + plotHeight}
                stroke="var(--border-strong)"
                strokeWidth="1"
                strokeDasharray="3 3"
              />
              <circle cx={hover.x} cy={hover.y} r="5" fill={color} stroke="var(--surface)" strokeWidth="2" />
              <g transform={`translate(${Math.min(Math.max(hover.x, pad.left + 60), width - pad.right - 60)}, ${pad.top + 4})`}>
                <rect x="-58" y="-2" width="116" height="34" rx="6" fill="var(--surface-raised)" stroke="var(--border-strong)" />
                <text x="0" y="12" textAnchor="middle" fontSize="11" fill="var(--ink)" style={{ fontVariantNumeric: "tabular-nums" }}>
                  {hover.v.toFixed(digits)}
                  {unit}
                </text>
                <text x="0" y="25" textAnchor="middle" fontSize="9" fill="var(--ink-muted)">
                  {formatX(hover)}
                </text>
              </g>
            </g>
          )}
        </svg>
      )}
    </figure>
  );
}

/** Tabular fallback so every chart's values are reachable without reading pixels. */
export function SeriesTable({ title, series, unit = "", digits = 1, rows = 8 }) {
  const recent = (series ?? []).slice(-rows).reverse();
  if (!recent.length) return null;
  return (
    <details>
      <summary className="subtle" style={{ cursor: "pointer" }}>
        {title} — table view
      </summary>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th scope="col">Time</th>
              <th scope="col">Value{unit && ` (${unit})`}</th>
            </tr>
          </thead>
          <tbody>
            {recent.map((point, index) => (
              <tr key={`${point.t}-${index}`}>
                <td>{new Date(point.t * 1000).toLocaleTimeString()}</td>
                <td className="num">{Number(point.v).toFixed(digits)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}
