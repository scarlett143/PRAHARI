/** Formatting helpers. Telemetry values are always shown with fixed precision so
 *  columns do not jitter as digits change. */

export function num(value, digits = 1) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return "—";
  return Number(value).toFixed(digits);
}

export function integer(value) {
  if (value === null || value === undefined) return "—";
  return Number(value).toLocaleString();
}

export function clockTime(value) {
  if (!value) return "—";
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function dateTime(value) {
  if (!value) return "—";
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString();
}

export function relativeTime(value) {
  if (!value) return "never";
  const then = new Date(value).getTime();
  if (Number.isNaN(then)) return "never";
  const seconds = Math.round((Date.now() - then) / 1000);
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

/** Shorten a hex digest for display without losing its recognisable ends. */
export function shortHash(value, head = 8, tail = 6) {
  if (!value) return "—";
  if (value.length <= head + tail + 1) return value;
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

export function coordinate(value, digits = 5) {
  if (value === null || value === undefined) return "—";
  return Number(value).toFixed(digits);
}

export function bytes(count) {
  if (!count && count !== 0) return "—";
  if (count < 1024) return `${count} B`;
  if (count < 1024 * 1024) return `${(count / 1024).toFixed(1)} KiB`;
  return `${(count / 1024 / 1024).toFixed(1)} MiB`;
}
