/**
 * Renders URLs inside decrypted message text as safe, clickable links.
 *
 * Two deliberate limits:
 *
 * 1. **No remote preview fetch.** The obvious "rich preview" feature would take a URL out
 *    of a decrypted message and hand it to an unfurling service or the origin server.
 *    That leaks message content to a third party and quietly voids the end-to-end
 *    property the rest of this system exists to provide. The card below is built purely
 *    from parsing the URL string locally -- no request leaves the browser.
 *
 * 2. **Scheme allow-list.** Only http and https render as anchors. `javascript:`,
 *    `data:` and friends stay inert text, so a peer cannot turn a message into script
 *    execution or a credential-stealing data document.
 */

// Trailing punctuation is excluded so "see https://example.com." does not capture the
// sentence-ending period as part of the link.
const URL_PATTERN = /\b(?:https?:\/\/|www\.)[^\s<>"']+[^\s<>"'.,;:!?)\]}]/gi;

const SAFE_PROTOCOLS = new Set(["http:", "https:"]);

function parse(raw) {
  const candidate = raw.startsWith("www.") ? `https://${raw}` : raw;
  try {
    const url = new URL(candidate);
    if (!SAFE_PROTOCOLS.has(url.protocol)) return null;
    return url;
  } catch {
    return null;
  }
}

export function extractLinks(text) {
  if (!text) return [];
  const seen = new Set();
  const found = [];
  for (const match of String(text).matchAll(URL_PATTERN)) {
    const url = parse(match[0]);
    if (!url || seen.has(url.href)) continue;
    seen.add(url.href);
    found.push(url);
  }
  return found;
}

/** A preview card assembled from the URL alone. Nothing is fetched. */
export function LinkCard({ url }) {
  const path = `${url.pathname}${url.search}`.replace(/\/$/, "");
  return (
    <a
      className="linkcard"
      href={url.href}
      target="_blank"
      rel="noopener noreferrer nofollow"
    >
      <span className="linkcard__host">
        <span aria-hidden="true">🔗</span>
        {url.hostname.replace(/^www\./, "")}
      </span>
      {path && path !== "/" && <span className="linkcard__path">{path}</span>}
      <span className="linkcard__note">opens in a new tab · not fetched for preview</span>
    </a>
  );
}

export default function Linkify({ text }) {
  const value = String(text ?? "");
  if (!value) return null;

  const parts = [];
  let cursor = 0;

  for (const match of value.matchAll(URL_PATTERN)) {
    const start = match.index ?? 0;
    const raw = match[0];
    const url = parse(raw);

    if (start > cursor) parts.push(value.slice(cursor, start));
    if (url) {
      parts.push(
        <a
          key={`${start}-${url.href}`}
          href={url.href}
          target="_blank"
          rel="noopener noreferrer nofollow"
          className="msglink"
        >
          {raw}
        </a>,
      );
    } else {
      // Unsafe scheme: shown, never made clickable.
      parts.push(raw);
    }
    cursor = start + raw.length;
  }

  if (cursor < value.length) parts.push(value.slice(cursor));
  return <>{parts}</>;
}
