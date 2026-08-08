/**
 * Empty (the default) means same-origin: the page's own host serves `/api` and `/ws`
 * through a reverse proxy. That is what lets one build run unchanged behind localhost, a
 * tunnel, or a real domain -- nothing about where the API lives is baked into the bundle,
 * and the browser never makes a cross-origin request, so there is no CORS to satisfy.
 *
 * Set VITE_API_URL only when the API genuinely lives on another origin.
 */
// Optional chaining because `import.meta.env` is injected by Vite and absent under plain
// Node, where this module is unit-tested.
const API_URL = (import.meta.env?.VITE_API_URL ?? "").trim().replace(/\/$/, "");
const TOKEN_KEY = "prahari_token";

/** Absolute base for building WebSocket URLs, which cannot be relative. */
export function getApiUrl() {
  return API_URL || window.location.origin;
}

export function getToken() {
  return localStorage.getItem(TOKEN_KEY) || "";
}

export function setToken(token) {
  if (token) localStorage.setItem(TOKEN_KEY, token);
  else localStorage.removeItem(TOKEN_KEY);
}

/**
 * Errors carry `status` and the parsed `detail` so callers can branch on the
 * structured codes the API returns (`rekey_required`, `session_offer_exists`,
 * `peer_required`) instead of matching on message text.
 */
export class ApiError extends Error {
  constructor(status, detail) {
    const message =
      typeof detail === "string"
        ? detail
        : detail?.message || JSON.stringify(detail);
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
    this.code = typeof detail === "object" && detail !== null ? detail.code : undefined;
  }
}

export async function api(path, options = {}) {
  const token = getToken();
  const response = await fetch(`${API_URL}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(options.headers || {}),
    },
  });

  const raw = await response.text();
  let body = null;
  //: True when the response was not JSON. Anything reaching this app through its own
  //: origin should be JSON, so a non-JSON body means the request never got as far as the
  //: application: nginx, Cloudflare, or a proxy in between answered instead.
  let unparseable = false;
  if (raw) {
    try {
      body = JSON.parse(raw);
    } catch {
      body = raw;
      unparseable = true;
    }
  }

  if (!response.ok) {
    // A 401 while holding a token means the session is gone -- expired, or signed out
    // from another device. Without this the app sits there throwing errors at every
    // panel; the session simply ends, which is what actually happened.
    if (response.status === 401 && token) {
      setToken("");
      window.dispatchEvent(new CustomEvent("prahari:session-ended"));
    }
    // Never surface the body of a non-JSON response. A gateway error page is an entire
    // HTML document, and passing it through as `message` dumped the page's markup into
    // the UI -- which is what "sending failed" looked like to anyone who hit a restart or
    // a Cloudflare timeout mid-send.
    if (unparseable) {
      throw new ApiError(response.status, gatewayMessage(response.status));
    }
    throw new ApiError(response.status, body?.detail ?? `HTTP ${response.status}`);
  }
  //: A successful response that is not JSON is equally wrong, and returning the markup
  //: would push the same problem into whichever caller tried to read a field off it.
  if (unparseable) {
    throw new ApiError(response.status, gatewayMessage(response.status));
  }
  return body;
}

/**
 * What to say when something between the browser and the app answered instead of the app.
 *
 * Phrased around what the operator should do rather than which component failed: they
 * cannot tell nginx from Cloudflare from uvicorn, and at this layer neither can we.
 */
function gatewayMessage(status) {
  if (status === 502 || status === 503 || status === 504) {
    return "The server is not responding right now. Your message was not sent — try again in a moment.";
  }
  if (status === 413) {
    return "That message is too large to send.";
  }
  if (status === 429) {
    return "Too many requests. Wait a moment and try again.";
  }
  if (status >= 500) {
    return `The server failed to handle that request (HTTP ${status}). Your message was not sent.`;
  }
  return `The request did not reach the application (HTTP ${status}).`;
}

const post = (path, payload) =>
  api(path, { method: "POST", body: JSON.stringify(payload ?? {}) });

/* -- auth ------------------------------------------------------------------ */

export const authApi = {
  register: (body) => post("/api/v2/auth/register", body),
  login: (body) => post("/api/v2/auth/login", body),
  me: () => api("/api/v2/auth/me"),
  challenge: () => post("/api/v2/auth/challenge"),
  // Password recovery. Unauthenticated on purpose: the caller has lost the password, and
  // proves the account with a signature from its identity key instead.
  recoveryChallenge: (username) => post("/api/v2/auth/recovery/challenge", { username }),
  recoveryReset: (body) => post("/api/v2/auth/recovery/reset", body),
  publishKeys: (body) => post("/api/v2/keys/publish", body),
  keyBundle: (username) => api(`/api/v2/keys/${encodeURIComponent(username)}`),
  // The peer's full publish history. Verified in the browser, never trusted as returned:
  // a log the relay grades itself against is not evidence.
  keyHistory: (username) => api(`/api/v2/keys/${encodeURIComponent(username)}/history`),
};

/* -- sessions ---------------------------------------------------------------
   Where this account is signed in, and how to take any of it away. */

export const twoFactorApi = {
  setup: () => post("/api/v2/auth/2fa/setup"),
  enable: (code) => post("/api/v2/auth/2fa/enable", { code }),
  disable: (password, code) => post("/api/v2/auth/2fa/disable", { password, code }),
};

export const passkeyApi = {
  list: () => api("/api/v2/auth/passkeys"),
  registerChallenge: () => post("/api/v2/auth/passkeys/register/challenge"),
  register: (body) => post("/api/v2/auth/passkeys/register", body),
  remove: (id) => api(`/api/v2/auth/passkeys/${id}`, { method: "DELETE" }),
  loginChallenge: (username) => post("/api/v2/auth/passkeys/login/challenge", { username }),
  login: (body) => post("/api/v2/auth/passkeys/login", body),
};

export const sessionApi = {
  list: () => api("/api/v2/auth/sessions"),
  revoke: (sessionId) => api(`/api/v2/auth/sessions/${sessionId}`, { method: "DELETE" }),
  revokeOthers: () => post("/api/v2/auth/sessions/revoke-others"),
};

/* -- workspaces and channels ----------------------------------------------- */

export const workspaceApi = {
  list: () => api("/api/v2/servers"),
  create: (name) => post("/api/v2/servers", { name }),
  addMember: (serverId, username) =>
    post(`/api/v2/servers/${serverId}/members`, { username }),
  rename: (serverId, name) => api(`/api/v2/servers/${serverId}`, {
    method: "PATCH",
    body: JSON.stringify({ name }),
  }),
  remove: (serverId) => api(`/api/v2/servers/${serverId}`, { method: "DELETE" }),
  removeMember: (serverId, userId) =>
    api(`/api/v2/servers/${serverId}/members/${userId}`, { method: "DELETE" }),
  leave: (serverId) => post(`/api/v2/servers/${serverId}/leave`),
  // Deleted workspaces still inside their restore window, owner-only.
  deleted: () => api("/api/v2/servers/deleted"),
  restore: (serverId) => post(`/api/v2/servers/${serverId}/restore`),
  createChannel: (body) => post("/api/v2/channels", body),
  // Group channel: the creator plus everyone named. Three or more members switches the
  // channel from a pairwise ratchet to a shared epoch key.
  createGroup: (serverId, name, memberUsernames) =>
    post("/api/v2/channels", {
      server_id: serverId,
      name,
      member_usernames: memberUsernames,
    }),
  addChannelMember: (channelId, username) =>
    post(`/api/v2/channels/${channelId}/members`, { username }),
  channel: (channelId) => api(`/api/v2/channels/${channelId}`),
  rotateEpoch: (channelId) => post(`/api/v2/channels/${channelId}/rotate-key`),
  messages: (channelId, limit = 100) =>
    api(`/api/v2/channels/${channelId}/messages?limit=${limit}`),
  send: (body) => post("/api/v2/messages", body),
  // Asks the relay to drop the stored ciphertext. The sealed `del` event published on the
  // channel is what peers actually honour; this only stops the server serving the message
  // to a device that has not synced yet.
  deleteMessage: (messageId) => api(`/api/v2/messages/${messageId}`, { method: "DELETE" }),
  searchUsers: (query) => api(`/api/v2/users?query=${encodeURIComponent(query)}`),
  presence: () => api("/api/v2/users/presence"),
  acknowledge: (channelId, messageIds, state) =>
    post("/api/v2/messages/receipts", {
      channel_id: channelId,
      message_ids: messageIds,
      state,
    }),
};

/* -- invite links ----------------------------------------------------------- */

const del = (path) => api(path, { method: "DELETE" });

export const inviteApi = {
  create: (body) => post("/api/v2/invites", body),
  list: (serverId) => api(`/api/v2/servers/${serverId}/invites`),
  revoke: (inviteId) => del(`/api/v2/invites/${inviteId}`),
  // Unauthenticated on purpose: the join screen has to render before sign-in.
  preview: (code) => api(`/api/v2/invites/${encodeURIComponent(code)}/preview`),
  accept: (code) => post(`/api/v2/invites/${encodeURIComponent(code)}/accept`),
};

/* -- direct peer links ------------------------------------------------------ */

export const linkApi = {
  request: (username, note) => post("/api/v2/links", { username, note: note || null }),
  list: () => api("/api/v2/links"),
  accept: (linkId) => post(`/api/v2/links/${linkId}/accept`),
  decline: (linkId) => post(`/api/v2/links/${linkId}/decline`),
  cancel: (linkId) => del(`/api/v2/links/${linkId}`),
};

/* -- fleet ------------------------------------------------------------------ */

export const fleetApi = {
  list: ({ fleet, query, limit = 200, offset = 0 } = {}) => {
    const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    if (fleet) params.set("fleet", fleet);
    // Searched server-side so matches on later pages are found, not just the page in hand.
    if (query) params.set("query", query);
    return api(`/api/v2/fleet/uavs?${params}`);
  },
  provision: (body) => post("/api/v2/fleet/uavs", body),
  provisionBulk: (body) => post("/api/v2/fleet/uavs/bulk", body),
  link: (callsign) => post(`/api/v2/fleet/uavs/${encodeURIComponent(callsign)}/link`),
  // Containment. Quarantine is reversible; revoke is not, and destroys the enrolment path.
  quarantine: (callsign, reason) =>
    post(`/api/v2/fleet/uavs/${encodeURIComponent(callsign)}/quarantine`, { reason }),
  revoke: (callsign, reason) =>
    post(`/api/v2/fleet/uavs/${encodeURIComponent(callsign)}/revoke`, { reason }),
  restore: (callsign) => post(`/api/v2/fleet/uavs/${encodeURIComponent(callsign)}/restore`),
  // Pin the firmware digest this endpoint should report. An empty value clears the pin.
  pinMeasurement: (callsign, measurementB64) =>
    post(`/api/v2/fleet/uavs/${encodeURIComponent(callsign)}/attestation`, {
      measurement_b64: measurementB64,
    }),
};

/* -- vpn control plane ------------------------------------------------------ */

// Control plane only: this issues configuration and carries sealed keys. No tunnel is
// terminated by the API server. See backend/app/api/vpn.py.
export const vpnApi = {
  gateways: () => api("/api/v2/vpn/gateways"),
  createGateway: (body) => post("/api/v2/vpn/gateways", body),
  peers: (gatewayId, includeRevoked = false) =>
    api(`/api/v2/vpn/gateways/${gatewayId}/peers?include_revoked=${includeRevoked}`),
  enrolPeer: (gatewayId, body) => post(`/api/v2/vpn/gateways/${gatewayId}/peers`, body),
  revokePeer: (peerId, reason) => post(`/api/v2/vpn/peers/${peerId}/revoke`, { reason }),
  config: (peerId) => api(`/api/v2/vpn/peers/${peerId}/config`),
};

/* -- proofs, quantum, admin ------------------------------------------------- */

export const proofApi = {
  batches: () => api("/api/v2/anchors"),
  build: () => post("/api/v2/anchors/batch"),
  proof: (batchId, messageId) => api(`/api/v2/anchors/${batchId}/proof/${messageId}`),
};

export const quantumApi = {
  run: (body) => post("/api/v2/quantum/experiment", body),
  history: () => api("/api/v2/quantum/experiments"),
};

export const opsApi = {
  health: () => api("/health"),
};
