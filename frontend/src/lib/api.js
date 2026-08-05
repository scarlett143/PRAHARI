/**
 * Empty (the default) means same-origin: the page's own host serves `/api` and `/ws`
 * through a reverse proxy. That is what lets one build run unchanged behind localhost, a
 * tunnel, or a real domain -- nothing about where the API lives is baked into the bundle,
 * and the browser never makes a cross-origin request, so there is no CORS to satisfy.
 *
 * Set VITE_API_URL only when the API genuinely lives on another origin.
 */
const API_URL = (import.meta.env.VITE_API_URL ?? "").trim().replace(/\/$/, "");
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
  if (raw) {
    try {
      body = JSON.parse(raw);
    } catch {
      body = raw;
    }
  }

  if (!response.ok) {
    throw new ApiError(response.status, body?.detail ?? body ?? `HTTP ${response.status}`);
  }
  return body;
}

const post = (path, payload) =>
  api(path, { method: "POST", body: JSON.stringify(payload ?? {}) });

/* -- auth ------------------------------------------------------------------ */

export const authApi = {
  register: (body) => post("/api/v2/auth/register", body),
  login: (body) => post("/api/v2/auth/login", body),
  me: () => api("/api/v2/auth/me"),
  challenge: () => post("/api/v2/auth/challenge"),
  publishKeys: (body) => post("/api/v2/keys/publish", body),
  keyBundle: (username) => api(`/api/v2/keys/${encodeURIComponent(username)}`),
};

/* -- workspaces and channels ----------------------------------------------- */

export const workspaceApi = {
  list: () => api("/api/v2/servers"),
  create: (name) => post("/api/v2/servers", { name }),
  addMember: (serverId, username) =>
    post(`/api/v2/servers/${serverId}/members`, { username }),
  createChannel: (body) => post("/api/v2/channels", body),
  channel: (channelId) => api(`/api/v2/channels/${channelId}`),
  rotateEpoch: (channelId) => post(`/api/v2/channels/${channelId}/rotate-key`),
  messages: (channelId, limit = 100) =>
    api(`/api/v2/channels/${channelId}/messages?limit=${limit}`),
  send: (body) => post("/api/v2/messages", body),
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
  list: ({ fleet, limit = 200, offset = 0 } = {}) => {
    const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    if (fleet) params.set("fleet", fleet);
    return api(`/api/v2/fleet/uavs?${params}`);
  },
  provision: (body) => post("/api/v2/fleet/uavs", body),
  provisionBulk: (body) => post("/api/v2/fleet/uavs/bulk", body),
  link: (callsign) => post(`/api/v2/fleet/uavs/${encodeURIComponent(callsign)}/link`),
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
