const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

export function getApiUrl() {
  return API_URL;
}

export function getToken() {
  return localStorage.getItem("prahari_token") || "";
}

export function setToken(token) {
  if (token) localStorage.setItem("prahari_token", token);
  else localStorage.removeItem("prahari_token");
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
  try {
    body = raw ? JSON.parse(raw) : null;
  } catch {
    body = raw;
  }
  if (!response.ok) {
    const detail = body?.detail ?? body ?? `HTTP ${response.status}`;
    const error = new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
    error.status = response.status;
    error.detail = detail;
    throw error;
  }
  return body;
}
