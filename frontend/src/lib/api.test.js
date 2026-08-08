/**
 * How the API client reports failures.
 *
 * The case that matters is a response the application never produced. nginx, Cloudflare
 * and any proxy between them answer with an HTML page, and passing that through as an
 * error message dumped a whole document into the UI -- which is what a failed send looked
 * like to the person doing it.
 */
import test from "node:test";
import assert from "node:assert/strict";

const GATEWAY_HTML = `<html>
<head><title>502 Bad Gateway</title></head>
<body><center><h1>502 Bad Gateway</h1></center><hr><center>nginx</center></body>
</html>`;

/** Install a fetch that returns one canned response, and load a fresh module copy. */
async function withResponse({ status, body, contentType = "text/html" }) {
  globalThis.fetch = async () => ({
    ok: status >= 200 && status < 300,
    status,
    headers: { get: () => contentType },
    text: async () => body,
  });
  globalThis.localStorage = {
    getItem: () => "",
    setItem: () => {},
    removeItem: () => {},
  };
  globalThis.window = { location: { origin: "https://example.test" }, dispatchEvent: () => {} };
  // Cache-busted so each test gets module state untouched by the last.
  return import(`./api.js?case=${status}-${Math.random()}`);
}

test("an HTML gateway error never reaches the user as markup", async () => {
  const { api, ApiError } = await withResponse({ status: 502, body: GATEWAY_HTML });

  await assert.rejects(
    () => api("/api/v2/messages", { method: "POST" }),
    (error) => {
      assert.ok(error instanceof ApiError);
      assert.equal(error.status, 502);
      assert.ok(!error.message.includes("<html"), "the page markup leaked into the message");
      assert.ok(!error.message.includes("nginx"), "the failing component leaked into the message");
      assert.match(error.message, /not responding/i);
      // And it says plainly that nothing was sent, which is the part the operator acts on.
      assert.match(error.message, /not sent/i);
      return true;
    },
  );
});

test("a structured API error still passes its detail through", async () => {
  // The rekey path depends on this: callers branch on `code`, not on message text.
  const { api, ApiError } = await withResponse({
    status: 409,
    contentType: "application/json",
    body: JSON.stringify({
      detail: { code: "rekey_required", reason: "message_limit", current_epoch: 4 },
    }),
  });

  await assert.rejects(
    () => api("/api/v2/messages", { method: "POST" }),
    (error) => {
      assert.ok(error instanceof ApiError);
      assert.equal(error.code, "rekey_required");
      assert.equal(error.detail.current_epoch, 4);
      return true;
    },
  );
});

test("a plain string detail is preserved", async () => {
  const { api } = await withResponse({
    status: 400,
    contentType: "application/json",
    body: JSON.stringify({ detail: "envelope too short" }),
  });

  await assert.rejects(() => api("/api/v2/messages", { method: "POST" }), /envelope too short/);
});

test("a 200 that is not JSON is an error, not a value handed to the caller", async () => {
  // Otherwise the markup travels one layer further and fails somewhere less obvious.
  const { api } = await withResponse({ status: 200, body: "<html>login page</html>" });

  await assert.rejects(() => api("/api/v2/channels"), /did not reach the application/i);
});

test("each gateway status gets its own actionable wording", async () => {
  for (const [status, pattern] of [
    [413, /too large/i],
    [429, /too many/i],
    [500, /failed to handle/i],
  ]) {
    const { api } = await withResponse({ status, body: GATEWAY_HTML });
    await assert.rejects(() => api("/api/v2/messages", { method: "POST" }), pattern);
  }
});
