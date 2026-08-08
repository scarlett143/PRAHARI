#!/usr/bin/env bash
#
# Build the console locally and ship the finished bytes.
#
# The governing constraint is that the target is a *shared* 2-core box which also serves
# the operator's panel, billing and status sites. So nothing expensive happens there:
# the bundle is built here, compressed here, and the server only ever receives files.
# An `npm run build` over SSH is what took every customer site down on 2026-08-05.
#
# Compressing at deploy time rather than per request is the same argument in miniature.
# The bundle is byte-identical for every visitor, so gzipping it on each request spends
# CPU re-deriving a known answer. nginx's `gzip_static on` picks up the .gz files written
# here; if a deploy ever skips this step the site keeps working and silently falls back to
# compressing on every request, which is why it lives in a script instead of a runbook.
#
# Usage:  deploy/publish-frontend.sh [--dry-run]
set -euo pipefail

HOST="${PRAHARI_HOST:-root@203.57.85.138}"
KEY="${PRAHARI_SSH_KEY:-$HOME/.ssh/prahari_deploy}"
WEBROOT="${PRAHARI_WEBROOT:-/var/www/prahari}"
NODE_BIN="${PRAHARI_NODE_BIN:-/opt/homebrew/opt/node@20/bin}"

cd "$(dirname "$0")/.."
DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

# Node 20+ or Vite refuses, and the crypto tests fail on a missing crypto.getRandomValues.
if [[ -d "$NODE_BIN" ]]; then
  export PATH="$NODE_BIN:$PATH"
fi
node_major="$(node -p 'process.versions.node.split(".")[0]')"
if (( node_major < 20 )); then
  echo "error: Node ${node_major} found; this build needs 20+. Set PRAHARI_NODE_BIN." >&2
  exit 1
fi

echo "==> Testing"
( cd frontend && npm test )

echo "==> Building"
( cd frontend && npm run build )

# -k keeps the original: nginx needs both, serving the .gz only to clients that accept it.
# -9 because this runs once per deploy on a developer machine, where the extra CPU is free
# and every byte saved is paid back on every download for the life of the release.
echo "==> Compressing"
find frontend/dist -type f \
  \( -name '*.js' -o -name '*.css' -o -name '*.html' -o -name '*.svg' -o -name '*.json' \) \
  -size +1k -print0 | xargs -0 -r gzip -9 -k -f

before=$(find frontend/dist -type f ! -name '*.gz' -exec cat {} + | wc -c)
after=$(find frontend/dist -type f -name '*.gz' -exec cat {} + | wc -c)
echo "    compressible payload ${before}B -> ${after}B"

if (( DRY_RUN )); then
  echo "==> Dry run; nothing uploaded."
  exit 0
fi

echo "==> Uploading to ${HOST}:${WEBROOT}"
# --delete so a stale hashed asset from a previous release cannot linger and be served.
rsync -az --delete -e "ssh -i ${KEY}" frontend/dist/ "${HOST}:${WEBROOT}/"

# Readable by the nginx worker, writable only by root.
ssh -i "$KEY" "$HOST" "chmod -R a+rX '${WEBROOT}'"

# nginx is only reloaded, never restarted: a restart drops the other vhosts on this box.
# `nginx -t` first so a bad config fails here instead of taking them all down.
echo "==> Verifying nginx"
ssh -i "$KEY" "$HOST" "nginx -t && systemctl reload nginx"

# Cloudflare answers non-browser user agents with error 1010, so a bare curl looks broken
# when the site is fine.
echo "==> Checking the deployed bundle"
ssh -i "$KEY" "$HOST" \
  "curl -sS -o /dev/null -w 'index.html %{http_code}\n' -H 'Accept-Encoding: gzip' http://127.0.0.1/ || true"

echo "==> Done."
