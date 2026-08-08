#!/usr/bin/env bash
#
# Watch the PRAHARI backend and say something when it stops answering.
#
# Until now an outage would have been reported by a user. systemd already restarts the
# unit on failure, which covers a crash -- but not the case that actually matters here: a
# process that is running and *not answering*, because it is wedged on a database lock, out
# of memory, or stuck behind something slow. `Restart=on-failure` sees a healthy process
# in all three.
#
# Deliberately a cron script rather than a daemon. This box has two cores shared with the
# operator's other services, and a resident monitor is a permanent cost to watch something
# that fails rarely. A curl every two minutes is free by comparison.
#
# Exit codes: 0 healthy, 1 unhealthy (alerted), 2 misconfigured.
set -uo pipefail

URL="${PRAHARI_HEALTH_URL:-http://127.0.0.1:8801/health}"
UNIT="${PRAHARI_UNIT:-prahari}"
STATE_DIR="${PRAHARI_STATE_DIR:-/var/lib/prahari-healthcheck}"
LOG="${PRAHARI_HEALTH_LOG:-/var/log/prahari-health.log}"
#: Optional. Anything that accepts a JSON POST -- Slack, Discord, ntfy, a webhook relay.
WEBHOOK="${PRAHARI_ALERT_WEBHOOK:-}"
#: How many consecutive failures before alerting. Two rather than one: a restart takes a
#: few seconds, and paging on every deploy is how alerts get ignored.
THRESHOLD="${PRAHARI_FAIL_THRESHOLD:-2}"
TIMEOUT="${PRAHARI_HEALTH_TIMEOUT:-8}"

mkdir -p "$STATE_DIR" || exit 2
FAILFILE="$STATE_DIR/consecutive-failures"
[ -f "$FAILFILE" ] || echo 0 > "$FAILFILE"

log() {
  # Explicit format rather than `date -Is`: that flag is GNU-only and silently prints
  # nothing on BSD, which is how a log ends up with unattributable lines.
  printf '%s %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$1" >> "$LOG"
}

notify() {
  local text="$1"
  # Logged whether or not a webhook is configured, so the record survives an alerting
  # channel that is itself down.
  log "ALERT $text"
  [ -z "$WEBHOOK" ] && return 0
  curl -sS -m 10 -X POST -H 'Content-Type: application/json' \
    --data "$(printf '{"text":%s}' "$(printf '%s' "$text" | sed 's/\\/\\\\/g; s/"/\\"/g; s/^/"/; s/$/"/')")" \
    "$WEBHOOK" >/dev/null 2>&1 || log "WARN webhook delivery failed"
}

# curl still writes %{http_code} ("000") when the connection fails *and* exits non-zero,
# so a `|| echo 000` fallback concatenates onto it and yields "000000". Default only when
# the capture is genuinely empty.
code="$(curl -sS -o /dev/null -w '%{http_code}' -m "$TIMEOUT" "$URL" 2>/dev/null)"
code="${code:-000}"
failures="$(cat "$FAILFILE" 2>/dev/null || echo 0)"

if [ "$code" = "200" ]; then
  # Only announce recovery if it was actually down, so a healthy box stays silent.
  if [ "$failures" -ge "$THRESHOLD" ]; then
    notify "PRAHARI backend recovered (HTTP 200 from $URL)"
  fi
  echo 0 > "$FAILFILE"
  exit 0
fi

failures=$((failures + 1))
echo "$failures" > "$FAILFILE"
log "unhealthy: HTTP $code from $URL (consecutive=$failures)"

if [ "$failures" -eq "$THRESHOLD" ]; then
  active="$(systemctl is-active "$UNIT" 2>/dev/null || echo unknown)"
  # The distinction worth alerting on: a unit that is *active* but not answering is the
  # case systemd will never fix by itself.
  notify "PRAHARI backend not answering: HTTP $code from $URL. systemd unit is '$active'. $(
    [ "$active" = "active" ] && echo 'Process is up but unresponsive -- restart will not be automatic.'
  )"
fi

exit 1
