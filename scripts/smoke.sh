#!/usr/bin/env bash
set -euo pipefail

ATLAS_HOST="${ATLAS_DEV_HOST:-127.0.0.1}"
ATLAS_PORT="${ATLAS_DEV_PORT:-15353}"

query_short() {
  dig @"$ATLAS_HOST" -p "$ATLAS_PORT" "$1" "${2:-A}" +time=2 +tries=1 +nocookie +short
}

expect_equal() {
  local label="$1" actual="$2" expected="$3"
  if [[ "$actual" != "$expected" ]]; then
    echo "[smoke] $label failed: expected '$expected', got '$actual'" >&2
    exit 1
  fi
  echo "[smoke] $label ok: $actual"
}

expect_equal "static hosts" "$(query_short static.test A)" "192.0.2.53"
expect_equal "forwarded UDP" "$(query_short example.test A)" "192.0.2.10"
expect_equal "upstream UDP-to-TCP fallback" "$(query_short truncated.test A)" "192.0.2.20"

tcp_answer="$(dig @"$ATLAS_HOST" -p "$ATLAS_PORT" example.test A +tcp +time=2 +tries=1 +short)"
expect_equal "client TCP" "$tcp_answer" "192.0.2.10"

plain_large="$(dig @"$ATLAS_HOST" -p "$ATLAS_PORT" large.test A +noedns +notcp +ignore +time=2 +tries=1)"
if ! awk '/flags:/ {for (i = 1; i <= NF; i++) {gsub(/;/, "", $i); if ($i == "tc") found = 1}} END {exit !found}' <<<"$plain_large"; then
  echo "[smoke] plain UDP response was not truncated to the 512-byte client capacity" >&2
  exit 1
fi
echo "[smoke] plain UDP client-aware truncation ok"

edns_answers="$(dig @"$ATLAS_HOST" -p "$ATLAS_PORT" large.test A +bufsize=1232 +notcp +time=2 +tries=1 +noall +answer | wc -l | tr -d '[:space:]')"
expect_equal "EDNS 1232 complete response" "$edns_answers" "40"

first="$(query_short counter.test A)"
second="$(query_short counter.test A)"
expect_equal "cache hit stability" "$second" "$first"

status="$(dig @"$ATLAS_HOST" -p "$ATLAS_PORT" blocked.test A +time=2 +tries=1 | awk -F'[, ]+' '/status:/ {print $6; exit}')"
expect_equal "rcode action" "$status" "REFUSED"

if ! curl -fsS http://127.0.0.1:16060/debug/pprof/ >/dev/null; then
  echo "[smoke] pprof endpoint failed" >&2
  exit 1
fi
echo "[smoke] pprof lifecycle endpoint ok"

runtime_stats="$(curl -fsS http://127.0.0.1:16060/debug/atlas)"
if [[ "$runtime_stats" != *'"dns"'* || "$runtime_stats" != *'"cache"'* ]]; then
  echo "[smoke] runtime stats endpoint returned unexpected data: $runtime_stats" >&2
  exit 1
fi
echo "[smoke] bounded-resource runtime metrics ok"

echo "[smoke] all Atlas end-to-end checks passed"
