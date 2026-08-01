#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO_BIN="${ATLAS_GO:-$ROOT/.cache/go-runtime/bin/go}"
CONFIG_PATH="${ATLAS_CONFIG:-$ROOT/config.dev.yaml}"
UPSTREAM_ADDR="${ATLAS_DEV_UPSTREAM_ADDR:-127.0.0.1:15354}"
ATLAS_ADDR="${ATLAS_DEV_ADDR:-127.0.0.1:15353}"
PID_DIR="${ATLAS_DEV_PID_DIR:-$ROOT/.dev-data}"
ROOT_HASH="$(printf '%s' "$ROOT" | cksum | awk '{print $1}')"
PID_FILE="${ATLAS_DEV_PID_FILE:-$PID_DIR/atlas-dev-$ROOT_HASH.pids}"

umask 077
mkdir -p "$ROOT/.dev-data" "$PID_DIR"
if [[ -L "$PID_FILE" ]]; then
  echo "refusing symbolic-link PID file: $PID_FILE" >&2
  exit 1
fi

proc_start_time() {
  local pid="$1"
  awk '{print $22}' "/proc/$pid/stat" 2>/dev/null || true
}

record_pid() {
  local pid="$1" label="$2" started
  started="$(proc_start_time "$pid")"
  if [[ -z "$started" ]]; then
    kill "$pid" 2>/dev/null || true
    echo "failed to identify $label process start time for pid=$pid" >&2
    return 1
  fi
  printf '%s %s %s\n' "$pid" "$started" "$label" >>"$PID_FILE"
}

kill_tree() {
  local pid="$1" child
  while read -r child; do
    [[ -n "$child" ]] && kill_tree "$child"
  done < <(pgrep -P "$pid" 2>/dev/null || true)
  kill "$pid" 2>/dev/null || true
}

kill_recorded() {
  local pid="$1" expected="$2" label="$3" current
  kill -0 "$pid" 2>/dev/null || return 0
  current="$(proc_start_time "$pid")"
  if [[ -n "$expected" && -n "$current" && "$expected" != "$current" ]]; then
    echo "[atlas] skip stale $label pid=$pid; process id was reused"
    return 0
  fi
  echo "[atlas] stopping $label pid=$pid"
  kill_tree "$pid"
}

cleanup_previous() {
  [[ -f "$PID_FILE" ]] || return 0
  echo "[atlas] cleaning previous dev processes from $PID_FILE"
  while read -r pid started label; do
    kill_recorded "$pid" "$started" "${label:-process}"
  done <"$PID_FILE"
  rm -f "$PID_FILE"
}

cleanup() {
  trap - INT TERM EXIT
  if [[ -f "$PID_FILE" ]]; then
    while read -r pid started label; do
      kill_recorded "$pid" "$started" "${label:-process}"
    done <"$PID_FILE"
  fi
  wait 2>/dev/null || true
  rm -f "$PID_FILE"
}

wait_dns() {
  local host="$1" port="$2" name="$3"
  for _ in $(seq 1 80); do
    if dig @"$host" -p "$port" "$name" A +time=1 +tries=1 +short >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  echo "DNS endpoint $host:$port did not become ready" >&2
  return 1
}

cleanup_previous
: >"$PID_FILE"
trap cleanup INT TERM EXIT

echo "[atlas] starting deterministic upstream on $UPSTREAM_ADDR"
(
  cd "$ROOT"
  exec "$GO_BIN" run ./cmd/atlas-test-upstream --bind="$UPSTREAM_ADDR"
) &
record_pid "$!" upstream

wait_dns "${UPSTREAM_ADDR%:*}" "${UPSTREAM_ADDR##*:}" example.test

echo "[atlas] starting Atlas on $ATLAS_ADDR with config=$CONFIG_PATH"
(
  cd "$ROOT"
  exec "$GO_BIN" run ./cmd/atlas --config="$CONFIG_PATH"
) &
record_pid "$!" atlas

wait_dns "${ATLAS_ADDR%:*}" "${ATLAS_ADDR##*:}" static.test
echo "[atlas] ready: DNS=$ATLAS_ADDR pprof=http://127.0.0.1:16060/debug/pprof/"
echo "[atlas] run 'make smoke' in another terminal for end-to-end acceptance"

wait -n
