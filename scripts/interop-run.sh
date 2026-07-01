#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SGWC_CONFIG="${SGWC_CONFIG:-$ROOT_DIR/configs/interop/sgw-c-lab.yaml}"
SGWU_CONFIG="${SGWU_CONFIG:-$ROOT_DIR/configs/interop/sgw-u-lab.yaml}"
LOG_DIR="${LOG_DIR:-$ROOT_DIR/logs/interop}"

mkdir -p "$LOG_DIR"

if [[ ! -x "$ROOT_DIR/bin/sgw-c" || ! -x "$ROOT_DIR/bin/sgw-u" ]]; then
  make -C "$ROOT_DIR" build
fi

"$ROOT_DIR/bin/sgw-c" -c "$SGWC_CONFIG" -validate
"$ROOT_DIR/bin/sgw-u" -c "$SGWU_CONFIG" -validate

cleanup() {
  trap - INT TERM EXIT
  if [[ -n "${SGWC_PID:-}" ]]; then
    kill "$SGWC_PID" 2>/dev/null || true
  fi
  if [[ -n "${SGWU_PID:-}" ]]; then
    kill "$SGWU_PID" 2>/dev/null || true
  fi
  wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

"$ROOT_DIR/bin/sgw-u" -d -c "$SGWU_CONFIG" >"$LOG_DIR/sgw-u.log" 2>&1 &
SGWU_PID=$!

"$ROOT_DIR/bin/sgw-c" -d -c "$SGWC_CONFIG" >"$LOG_DIR/sgw-c.log" 2>&1 &
SGWC_PID=$!

printf 'SGW-U pid=%s log=%s\n' "$SGWU_PID" "$LOG_DIR/sgw-u.log"
printf 'SGW-C pid=%s log=%s\n' "$SGWC_PID" "$LOG_DIR/sgw-c.log"
printf 'Press Ctrl-C to stop both processes.\n'

wait "$SGWU_PID" "$SGWC_PID"
