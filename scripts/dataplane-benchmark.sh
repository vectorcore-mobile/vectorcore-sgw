#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCHTIME="${BENCHTIME:-3s}"
COUNT="${COUNT:-3}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/docs/performance}"
OUT_FILE="${OUT_FILE:-$OUT_DIR/dataplane-benchmark.txt}"

mkdir -p "$OUT_DIR"

cat >"$OUT_FILE" <<EOF
VectorCore SGW dataplane benchmark
date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
benchtime=$BENCHTIME
count=$COUNT

EOF

GOCACHE="${GOCACHE:-/tmp/vectorcore-sgw-gocache}" \
GOMODCACHE="${GOMODCACHE:-/tmp/vectorcore-sgw-gomodcache}" \
go test "$ROOT_DIR/internal/dataplane/bpf" \
  -run '^$' \
  -bench 'Benchmark(BPFForward|UserspaceForward)$' \
  -benchtime "$BENCHTIME" \
  -count "$COUNT" \
  -benchmem | tee -a "$OUT_FILE"

printf 'Benchmark report written to %s\n' "$OUT_FILE"
