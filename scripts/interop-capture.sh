#!/usr/bin/env bash
set -euo pipefail

CAPTURE_DIR="${CAPTURE_DIR:-docs/captures/interop}"
S11_IFACE="${S11_IFACE:-eth0}"
S5C_IFACE="${S5C_IFACE:-eth0}"
PFCP_IFACE="${PFCP_IFACE:-eth0}"
S1U_IFACE="${S1U_IFACE:-eth0}"
S5U_IFACE="${S5U_IFACE:-eth0}"

mkdir -p "$CAPTURE_DIR"

cleanup() {
  trap - INT TERM EXIT
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

PIDS=()

tcpdump -i "$S11_IFACE" -w "$CAPTURE_DIR/s11.pcap" 'udp port 2123' &
PIDS+=("$!")
tcpdump -i "$S5C_IFACE" -w "$CAPTURE_DIR/s5c.pcap" 'udp port 2123' &
PIDS+=("$!")
tcpdump -i "$PFCP_IFACE" -w "$CAPTURE_DIR/sxa.pcap" 'udp port 8805' &
PIDS+=("$!")
tcpdump -i "$S1U_IFACE" -w "$CAPTURE_DIR/s1u.pcap" 'udp port 2152' &
PIDS+=("$!")
tcpdump -i "$S5U_IFACE" -w "$CAPTURE_DIR/s5u.pcap" 'udp port 2152' &
PIDS+=("$!")

printf 'Capturing interop traffic in %s\n' "$CAPTURE_DIR"
printf 'Interfaces: S11=%s S5C=%s PFCP=%s S1U=%s S5U=%s\n' \
  "$S11_IFACE" "$S5C_IFACE" "$PFCP_IFACE" "$S1U_IFACE" "$S5U_IFACE"
printf 'Press Ctrl-C to stop captures.\n'

wait
