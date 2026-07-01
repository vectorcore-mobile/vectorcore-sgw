#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 <pcap> [display-filter]" >&2
  echo "example: $0 cisco-sgw-pgw.pcap 'ip.addr == 10.90.250.92 && ip.addr == 10.90.250.80 && udp.port == 2123'" >&2
  exit 2
fi

PCAP=$1
PEER_FILTER=${2:-udp.port == 2123}
MAX_ROWS=${MAX_ROWS:-80}
S5C_VERBOSE=${S5C_VERBOSE:-0}
MAX_VERBOSE_LINES=${MAX_VERBOSE_LINES:-400}

if [[ ! -r "$PCAP" ]]; then
  echo "pcap is not readable: $PCAP" >&2
  exit 2
fi
if ! command -v tshark >/dev/null 2>&1; then
  echo "tshark is required" >&2
  exit 2
fi

echo "S5/S8-C reference summary"
echo "pcap: $PCAP"
echo "filter: $PEER_FILTER"
echo "max_rows: $MAX_ROWS"
echo

echo "== Procedure timeline =="
tshark -r "$PCAP" \
  -Y "gtpv2 && ($PEER_FILTER) && (gtpv2.message_type == 32 || gtpv2.message_type == 33 || gtpv2.message_type == 95 || gtpv2.message_type == 96)" \
  -T fields \
  -e frame.number \
  -e frame.time_relative \
  -e ip.src \
  -e ip.dst \
  -e udp.srcport \
  -e udp.dstport \
  -e gtpv2.message_type \
  -e gtpv2.teid \
  -e gtpv2.seq \
  -e gtpv2.cause \
  -e gtpv2.ebi \
  -e gtpv2.f_teid_interface_type \
  -e gtpv2.f_teid_gre_key \
  -e gtpv2.f_teid_ipv4 \
  -E header=y \
  -E separator='|' |
  awk -v max="$MAX_ROWS" 'NR == 1 || NR <= max + 1'

if [[ "$S5C_VERBOSE" == "1" ]]; then
  echo
  echo "== IMS Create Session / Create Bearer decode =="
  tshark -r "$PCAP" \
    -Y "gtpv2 && ($PEER_FILTER) && (gtpv2.message_type == 32 || gtpv2.message_type == 33 || gtpv2.message_type == 95 || gtpv2.message_type == 96)" \
    -V |
    sed -n '/GPRS Tunneling Protocol V2/,$p' |
    awk '
      /Message Type: Create Session Request/ ||
      /Message Type: Create Session Response/ ||
      /Message Type: Create Bearer Request/ ||
      /Message Type: Create Bearer Response/ ||
      /Flags:/ ||
      /Message Length:/ ||
      /Tunnel Endpoint Identifier:/ ||
      /Sequence Number:/ ||
      /Cause :/ ||
      /EPS Bearer ID/ ||
      /Bearer Context/ ||
      /Fully Qualified Tunnel Endpoint Identifier/ ||
      /Protocol Configuration Options/ ||
      /Aggregate Maximum Bit Rate/ ||
      /PDN Address Allocation/ ||
      /APN Restriction/ ||
      /Bearer Level Quality of Service/ ||
      /EPS Bearer Level Traffic Flow Template/ ||
      /Charging ID/ ||
      /Recovery/ {
        print
      }' |
    awk -v max="$MAX_VERBOSE_LINES" 'NR <= max'
else
  echo
  echo "Set S5C_VERBOSE=1 for a bounded decoded IE summary."
fi
