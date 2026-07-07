#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 <pcap> [sgw-c-log]" >&2
  exit 2
fi

PCAP=$1
LOG_FILE=${2:-}
SGWC_IP=${SGWC_IP:-10.90.250.59}
MME_IP=${MME_IP:-10.90.250.77}
MAX_DDN=${MAX_DDN:-4}
MAX_DDN_OUTCOME=${MAX_DDN_OUTCOME:-4}
MAX_MODIFY_BEARER=${MAX_MODIFY_BEARER:-8}
MAX_PFCP_MOD_REQ=${MAX_PFCP_MOD_REQ:-12}

if [[ ! -r "$PCAP" ]]; then
  echo "pcap is not readable: $PCAP" >&2
  exit 2
fi
if [[ -n "$LOG_FILE" && ! -r "$LOG_FILE" ]]; then
  echo "SGW-C log is not readable: $LOG_FILE" >&2
  exit 2
fi
if ! command -v tshark >/dev/null 2>&1; then
  echo "tshark is required for the MME restoration/NTSR lab gate" >&2
  exit 2
fi

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

gtpv2_tsv="$tmpdir/gtpv2.tsv"
pfcp_tsv="$tmpdir/pfcp.tsv"

tshark -r "$PCAP" \
  -Y 'gtpv2.message_type == 34 || gtpv2.message_type == 35 || gtpv2.message_type == 70 || gtpv2.message_type == 73 || gtpv2.message_type == 176 || gtpv2.message_type == 177' \
  -T fields \
  -e frame.number \
  -e frame.time_relative \
  -e ip.src \
  -e ip.dst \
  -e udp.srcport \
  -e udp.dstport \
  -e gtpv2.message_type \
  -e gtpv2.seq \
  -e gtpv2.teid \
  -e gtpv2.cause \
  >"$gtpv2_tsv"

tshark -r "$PCAP" \
  -Y 'pfcp.msg_type == 52' \
  -T fields \
  -e frame.number \
  -e frame.time_relative \
  -e ip.src \
  -e ip.dst \
  -e pfcp.msg_type \
  -e pfcp.seid \
  >"$pfcp_tsv"

count_gtpv2() {
  local src=$1
  local dst=$2
  local msg_type=$3
  awk -F '\t' -v src="$src" -v dst="$dst" -v msg="$msg_type" '
    $3 == src && $4 == dst && ("," $7 ",") ~ ("," msg ",") { count++ }
    END { print count + 0 }
  ' "$gtpv2_tsv"
}

count_gtpv2_any() {
  local msg_type=$1
  awk -F '\t' -v msg="$msg_type" '
    ("," $7 ",") ~ ("," msg ",") { count++ }
    END { print count + 0 }
  ' "$gtpv2_tsv"
}

unique_gtpv2_seqs() {
  local src=$1
  local dst=$2
  local msg_type=$3
  awk -F '\t' -v src="$src" -v dst="$dst" -v msg="$msg_type" '
    $3 == src && $4 == dst && ("," $7 ",") ~ ("," msg ",") { print $8 }
  ' "$gtpv2_tsv" | sort -u | awk 'NF { count++ } END { print count + 0 }'
}

pfcp_mod_req_count=$(awk 'END { print NR + 0 }' "$pfcp_tsv")
ddn_count=$(count_gtpv2 "$SGWC_IP" "$MME_IP" 176)
ddn_unique_seq=$(unique_gtpv2_seqs "$SGWC_IP" "$MME_IP" 176)
ddn_ack_count=$(count_gtpv2 "$MME_IP" "$SGWC_IP" 177)
ddn_failure_count=$(count_gtpv2 "$MME_IP" "$SGWC_IP" 70)
stop_paging_count=$(count_gtpv2 "$SGWC_IP" "$MME_IP" 73)
mbr_req_count=$(count_gtpv2 "$MME_IP" "$SGWC_IP" 34)
mbr_rsp_count=$(count_gtpv2 "$SGWC_IP" "$MME_IP" 35)
all_ddn=$(count_gtpv2_any 176)
all_outcome=$((ddn_ack_count + ddn_failure_count))

echo "MME restoration / NTSR lab gate summary"
echo "pcap: $PCAP"
echo "SGW-C: $SGWC_IP  MME: $MME_IP"
echo "SGW-C->MME Downlink Data Notifications: $ddn_count"
echo "SGW-C->MME DDN unique sequences: $ddn_unique_seq"
echo "MME->SGW-C DDN Acks: $ddn_ack_count"
echo "MME->SGW-C DDN Failure Indications: $ddn_failure_count"
echo "SGW-C->MME Stop Paging Indications: $stop_paging_count"
echo "MME->SGW-C Modify Bearer Requests: $mbr_req_count"
echo "SGW-C->MME Modify Bearer Responses: $mbr_rsp_count"
echo "PFCP Session Modification Requests: $pfcp_mod_req_count"

failed=0
if (( ddn_count == 0 )); then
  echo "FAIL: no S11 Downlink Data Notification from SGW-C to MME was found" >&2
  if (( all_ddn > 0 )); then
    echo "      DDN exists in pcap, but not for SGWC_IP=$SGWC_IP to MME_IP=$MME_IP" >&2
  fi
  failed=1
fi
if (( ddn_count > MAX_DDN )); then
  echo "FAIL: DDN count $ddn_count exceeds MAX_DDN=$MAX_DDN" >&2
  failed=1
fi
if (( ddn_unique_seq > MAX_DDN )); then
  echo "FAIL: DDN unique sequence count $ddn_unique_seq exceeds MAX_DDN=$MAX_DDN" >&2
  failed=1
fi
if (( all_outcome == 0 )); then
  echo "FAIL: no DDN Ack or DDN Failure Indication from MME to SGW-C was found" >&2
  failed=1
fi
if (( all_outcome > MAX_DDN_OUTCOME )); then
  echo "FAIL: DDN outcome count $all_outcome exceeds MAX_DDN_OUTCOME=$MAX_DDN_OUTCOME" >&2
  failed=1
fi
if (( mbr_req_count == 0 )); then
  echo "FAIL: no S11 Modify Bearer Request from MME to SGW-C was found after restoration trigger" >&2
  failed=1
fi
if (( mbr_rsp_count == 0 )); then
  echo "FAIL: no S11 Modify Bearer Response from SGW-C to MME was found" >&2
  failed=1
fi
if (( mbr_req_count > MAX_MODIFY_BEARER )); then
  echo "FAIL: Modify Bearer Request count $mbr_req_count exceeds MAX_MODIFY_BEARER=$MAX_MODIFY_BEARER" >&2
  failed=1
fi
if (( mbr_rsp_count > MAX_MODIFY_BEARER )); then
  echo "FAIL: Modify Bearer Response count $mbr_rsp_count exceeds MAX_MODIFY_BEARER=$MAX_MODIFY_BEARER" >&2
  failed=1
fi
if (( pfcp_mod_req_count == 0 )); then
  echo "FAIL: no PFCP Session Modification Request was found for user-plane restoration" >&2
  failed=1
fi
if (( pfcp_mod_req_count > MAX_PFCP_MOD_REQ )); then
  echo "FAIL: PFCP Session Modification Request count $pfcp_mod_req_count exceeds MAX_PFCP_MOD_REQ=$MAX_PFCP_MOD_REQ" >&2
  failed=1
fi

if [[ -n "$LOG_FILE" ]]; then
  echo "SGW-C log: $LOG_FILE"
  if grep -Eiq 'unhandled.*msg_type[:= ]+66|msg_type[:= ]+66.*unhandled' "$LOG_FILE"; then
    echo "FAIL: SGW-C log contains an unhandled S11 Delete Bearer Command type 66" >&2
    failed=1
  fi
  for pattern in \
    'MME restart marked for restoration' \
    'MME restoration DDN triggered' \
    'MME restoration user plane restored by Modify Bearer'; do
    if ! grep -Fq "$pattern" "$LOG_FILE"; then
      echo "WARN: SGW-C log does not contain expected marker: $pattern" >&2
    fi
  done
  ddn_controlled=$(grep -Fc 'MME restoration DDN controlled' "$LOG_FILE" || true)
  ddn_delayed=$(grep -Fc 'MME restoration DDN delayed' "$LOG_FILE" || true)
  high_priority_bypass=$(grep -Fc 'high-priority-bypass' "$LOG_FILE" || true)
  mme_low_priority_throttle=$(grep -Fc 'mme-low-priority-throttling' "$LOG_FILE" || true)
  echo "SGW-C DDN controlled decisions: $ddn_controlled"
  echo "SGW-C DDN delayed decisions: $ddn_delayed"
  echo "SGW-C high-priority bypass decisions: $high_priority_bypass"
  echo "SGW-C MME low-priority throttle suppressions: $mme_low_priority_throttle"
fi

if (( failed != 0 )); then
  exit 1
fi

echo "PASS: MME restoration/NTSR lab gate saw DDN, DDN outcome, Modify Bearer, and PFCP restoration without churn thresholds being exceeded"
