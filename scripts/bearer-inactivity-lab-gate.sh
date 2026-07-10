#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 3 ]]; then
  echo "usage: $0 <pcap> [sgw-c-log] [bearer-inactivity-json]" >&2
  exit 2
fi

PCAP=$1
LOG_FILE=${2:-}
STATUS_JSON=${3:-}
SGWC_IP=${SGWC_IP:-10.90.250.59}
MME_IP=${MME_IP:-10.90.250.77}
PGW_IP=${PGW_IP:-10.90.250.92}
MIN_PFCP_MOD_REQ=${MIN_PFCP_MOD_REQ:-1}
MAX_PFCP_MOD_REQ=${MAX_PFCP_MOD_REQ:-8}
MAX_MODIFY_BEARER=${MAX_MODIFY_BEARER:-8}
MAX_DELETE_SESSION=${MAX_DELETE_SESSION:-0}
MAX_DELETE_BEARER_GTPC=${MAX_DELETE_BEARER_GTPC:-0}
MIN_GTPU_PACKETS=${MIN_GTPU_PACKETS:-1}

if [[ ! -r "$PCAP" ]]; then
  echo "pcap is not readable: $PCAP" >&2
  exit 2
fi
if [[ -n "$LOG_FILE" && ! -r "$LOG_FILE" ]]; then
  echo "SGW-C log is not readable: $LOG_FILE" >&2
  exit 2
fi
if [[ -n "$STATUS_JSON" && ! -r "$STATUS_JSON" ]]; then
  echo "bearer inactivity JSON is not readable: $STATUS_JSON" >&2
  exit 2
fi
if ! command -v tshark >/dev/null 2>&1; then
  echo "tshark is required for the bearer inactivity lab gate" >&2
  exit 2
fi

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

gtpv2_tsv="$tmpdir/gtpv2.tsv"
pfcp_tsv="$tmpdir/pfcp.tsv"
gtpu_tsv="$tmpdir/gtpu.tsv"

tshark -r "$PCAP" \
  -Y 'gtpv2.message_type == 34 || gtpv2.message_type == 35 || gtpv2.message_type == 36 || gtpv2.message_type == 37 || gtpv2.message_type == 66 || gtpv2.message_type == 67 || gtpv2.message_type == 99 || gtpv2.message_type == 100' \
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
  -Y 'pfcp.msg_type == 52 || pfcp.msg_type == 53 || pfcp.msg_type == 54 || pfcp.msg_type == 55' \
  -T fields \
  -e frame.number \
  -e frame.time_relative \
  -e ip.src \
  -e ip.dst \
  -e pfcp.msg_type \
  -e pfcp.seid \
  >"$pfcp_tsv"

tshark -r "$PCAP" \
  -Y 'udp.port == 2152' \
  -T fields \
  -e frame.number \
  -e frame.time_relative \
  -e ip.src \
  -e ip.dst \
  >"$gtpu_tsv"

count_gtpv2() {
  local msg_type=$1
  awk -F '\t' -v msg="$msg_type" '
    ("," $7 ",") ~ ("," msg ",") { count++ }
    END { print count + 0 }
  ' "$gtpv2_tsv"
}

count_gtpv2_between() {
  local src=$1
  local dst=$2
  local msg_type=$3
  awk -F '\t' -v src="$src" -v dst="$dst" -v msg="$msg_type" '
    $3 == src && $4 == dst && ("," $7 ",") ~ ("," msg ",") { count++ }
    END { print count + 0 }
  ' "$gtpv2_tsv"
}

count_pfcp() {
  local msg_type=$1
  awk -F '\t' -v msg="$msg_type" '
    ("," $5 ",") ~ ("," msg ",") { count++ }
    END { print count + 0 }
  ' "$pfcp_tsv"
}

pfcp_mod_req_count=$(count_pfcp 52)
pfcp_mod_rsp_count=$(count_pfcp 53)
pfcp_del_req_count=$(count_pfcp 54)
pfcp_del_rsp_count=$(count_pfcp 55)
mbr_req_count=$(count_gtpv2_between "$MME_IP" "$SGWC_IP" 34)
mbr_rsp_count=$(count_gtpv2_between "$SGWC_IP" "$MME_IP" 35)
delete_session_count=$(( $(count_gtpv2 36) + $(count_gtpv2 37) ))
delete_bearer_gtpc_count=$(( $(count_gtpv2 66) + $(count_gtpv2 67) + $(count_gtpv2 99) + $(count_gtpv2 100) ))
gtpu_count=$(awk 'END { print NR + 0 }' "$gtpu_tsv")

echo "Bearer inactivity lab gate summary"
echo "pcap: $PCAP"
echo "SGW-C: $SGWC_IP  MME: $MME_IP  PGW: $PGW_IP"
echo "PFCP Session Modification Requests: $pfcp_mod_req_count"
echo "PFCP Session Modification Responses: $pfcp_mod_rsp_count"
echo "PFCP Session Deletion Requests: $pfcp_del_req_count"
echo "PFCP Session Deletion Responses: $pfcp_del_rsp_count"
echo "MME->SGW-C Modify Bearer Requests: $mbr_req_count"
echo "SGW-C->MME Modify Bearer Responses: $mbr_rsp_count"
echo "GTPv2-C Delete Session messages: $delete_session_count"
echo "GTPv2-C Delete Bearer messages: $delete_bearer_gtpc_count"
echo "GTP-U packets: $gtpu_count"

failed=0
if (( pfcp_mod_req_count < MIN_PFCP_MOD_REQ )); then
  echo "FAIL: PFCP Session Modification Request count $pfcp_mod_req_count is below MIN_PFCP_MOD_REQ=$MIN_PFCP_MOD_REQ" >&2
  failed=1
fi
if (( pfcp_mod_req_count > MAX_PFCP_MOD_REQ )); then
  echo "FAIL: PFCP Session Modification Request count $pfcp_mod_req_count exceeds MAX_PFCP_MOD_REQ=$MAX_PFCP_MOD_REQ" >&2
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
if (( delete_session_count > MAX_DELETE_SESSION )); then
  echo "FAIL: Delete Session messages $delete_session_count exceed MAX_DELETE_SESSION=$MAX_DELETE_SESSION" >&2
  failed=1
fi
if (( delete_bearer_gtpc_count > MAX_DELETE_BEARER_GTPC )); then
  echo "FAIL: GTP-C Delete Bearer messages $delete_bearer_gtpc_count exceed MAX_DELETE_BEARER_GTPC=$MAX_DELETE_BEARER_GTPC" >&2
  failed=1
fi
if (( gtpu_count < MIN_GTPU_PACKETS )); then
  echo "FAIL: GTP-U packet count $gtpu_count is below MIN_GTPU_PACKETS=$MIN_GTPU_PACKETS; first-call/active-call traffic was not proven" >&2
  failed=1
fi

if [[ -n "$LOG_FILE" ]]; then
  echo "SGW-C log: $LOG_FILE"
  if grep -Eiq 'unhandled.*msg_type[:= ]+66|msg_type[:= ]+66.*unhandled' "$LOG_FILE"; then
    echo "FAIL: SGW-C log contains an unhandled S11 Delete Bearer Command type 66" >&2
    failed=1
  fi
  if grep -Eiq 'default-bearer-cleanup-not-executed|refusing inactivity cleanup for default bearer|default bearer.*removed by.*inactivity' "$LOG_FILE"; then
    echo "FAIL: SGW-C log contains default bearer cleanup/refusal markers; inspect policy before lab acceptance" >&2
    failed=1
  fi
  cleaned=$(grep -Fc 'SGW-C bearer inactivity cleanup completed' "$LOG_FILE" || true)
  failed_cleanup=$(grep -Fc 'SGW-C bearer inactivity cleanup failed' "$LOG_FILE" || true)
  scans=$(grep -Fc 'SGW-C bearer inactivity scan complete' "$LOG_FILE" || true)
  echo "SGW-C bearer inactivity cleanup completed logs: $cleaned"
  echo "SGW-C bearer inactivity cleanup failed logs: $failed_cleanup"
  echo "SGW-C bearer inactivity scan complete logs: $scans"
  if (( cleaned == 0 )); then
    echo "WARN: SGW-C log does not show a completed bearer inactivity cleanup" >&2
  fi
  if (( failed_cleanup > 0 )); then
    echo "FAIL: SGW-C log contains bearer inactivity cleanup failures" >&2
    failed=1
  fi
fi

if [[ -n "$STATUS_JSON" ]]; then
  echo "Bearer inactivity API snapshot: $STATUS_JSON"
  if command -v jq >/dev/null 2>&1; then
    candidates=$(jq -r '.candidates // 0' "$STATUS_JSON")
    cleaned=$(jq -r '.runtime.cleaned // 0' "$STATUS_JSON")
    failed_api=$(jq -r '.runtime.failed // 0' "$STATUS_JSON")
    denied_default=$(jq -r '.runtime.denied_default // 0' "$STATUS_JSON")
    missing_rules=$(jq -r '.runtime.missing_rules // 0' "$STATUS_JSON")
    echo "API candidates: $candidates"
    echo "API runtime cleaned: $cleaned"
    echo "API runtime failed: $failed_api"
    echo "API runtime denied_default: $denied_default"
    echo "API runtime missing_rules: $missing_rules"
    if (( failed_api > 0 || denied_default > 0 || missing_rules > 0 )); then
      echo "FAIL: bearer inactivity API reports cleanup failures/denials/missing rules" >&2
      failed=1
    fi
  else
    if grep -Eq '"failed"[[:space:]]*:[[:space:]]*[1-9]|"denied_default"[[:space:]]*:[[:space:]]*[1-9]|"missing_rules"[[:space:]]*:[[:space:]]*[1-9]' "$STATUS_JSON"; then
      echo "FAIL: bearer inactivity API snapshot reports failures/denials/missing rules" >&2
      failed=1
    fi
  fi
fi

if (( failed != 0 )); then
  exit 1
fi

echo "PASS: bearer inactivity lab gate did not detect default bearer deletion, GTP-C bearer/session deletes, PFCP churn, cleanup failures, or missing user-plane traffic"
