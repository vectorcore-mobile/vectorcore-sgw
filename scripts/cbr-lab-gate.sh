#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <pcap>" >&2
  exit 2
fi

PCAP=$1
SGWC_IP=${SGWC_IP:-10.90.250.59}
MME_IP=${MME_IP:-10.90.250.77}
PGW_IP=${PGW_IP:-10.90.250.92}
MAX_S11_CBR=${MAX_S11_CBR:-1}
MAX_S11_CBRESP=${MAX_S11_CBRESP:-1}
MAX_S5C_CBRESP=${MAX_S5C_CBRESP:-1}
MAX_PFCP_MOD_REQ=${MAX_PFCP_MOD_REQ:-4}

if [[ ! -r "$PCAP" ]]; then
  echo "pcap is not readable: $PCAP" >&2
  exit 2
fi
if ! command -v tshark >/dev/null 2>&1; then
  echo "tshark is required for the CBR lab gate" >&2
  exit 2
fi

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

gtpv2_tsv="$tmpdir/gtpv2.tsv"
pfcp_tsv="$tmpdir/pfcp.tsv"

tshark -r "$PCAP" \
  -Y 'gtpv2.message_type == 95 || gtpv2.message_type == 96' \
  -T fields \
  -e frame.number \
  -e frame.time_relative \
  -e ip.src \
  -e ip.dst \
  -e udp.srcport \
  -e udp.dstport \
  -e gtpv2.message_type \
  -e gtpv2.seq \
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

unique_gtpv2_seqs() {
  local src=$1
  local dst=$2
  local msg_type=$3
  awk -F '\t' -v src="$src" -v dst="$dst" -v msg="$msg_type" '
    $3 == src && $4 == dst && ("," $7 ",") ~ ("," msg ",") { print $8 }
  ' "$gtpv2_tsv" | sort -u | awk 'NF { count++ } END { print count + 0 }'
}

pfcp_mod_req_count=$(awk 'END { print NR + 0 }' "$pfcp_tsv")
pgw_cbr_count=$(count_gtpv2 "$PGW_IP" "$SGWC_IP" 95)
s11_cbr_count=$(count_gtpv2 "$SGWC_IP" "$MME_IP" 95)
s11_cbr_unique_seq=$(unique_gtpv2_seqs "$SGWC_IP" "$MME_IP" 95)
s11_cbresp_count=$(count_gtpv2 "$MME_IP" "$SGWC_IP" 96)
s5c_cbresp_count=$(count_gtpv2 "$SGWC_IP" "$PGW_IP" 96)

echo "CBR lab gate summary"
echo "pcap: $PCAP"
echo "SGW-C: $SGWC_IP  MME: $MME_IP  PGW: $PGW_IP"
echo "PGW->SGW-C Create Bearer Requests: $pgw_cbr_count"
echo "SGW-C->MME S11 Create Bearer Requests: $s11_cbr_count"
echo "SGW-C->MME S11 Create Bearer unique sequences: $s11_cbr_unique_seq"
echo "MME->SGW-C S11 Create Bearer Responses: $s11_cbresp_count"
echo "SGW-C->PGW S5/S8-C Create Bearer Responses: $s5c_cbresp_count"
echo "PFCP Session Modification Requests: $pfcp_mod_req_count"

failed=0
if (( s11_cbr_count == 0 )); then
  echo "FAIL: no S11 Create Bearer Request from SGW-C to MME was found" >&2
  failed=1
fi
if (( s11_cbr_count > MAX_S11_CBR )); then
  echo "FAIL: S11 Create Bearer Request count $s11_cbr_count exceeds MAX_S11_CBR=$MAX_S11_CBR" >&2
  failed=1
fi
if (( s11_cbr_unique_seq > MAX_S11_CBR )); then
  echo "FAIL: S11 Create Bearer unique sequence count $s11_cbr_unique_seq exceeds MAX_S11_CBR=$MAX_S11_CBR" >&2
  failed=1
fi
if (( s11_cbresp_count == 0 )); then
  echo "FAIL: no S11 Create Bearer Response from MME to SGW-C was found" >&2
  failed=1
fi
if (( s11_cbresp_count > MAX_S11_CBRESP )); then
  echo "FAIL: S11 Create Bearer Response count $s11_cbresp_count exceeds MAX_S11_CBRESP=$MAX_S11_CBRESP" >&2
  failed=1
fi
if (( s5c_cbresp_count == 0 )); then
  echo "FAIL: no S5/S8-C Create Bearer Response from SGW-C to PGW was found" >&2
  failed=1
fi
if (( s5c_cbresp_count > MAX_S5C_CBRESP )); then
  echo "FAIL: S5/S8-C Create Bearer Response count $s5c_cbresp_count exceeds MAX_S5C_CBRESP=$MAX_S5C_CBRESP" >&2
  failed=1
fi
if (( pfcp_mod_req_count > MAX_PFCP_MOD_REQ )); then
  echo "FAIL: PFCP Session Modification Request count $pfcp_mod_req_count exceeds MAX_PFCP_MOD_REQ=$MAX_PFCP_MOD_REQ" >&2
  failed=1
fi

if (( failed != 0 )); then
  exit 1
fi

echo "PASS: CBR lab gate did not detect repeated S11 CBRs or PFCP modification churn"
