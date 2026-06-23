# VectorCore SGW — Packet Capture Templates

Capture templates for validating Phase 8 end-to-end default bearer attach.
All UDP ports and GTP-U port 2152 per TS 29.281 §4.4.2.1.

---

## S11 — SGW-C ↔ MME (GTPv2-C)

**Interface:** SGW-C S11 listener (configured in `sgwc.yaml` → `s11.listen`)
**Protocol:** GTPv2-C over UDP/2123

```bash
# Live capture on S11 interface
tcpdump -i eth0 -w s11.pcap 'udp port 2123'

# tshark display filter — all GTPv2-C on S11
tshark -r s11.pcap -Y 'gtpv2'

# Create Session Request (MsgType=32) from MME
tshark -r s11.pcap -Y 'gtpv2.message_type == 32'

# Create Session Response (MsgType=33) to MME
tshark -r s11.pcap -Y 'gtpv2.message_type == 33'

# Modify Bearer Request (MsgType=34) from MME with eNB F-TEID
tshark -r s11.pcap -Y 'gtpv2.message_type == 34'

# Modify Bearer Response (MsgType=35) to MME
tshark -r s11.pcap -Y 'gtpv2.message_type == 35'

# Delete Session Request/Response (MsgType=36/37)
tshark -r s11.pcap -Y 'gtpv2.message_type == 36 || gtpv2.message_type == 37'

# Verify response TEID matches MME's control TEID (C4 check)
tshark -r s11.pcap -Y 'gtpv2.message_type == 33 || gtpv2.message_type == 35' \
    -T fields -e frame.number -e gtpv2.message_type -e gtpv2.teid
```

---

## S5/S8-C — SGW-C ↔ PGW (GTPv2-C)

**Interface:** SGW-C S5/S8-C egress (configured in `sgwc.yaml` → `s5c.local_addr`)
**Protocol:** GTPv2-C over UDP/2123

```bash
# Live capture
tcpdump -i eth1 -w s5c.pcap 'udp port 2123'

# Create Session Request to PGW (MsgType=32)
tshark -r s5c.pcap -Y 'gtpv2.message_type == 32'

# Create Session Response from PGW (MsgType=33)
# Verify: PGW S5/S8-U F-TEID in Bearer Context (instance 2 per Table 7.2.2-2)
tshark -r s5c.pcap -Y 'gtpv2.message_type == 33' \
    -T fields -e gtpv2.cause -e gtpv2.f_teid_v4 -e gtpv2.f_teid_teid

# Delete Session Request (MsgType=36) — TEID must be PGW's control TEID (C4)
tshark -r s5c.pcap -Y 'gtpv2.message_type == 36'
```

---

## Sxa — SGW-C ↔ SGW-U (PFCP)

**Interface:** SGW-C PFCP listener (configured in `sgwc.yaml` → `pfcp.local_addr`)
**Protocol:** PFCP over UDP/8805

```bash
# Live capture
tcpdump -i lo -w sxa.pcap 'udp port 8805'

# All PFCP messages
tshark -r sxa.pcap -Y 'pfcp'

# Session Establishment Request (MsgType=50)
tshark -r sxa.pcap -Y 'pfcp.message_type == 50'

# Session Modification Request (MsgType=52) — sent after MBReq arrives
# Verify: Update FAR IE (type=10) with OHC containing eNB TEID
tshark -r sxa.pcap -Y 'pfcp.message_type == 52'

# Session Deletion Request (MsgType=54)
tshark -r sxa.pcap -Y 'pfcp.message_type == 54'

# Check PFCP session SEID values across establishment and modification
tshark -r sxa.pcap -Y 'pfcp' \
    -T fields -e frame.number -e pfcp.message_type -e pfcp.seid
```

---

## S1-U — SGW-U ↔ eNodeB (GTP-U)

**Interface:** SGW-U S1-U access interface (configured in `sgwu.yaml` → `gtpu.access.ifname`)
**Protocol:** GTP-U over UDP/2152

```bash
# Live capture
tcpdump -i eth2 -w s1u.pcap 'udp port 2152'

# All GTP-U packets (G-PDU MsgType=255 and control)
tshark -r s1u.pcap -Y 'gtp'

# G-PDU user data packets only (MsgType=255)
tshark -r s1u.pcap -Y 'gtp.message_type == 255'

# Echo Request (MsgType=1) / Echo Response (MsgType=2) keepalives
tshark -r s1u.pcap -Y 'gtp.message_type == 1 || gtp.message_type == 2'

# End Marker (MsgType=254) — sent on tunnel handover per TS 29.281 §7.3.2
tshark -r s1u.pcap -Y 'gtp.message_type == 254'

# Verify TEID matches SGW-U's allocated S1-U TEID (from CSResp Bearer Context)
tshark -r s1u.pcap -Y 'gtp.message_type == 255' \
    -T fields -e frame.number -e gtp.teid -e ip.src -e ip.dst -e frame.len

# Verify GTP-U flags: version=1(001b), PT=1 → flags byte bits 8-5 = 0x30
# Spare bit (bit 4) must not be checked per TS 29.281 §5.1 NOTE 0.
tshark -r s1u.pcap -Y 'gtp.message_type == 255' \
    -T fields -e gtp.flags
```

---

## S5/S8-U — SGW-U ↔ PGW-U (GTP-U)

**Interface:** SGW-U S5/S8-U core interface (configured in `sgwu.yaml` → `gtpu.core.ifname`)
**Protocol:** GTP-U over UDP/2152

```bash
# Live capture
tcpdump -i eth3 -w s5u.pcap 'udp port 2152'

# G-PDU packets (MsgType=255)
tshark -r s5u.pcap -Y 'gtp.message_type == 255'

# Verify TEID on uplink: must match PGW-U's S5/S8-U TEID (from PGW CSResp Bearer Context)
# Verify TEID on downlink: must match SGW-U's allocated S5/S8-U TEID (Created PDR 2)
tshark -r s5u.pcap -Y 'gtp.message_type == 255' \
    -T fields -e frame.number -e gtp.teid -e ip.src -e ip.dst

# Verify outer IP rewrite by TC-BPF fast path (Phase 7):
# Uplink: outer src=SGW-U S5/S8-U IP, outer dst=PGW-U IP
# Downlink: outer src=SGW-U S1-U IP, outer dst=eNB IP (after BPF rewrites it)
tshark -r s5u.pcap -Y 'gtp.message_type == 255' \
    -T fields -e ip.src -e ip.dst -e gtp.teid
```

---

## Combined: Full Attach Sequence Capture

```bash
# Capture all relevant interfaces simultaneously
tcpdump -i eth0 -w s11.pcap    'udp port 2123' &
tcpdump -i eth1 -w s5c.pcap    'udp port 2123' &
tcpdump -i lo   -w sxa.pcap    'udp port 8805' &
tcpdump -i eth2 -w s1u.pcap    'udp port 2152' &
tcpdump -i eth3 -w s5u.pcap    'udp port 2152' &
wait

# Merge for sequence analysis
mergecap -w attach.pcap s11.pcap s5c.pcap sxa.pcap s1u.pcap s5u.pcap

# Timeline view of full attach
tshark -r attach.pcap -Y 'gtpv2 || pfcp || gtp' \
    -T fields -e frame.time_relative -e _ws.col.Protocol -e _ws.col.Info | head -50
```

---

## Expected Attach Message Sequence

```
MME → SGW-C    S11  CreateSessionRequest   (MsgType=32)
SGW-C → PGW    S5/S8-C CreateSessionRequest (MsgType=32)
PGW → SGW-C    S5/S8-C CreateSessionResponse (MsgType=33, Cause=16)
SGW-C → SGW-U  Sxa  SessionEstablishmentRequest (MsgType=50)
SGW-U → SGW-C  Sxa  SessionEstablishmentResponse (MsgType=51, Cause=1)
SGW-C → MME    S11  CreateSessionResponse (MsgType=33, Cause=16)
MME → SGW-C    S11  ModifyBearerRequest (MsgType=34) ← eNB S1-U F-TEID
SGW-C → SGW-U  Sxa  SessionModificationRequest (MsgType=52) ← Update FAR 2 FORW+OHC
SGW-U → SGW-C  Sxa  SessionModificationResponse (MsgType=53, Cause=1)
SGW-C → MME    S11  ModifyBearerResponse (MsgType=35, Cause=16)
UE              S1-U/S5-U  G-PDU traffic (MsgType=255)
```

Reference constants (TS 29.274 Table 6.1-1, TS 29.244 Table 7.1-1):
- GTPv2-C port 2123 (UDP)
- GTP-U port 2152 per TS 29.281 §4.4.2.1
- PFCP port 8805 per TS 29.244 §4.4.1 (IANA assigned)
