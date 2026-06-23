# VectorCore SGW — Architecture

## CUPS Split

```
                    +----------------------+
                    |        MME           |
                    +----------+-----------+
                               |
                               | S11 / GTPv2-C  (TS 29.274)
                               |
                    +----------v-----------+
                    |  VectorCore SGW-C    |
                    |----------------------|
                    | S11 handler          |
                    | S5/S8-C client       |
                    | session manager      |
                    | bearer manager       |
                    | TEID allocator       |
                    | PFCP/Sxa controller  |
                    +----+-------------+---+
                         |             |
            S5/S8-C      |             | Sxa / PFCP  (TS 29.244)
            (TS 29.274)  |             |
        +----------------v--+       +--v-------------------+
        | PGW-C / legacy PGW |       | VectorCore SGW-U     |
        +-------------------+       |----------------------|
                                    | PFCP server          |
                                    | PDR/FAR/QER store    |
                                    | BPF rule compiler    |
                                    | TC-BPF GTP-U path    |
                                    | userspace ref path   |
                                    +----+------------+----+
                                         |            |
                               S1-U      |            | S5/S8-U
                           (TS 29.281)   |            | (TS 29.281)
                                  +------v--+      +--v------+
                                  | eNodeB  |      | PGW-U   |
                                  +---------+      +---------+
```

## SGW-C Responsibilities

- Listen on S11 for MME GTPv2-C (TS 29.274)
- Allocate SGW control TEIDs for S11 and S5/S8-C
- Create/modify/delete PDN sessions toward PGW-C via S5/S8-C
- Maintain PFCP associations to SGW-U nodes (Sxa, TS 29.244)
- Translate bearer state into PFCP PDR/FAR/QER rules
- Request SGW-U F-TEID allocation via PFCP CHOOSE bit
- Handle MME-triggered and PGW-triggered bearer procedures
- Expose session/bearer/debug REST API (Huma/OpenAPI)
- Export Prometheus metrics

## SGW-U Responsibilities

- Listen for Sxa/PFCP from SGW-C (TS 29.244)
- Accept PFCP Association Setup and maintain heartbeat
- Accept PFCP Session Establishment / Modification / Deletion
- Allocate local user-plane TEIDs when CHOOSE bit is set
- Compile PFCP PDR/FAR/QER state into compact BPF map entries
- Program TC-BPF maps for GTP-U fast path
- Forward S1-U ↔ S5/S8-U via TC-BPF or userspace reference path
- Handle GTP-U Echo, Error Indication, End Marker in userspace
- Maintain per-session and per-bearer packet/byte counters
- Export Prometheus metrics and debug REST API

## Dataplane Fast Path (Phase 7+)

```
Incoming GTP-U packet (S1-U or S5/S8-U)
    |
    v TC ingress hook
    Parse Ethernet / IPv4 / UDP / GTP-U header
    |
    v
    Validate: G-PDU, port 2152, GTP-U flags
    |
    v
    Lookup gtpu_rule_key { local_teid, ingress_ifindex, direction }
    |
    +-- No rule --> punt to userspace or drop (per config)
    |
    v
    Apply gtpu_rule_value:
      rewrite outer src IP
      rewrite outer dst IP
      rewrite GTP-U TEID
      update IP/UDP checksums
      increment counter
      redirect to egress interface
```

## Punt Path (userspace)

The following always go to userspace rather than BPF fast path:
- GTP-U Echo Request / Response
- GTP-U Error Indication
- GTP-U End Marker
- Unknown TEID
- Malformed GTP-U
- Non-G-PDU message types
- Outer IP fragments

## PFCP to BPF Compilation

```
PFCP Session Establishment Request
    |
    v SGW-U validates PDR/FAR/QER
    |
    v SGW-U compiles compact forwarding entries:
        uplink:   key={s1u_teid, s1u_if, access_to_core}  value={forward, s5u_src, pgwu_dst, pgwu_teid, s5u_if}
        downlink: key={s5u_teid, s5u_if, core_to_access}  value={forward, s1u_src, enb_dst,  enb_teid,  s1u_if}
    |
    v SGW-U writes BPF hash maps
    |
    v TC-BPF executes forwarding by TEID lookup
```

## Binary Layout

```
cmd/
  vectorcore-sgw-c/   SGW-C binary (control plane)
  vectorcore-sgw-u/   SGW-U binary (user plane)
  vectorcore-sgwctl/  CLI management tool

internal/
  config/sgwc/        SGW-C YAML config (configs/sgw-c.yaml)
  config/sgwu/        SGW-U YAML config (configs/sgw-u.yaml)
  log/                slog JSON logger (file + optional debug console)
  metrics/            Prometheus registry + HTTP server
  api/                Huma/OpenAPI REST server
  gtpv2/              Internal GTPv2-C codec (codec, ie, message, transport)
  sgwc/               SGW-C subsystems (s11, s5c, session, bearer, teid, pfcpclient)
  sgwu/               SGW-U subsystems (pfcpserver, session, compiler, dataplane, counters)
  dataplane/          BPF loader, map definitions, forwarding model

ebpf/
  tc_sgw_gtpu.c       TC-BPF GTP-U fast path (Phase 7)
  maps.h              BPF map definitions
  common.h            Shared structs
```
