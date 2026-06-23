# VectorCore SGW CUPS Build Plan

**Project:** VectorCore SGW-C / SGW-U  
**Language:** Go  
**Dataplane:** eBPF / TC-BPF GTP-U fast path  
**PFCP Library:** `github.com/wmnsk/go-pfcp`  
**Target Architecture:** 3GPP EPC CUPS-compliant SGW-C / SGW-U split  
**3GPP Release Target:** Release 15 (Rel-15)  
**Primary Interfaces:** S11, S5/S8-C, S1-U, S5/S8-U, Sxa/PFCP  
**Initial Scope:** LTE EPC Serving Gateway, default bearer first, dedicated bearers later

---

## 1. Goal

Build a 3GPP-spec-targeted LTE Serving Gateway using a true CUPS architecture. The implemented feature scope must follow the applicable 3GPP specifications, not merely match one vendor implementation or one open-source stack:

```text
MME
 |
 | S11 / GTPv2-C
 v
VectorCore SGW-C
 |
 | S5/S8-C / GTPv2-C
 v
PGW-C / legacy PGW control side

VectorCore SGW-C
 |
 | Sxa / PFCP
 v
VectorCore SGW-U
 |
 +-- S1-U / GTP-U toward eNodeB
 |
 +-- S5/S8-U / GTP-U toward PGW-U / legacy PGW user side
```

The SGW-C owns control-plane state, bearer state, TEID allocation, S11 handling, S5/S8-C handling, PFCP session control, and SGW-U selection.

The SGW-U owns GTP-U forwarding, PFCP session enforcement, eBPF map programming, counters, and packet fast-path behavior.

The primary performance objective is to avoid the classic userspace GTP-U forwarding model:

```text
packet -> kernel UDP socket -> userspace parse -> userspace lookup -> userspace send -> kernel transmit
```

and replace it with:

```text
packet -> TC-BPF ingress -> TEID lookup -> rewrite -> redirect
```

---

## 2. Standards Alignment

### 2.0 3GPP Release Target

**All interfaces and procedures MUST be implemented against 3GPP Release 15 (Rel-15).**

Rel-15 is the stable, widely-deployed LTE CUPS generation and the baseline for this project. It is the first release to include the mature CUPS architecture (TS 23.214), PFCP Rel-15 (TS 29.244), and the full Rel-15 GTPv2-C feature set (TS 29.274). Every spec reference in this document refers to the Rel-15 version of that specification unless explicitly noted otherwise.

| Specification | Rel-15 Version Used | Purpose |
|---|---|---|
| TS 23.401 v15.x | Release 15 | LTE/EPC architecture, attach, bearer, SGW role |
| TS 23.214 v15.x | Release 15 | CUPS architecture, SGW-C/SGW-U split, Sxa |
| TS 29.274 v15.x | Release 15 | GTPv2-C — S11 and S5/S8-C messages and IEs |
| TS 29.244 v15.x | Release 15 | PFCP/Sxa — PDR, FAR, QER, URR, BAR |
| TS 29.281 v15.x | Release 15 | GTP-U — S1-U and S5/S8-U tunneling |
| TS 23.203 v15.x | Release 15 | QoS, QCI, ARP, GBR/MBR |
| TS 23.003 v15.x | Release 15 | IMSI/MSISDN TBCD, APN label encoding |
| TS 29.303 v15.x | Release 15 | SGW/PGW/APN DNS selection (later phase) |

When a feature is first introduced in a release AFTER Rel-15 it must be deferred and documented as out-of-scope. When a feature exists in Rel-15 it must be implemented per the Rel-15 definition, not a vendor-specific or earlier-release interpretation.

The implementation MUST be built against the following 3GPP specifications. These references define the required behavior for the declared feature scope:

| Area | Specification | Purpose |
|---|---:|---|
| EPC architecture | TS 23.401 | LTE/EPC attach, default bearer, dedicated bearer, SGW role |
| EPC CUPS architecture | TS 23.214 | SGW-C / SGW-U split, Sxa, CUPS behavior |
| GTPv2-C | TS 29.274 | S11 and S5/S8-C procedures |
| PFCP / Sxa | TS 29.244 | PFCP messages, PDR/FAR/QER/URR/BAR rules |
| GTP-U | TS 29.281 | G-PDU forwarding, TEID behavior, Echo, Error Indication |
| QoS / bearer concepts | TS 23.203 / TS 23.401 | QCI, ARP, GBR/MBR, TFT handling |
| DNS selection, later phase | TS 29.303 | SGW/PGW/APN selection if dynamic DNS selection is added |

Implementation notes:

- Treat TS 23.214 Rel-15 as the main CUPS architecture spec.
- Treat TS 29.244 Rel-15 as the mandatory PFCP/Sxa implementation spec.
- Treat TS 29.274 Rel-15 as mandatory for S11 and S5/S8-C correctness.
- Treat TS 29.281 Rel-15 as mandatory for the S1-U and S5/S8-U GTP-U dataplane.
- For v0/v1, constrain scope intentionally; do not attempt every optional LTE feature at once.

### 2.1 Mandatory Interface Compliance Requirement

All external EPC interfaces MUST be implemented against the applicable 3GPP specifications, not merely against Open5GS behavior, StarOS behavior, or any other single vendor implementation. Open5GS, StarOS, srsRAN, and packet captures may be used as interop targets and behavioral references, but they are not the specification authority.

The project requirement is:

```text
Implemented feature scope = 3GPP-spec-correct
Deferred feature scope    = explicitly documented as not supported yet
Vendor quirks            = compatibility layer only, never the baseline behavior
```

This means v0 may intentionally defer features such as IPv6 PDN, SGW relocation, ISR, S4/S12, PMIP, roaming, and advanced charging; however, every supported v0 feature must behave according to the relevant 3GPP procedures and information elements.

### 2.2 Required Interface Specifications

| Interface | Endpoint Direction | Protocol | Mandatory Spec Target | Required Meaning |
|---|---|---|---|---|
| S11 | MME ↔ SGW-C | GTPv2-C | TS 29.274 | LTE session/bearer control between MME and SGW |
| S5/S8-C | SGW-C ↔ PGW-C / legacy PGW | GTPv2-C | TS 29.274 | Control-plane session/bearer procedures toward PGW |
| Sxa | SGW-C ↔ SGW-U | PFCP | TS 29.244 + TS 23.214 | CUPS control of SGW-U PDR/FAR/QER/URR/BAR state |
| S1-U | eNodeB ↔ SGW-U | GTP-U | TS 29.281 | User-plane tunnel between eNodeB and SGW-U |
| S5/S8-U | SGW-U ↔ PGW-U / legacy PGW | GTP-U | TS 29.281 | User-plane tunnel between SGW-U and PGW-U |

### 2.3 eBPF Compliance Boundary

The eBPF dataplane is an acceleration mechanism only. It MUST preserve 3GPP GTP-U behavior for S1-U and S5/S8-U, including TEID handling, encapsulation/decapsulation behavior, peer addressing, Error Indication handling, End Marker behavior, Echo handling through the userspace control path, and unknown-TEID behavior.

BPF must not redefine the protocol. The userspace SGW-U must compile validated PFCP/GTP-U state into compact BPF map entries, and the BPF program must execute only the forwarding behavior that is already authorized by spec-derived control-plane state.

### 2.4 Compliance Acceptance Rule

A feature is not considered complete until all three checks pass:

1. The implementation is mapped to the relevant 3GPP procedure and IE requirements.
2. PCAPs show correct wire behavior on the relevant interface.
3. Interop testing succeeds against at least one real peer, while still preserving spec-correct baseline behavior.

### 2.5 Spec-Traceability Implementation Process

Every GTPv2-C, PFCP, or GTP-U message implementation MUST follow this process before the code is considered complete:

1. **Identify the exact spec table.** For every message, locate the IE table in the relevant spec (e.g., TS 29.274 Table 7.2.1-1 for Create Session Request). This table defines the conditionality of every IE: M = Mandatory, C = Conditional, CO = Conditional Optional.

2. **Map conditionality in code.** Only IEs marked M may be validated as mandatory (rejected if absent). IEs marked C or CO must be treated as optional — their absence is not an error. A comment in the `validate()` or `Parse*()` function MUST cite the spec table it implements.

3. **Verify bit-level encoding.** For every IE with non-trivial encoding (multi-bit flags, BCD, label-length strings, 5-byte rate fields), write a unit test that encodes a known value and compares the raw wire bytes against the value computed from the spec figure. Round-trip tests (encode → decode) are not sufficient on their own because encoding and decoding bugs can cancel each other out.

4. **Verify header and routing fields.** For every response message, verify that the GTPv2-C header TEID, sequence number, and message type are set according to the spec, not inferred from the request. Specifically: the TEID in a response header is the receiver's TEID (the peer's TEID extracted from the request's F-TEID IE), not the header TEID from the received request.

5. **Add a spec-traceability comment block.** Each message file must begin with a comment citing the spec section, e.g.:
   ```go
   // Implements TS 29.274 Section 7.2.7 / Table 7.2.7-1.
   // BearerContext: C (conditional — may be absent in UE time-zone-only updates)
   // FTEID instance 0: CO (conditional optional — not required on S11)
   ```

---

## 3. External Library Choices

### 3.1 PFCP

Use:

```go
github.com/wmnsk/go-pfcp
```

Use it as the PFCP protocol encoder/decoder and message model. Do **not** let the library define the SGW architecture.

`go-pfcp` should handle:

- PFCP message structures
- IE encoding and decoding
- Association Setup Request / Response
- Heartbeat Request / Response
- Session Establishment Request / Response
- Session Modification Request / Response
- Session Deletion Request / Response
- PFCP sequence handling

VectorCore should own:

- SGW-C session state
- SGW-U session state
- PFCP transaction manager
- PFCP retransmission policy
- PDR/FAR/QER/URR/BAR lifecycle
- PFCP-to-BPF compilation
- restart recovery
- metrics
- API visibility

### 3.2 GTPv2-C

VectorCore will implement an internal GTPv2-C codec in `internal/gtpv2/`. Existing Go GTP libraries do not provide complete coverage of the required grouped IE and bearer context IE set, and the spec-compliance requirement makes patching an external library more costly than owning the codec directly. The codec will be PCAP-driven and independently testable.

Internal boundary:

```text
GTPv2-C message codec
    -> S11 procedure handler
    -> SGW session manager
    -> S5/S8-C client toward PGW
    -> PFCP session compiler
```

### 3.3 eBPF

Use Go userspace loader/control libraries such as:

```go
github.com/cilium/ebpf
```

Recommended initial dataplane attachment:

```text
TC ingress on S1-U interface
TC ingress on S5/S8-U interface
```

TC-BPF is preferred over XDP for v0/v1 because it gives easier access to skb metadata, redirects, checksum helpers, and normal Linux network integration.

---

## 4. Target Component Layout

```text
cmd/
  vectorcore-sgw-c/
    main.go
  vectorcore-sgw-u/
    main.go
  vectorcore-sgwctl/
    main.go

internal/
  config/
    config.go
    validate.go

  log/
    log.go

  gtpv2/
    codec/
    ie/
    message/
    transport/

  sgwc/
    app/
    s11/
    s5c/
    session/
    bearer/
    teid/
    pgwselect/
    pfcpclient/
    recovery/

  sgwu/
    app/
    pfcpserver/
    session/
    compiler/
    dataplane/
    counters/
    recovery/

  dataplane/
    bpf/
      loader.go
      maps.go
      programs.go
    model/
      rule.go
      counter.go
      tunnel.go

  api/
    huma/
      sgwc_routes.go
      sgwu_routes.go

  metrics/
    prometheus.go

  testutil/
    pcap.go
    gtpu.go
    pfcp.go
    gtpv2.go

ebpf/
  tc_sgw_gtpu.c
  maps.h
  common.h

configs/
  sgw-c.yaml
  sgw-u.yaml

scripts/
  dev_setup_tc.sh
  cleanup_tc.sh
  run_sgw_lab.sh

docs/
  specs.md
  interop.md
  architecture.md
  pfcp_mapping.md
  ebpf_dataplane.md
```

---

## 5. Runtime Architecture

### 5.1 SGW-C

Responsibilities:

- Listen on S11 for MME GTPv2-C.
- Create S5/S8-C sessions toward PGW-C / legacy PGW.
- Allocate SGW control TEIDs.
- Request SGW-U user-plane F-TEID allocation via the PFCP CHOOSE bit: set CHOOSE in the Create PDR F-TEID IE; SGW-U picks and returns its allocated TEID in the Session Establishment Response. SGW-C does not pre-allocate SGW-U user-plane TEIDs.
- Translate bearer/session state into PFCP PDR/FAR/QER rules.
- Maintain PFCP association to one or more SGW-U nodes.
- Handle MME-triggered and PGW-triggered bearer procedures.
- Expose session/bearer/debug APIs.

### 5.2 SGW-U

Responsibilities:

- Listen for Sxa/PFCP from SGW-C.
- Accept PFCP Association Setup.
- Accept PFCP Session Establishment / Modification / Deletion.
- Allocate local user-plane TEIDs when CHOOSE bit is set in Create PDR F-TEID IE and return them in Session Establishment Response.
- Compile PFCP PDR/FAR/QER state into compact dataplane rules.
- Program TC-BPF maps.
- Forward S1-U to S5/S8-U and S5/S8-U to S1-U.
- Maintain per-session and per-bearer counters.
- Export metrics and debug APIs.

---

## 6. eBPF Dataplane Model

### 6.1 Do Not Implement Full PFCP in BPF

PFCP is a control protocol. BPF should not interpret full PFCP semantics.

Correct model:

```text
PFCP Session Establishment
    -> SGW-U userspace validates PDR/FAR/QER
    -> SGW-U userspace compiles compact forwarding entries
    -> SGW-U writes eBPF maps
    -> TC-BPF forwards packets by TEID
```

Incorrect model:

```text
BPF parses PFCP objects
BPF evaluates complex grouped IE trees
BPF maintains PFCP session state machines
```

### 6.2 Initial BPF Rule Key

```c
typedef struct {
    __u32 local_teid;
    __u32 ingress_ifindex;
    __u8  direction;       // 1 = access_to_core, 2 = core_to_access
    __u8  pad[3];
} gtpu_rule_key_t;
```

### 6.3 Initial BPF Rule Value

```c
typedef struct {
    __u8  action;          // drop, forward, punt
    __u8  qci;
    __u16 bearer_id;

    __u32 session_id;
    __u32 counter_id;

    __u32 egress_ifindex;

    __u32 outer_src_ipv4;
    __u32 outer_dst_ipv4;
    __u32 new_teid;

    __u8  flags;
    __u8  pad[3];
} gtpu_rule_value_t;
```

### 6.4 Initial Fast Path

For a received GTP-U packet:

1. Validate IPv4 / UDP / GTP-U.
2. Check UDP destination port 2152.
3. Parse GTP-U flags and message type.
4. Accept only G-PDU in fast path for v0.
5. Extract TEID.
6. Lookup `gtpu_rule_key_t`.
7. If no rule, drop or punt based on config.
8. Rewrite outer source IP.
9. Rewrite outer destination IP.
10. Rewrite GTP-U TEID.
11. Update checksums.
12. Increment per-rule counters.
13. Redirect to egress interface.

### 6.5 Punt Path

The following packets should initially punt to userspace or bypass the BPF fast path:

- GTP-U Echo Request / Response
- GTP-U Error Indication
- End Marker
- Extension-header-heavy packets
- Unknown TEID
- Malformed GTP-U
- Non-G-PDU messages

Later, Echo and Error Indication can be handled in the SGW-U userspace control agent.

---

## 7. PFCP to BPF Mapping

### 7.1 Access-to-Core Uplink

PFCP model:

```text
PDR:
  Source Interface = Access
  Local F-TEID = SGW-U S1-U TEID

FAR:
  Apply Action = FORW
  Destination Interface = Core
  Outer Header Creation = GTP-U/UDP/IPv4
  Remote F-TEID = PGW-U S5/S8-U TEID + PGW-U IP
```

BPF map entry:

```text
key:
  local_teid = SGW-U S1-U TEID
  ingress_ifindex = S1-U interface
  direction = access_to_core

value:
  action = forward
  outer_src_ipv4 = SGW-U S5/S8-U address
  outer_dst_ipv4 = PGW-U address
  new_teid = PGW-U S5/S8-U TEID
  egress_ifindex = S5/S8-U interface
```

### 7.2 Core-to-Access Downlink

PFCP model:

```text
PDR:
  Source Interface = Core
  Local F-TEID = SGW-U S5/S8-U TEID

FAR:
  Apply Action = FORW
  Destination Interface = Access
  Outer Header Creation = GTP-U/UDP/IPv4
  Remote F-TEID = eNodeB S1-U TEID + eNodeB IP
```

BPF map entry:

```text
key:
  local_teid = SGW-U S5/S8-U TEID
  ingress_ifindex = S5/S8-U interface
  direction = core_to_access

value:
  action = forward
  outer_src_ipv4 = SGW-U S1-U address
  outer_dst_ipv4 = eNodeB S1-U address
  new_teid = eNodeB S1-U TEID
  egress_ifindex = S1-U interface
```

---

## 8. Phase Gate Process

Every phase follows this mandatory process. A phase is not complete until all four steps have been executed. If any step is skipped, the code for that phase must be rolled back and the phase restarted.

### Step 1 — Spec Review (before any code is written)

State explicitly which 3GPP specification sections govern the work in this phase. Read the relevant sections. For each message, procedure, or IE to be implemented, identify the exact table or figure that defines it. Do not start coding until this is done.

### Step 2 — Implementation

Write the code. Apply compliance rules C1–C8 (Section 14.2) throughout.

### Step 3 — Compliance Audit (after all phase code is written)

Re-read every new or changed file. Verify:
- IE conditionality matches the spec table exactly (Rule C1).
- Response header TEID set correctly from peer's F-TEID IE, not echoed from request header (Rule C4).
- Response message types are explicit constants, not computed (Rule C5).
- All non-trivial bit-field IEs have raw-wire unit tests (Rule C6).
- Inbound retransmit detection is present for any transport changes (Rule C7).
- Re-attach cleanup is handled for any session-create changes (Rule C8).

Fix every violation found before proceeding to Step 4.

### Step 4 — Console Compliance Report

Display a compliance report in this format:

```
=== Phase N — 3GPP Compliance Report ===

Specs referenced:
  TS XXXXX §X.Y.Z — [purpose]

Files changed:
  path/to/file.go — [description and spec section]

IE conditionality verified:
  MessageName — Table X.Y.Z-W — [M/C/CO assignments checked]

Compliance findings:
  PASS: [description]  OR  FIXED: [what was wrong / spec violation / correction]

Phase N: COMPLETE
```

The phase is only complete when this report has been displayed and shows no outstanding violations.

---

## 9. Phased Build Plan

## Phase 0 — Specification Baseline and Project Skeleton

### Objectives

Create the repository structure, define the supported 3GPP feature baseline, and prevent uncontrolled scope creep.

### Deliverables

- Repository skeleton.
- `docs/specs.md` with required and deferred spec sections.
- `docs/architecture.md` with SGW-C / SGW-U diagrams.
- Config schema for SGW-C and SGW-U.
- Basic logging, metrics, and build pipeline.
- Go module initialized.
- CI pipeline for unit tests and static checks.

### Required Decisions

- IPv4-only in v0.
- Default bearer only in v0.
- One MME, one PGW, one SGW-U in v0.
- No SGW relocation in v0.
- No ISR in v0.
- No S4/S12 in v0.
- No IPv6 PDN in v0.
- No PMIP in v0.

### Acceptance Criteria

- `go test ./...` passes.
- SGW-C and SGW-U binaries start with config files.
- Huma/OpenAPI endpoint exists for health/status.
- Prometheus `/metrics` exists.
- Spec coverage matrix exists.

---

## Phase 1 — GTPv2-C S11 Codec and Transport

### Objectives

Implement enough S11 GTPv2-C handling to receive and parse MME requests.

### Procedures

Initial required messages:

- Echo Request / Response
- Create Session Request
- Modify Bearer Request
- Delete Session Request
- Release Access Bearers Request

Initial required IE support:

- IMSI
- MSISDN, optional
- MEI, optional
- RAT Type
- Serving Network
- F-TEID
- APN
- PDN Type
- PAA
- Bearer Context
- EBI
- Bearer QoS
- AMBR
- Indication, partial
- Recovery
- Cause

### IE Conditionality Reference (per TS 29.274)

All message parsers must implement conditionality exactly as specified. Required references:

| Message | Spec Table | Notes |
|---|---|---|
| Create Session Request (S11) | Table 7.2.1-1 | IMSI=M, RATType=M, ServingNetwork=M, FTEID inst0=M, APN=M, PDNType=M, BearerContext=M; PGW FTEID inst1=C |
| Create Session Response (S11) | Table 7.2.2-1 | Cause=M, FTEID inst0=C, PAA=C, BearerContext=C |
| Modify Bearer Request (S11) | Table 7.2.7-1 | BearerContext=**C** (not M — absent in UE tz/RAT-only updates) |
| Delete Session Request (S11) | Table 7.2.9.1-1 | EBI=**C** (not M — absent when deleting by TEID only) |
| Release Access Bearers Request | Table 7.2.21.1-1 | All IEs are C or CO |
| Echo Request / Response | Section 7.1.1 | Recovery=M in response |

### Deliverables

- GTPv2-C UDP transport with **both** outbound retransmit (T3/N3) and inbound retransmit detection (server-side response cache per TS 29.274 Section 7.6.3).
- Message parser and encoder with spec-table comment citations in every `validate()` function.
- Transaction manager.
- S11 handler skeleton.
- PCAP-driven tests for valid/invalid messages.
- Bit-field unit tests for: ARP (PCI/PL/PVI), PLMN BCD, TBCD (IMSI/MEI), APN label-length, F-TEID CHOOSE bit, Cause IE with Offending IE embedded.

### Acceptance Criteria

- SGW-C responds correctly to S11 Echo.
- SGW-C parses Create Session Request from a real MME capture.
- SGW-C rejects malformed requests with correct cause handling.
- SGW-C accepts Modify Bearer Request **without** BearerContext (conditional IE absent — must not reject).
- SGW-C accepts Delete Session Request **without** EBI (conditional IE absent — must not reject).
- Every `validate()` function cites its TS 29.274 table in a comment.
- Inbound retransmit of Create Session Request does not create a second session.
- Unit tests verify raw wire bytes for ARP, PLMN, TBCD, and APN encoding against the spec figure, not just round-trip equality.
- Create Session Response header TEID equals the MME's S11 control TEID from the CSReq F-TEID IE (not the request header TEID).

---

## Phase 2 — SGW-C Session and Bearer State Model

### Objectives

Create the internal state model before adding S5/S8-C or PFCP behavior.

### SGW-C Role and APN Agnosticism

The SGW-C is APN-agnostic. Per TS 23.401 Section 4.7.1, APN resolution and enforcement is a PGW responsibility. The MME selects the PGW (via DNS on the APN per TS 29.303, or via HSS-provided subscription data) and communicates the selected PGW's S5/S8-C address to the SGW in the Create Session Request. The SGW:

- Receives the APN from the MME's CSReq and stores it **for logging and API observability only**.
- Forwards the APN verbatim in the S5/S8-C CSReq to the PGW.
- Never uses the APN for routing, PGW selection, policy, or enforcement.
- Never defines an APN in its own config files.

### PGW Address Origin

The PGW's S5/S8-C address is provided by the MME in the Create Session Request as F-TEID IE (instance 1), per TS 29.274 Table 7.2.1-1 and TS 23.401 Section 5.3.2.1. The SGW-C must use this address to route the S5/S8-C Create Session Request. A statically configured PGW address in `sgw-c.yaml` is permitted **only as a lab fallback** for test environments where the MME does not supply the PGW F-TEID — it is never the primary selection mechanism.

### Core Objects

```go
type SGWSession struct {
    SessionID       string
    IMSI            string
    APN             string    // from MME CSReq; stored for observability only — never used for policy
    RATType         uint8
    ServingNetwork  string
    ULI             []byte    // User Location Information — forwarded to PGW in S5/S8-C CSReq

    MMEControlFTEID FTEID
    SGWS11FTEID     FTEID

    PGWControlFTEID FTEID     // set in Phase 3 from MME-supplied PGW F-TEID (CSReq inst1)
    SGWS5CFTEID     FTEID

    UEIPv4          netip.Addr
    DefaultBearerID uint8

    Bearers         map[uint8]*Bearer
    PFCP            PFCPSessionBinding

    State           SessionState
}
```

```go
type Bearer struct {
    EBI              uint8
    QCI              uint8
    ARP              ARP

    ENBS1UFTEID      FTEID
    SGWS1UFTEID      FTEID

    PGWS5UFTEID      FTEID
    SGWS5UFTEID      FTEID

    TFT              *TFT
    State            BearerState
}
```

### Deliverables

- Session manager.
- Bearer manager.
- TEID allocator.
- Recovery/restart counter storage.
- Session state API.

### Acceptance Criteria

- Create Session Request creates a pending session.
- Modify Bearer Request updates eNodeB S1-U F-TEID.
- Delete Session Request removes the session.
- Session state is visible via API.

---

## Phase 3 — S5/S8-C Client Toward PGW

### Objectives

Allow SGW-C to create a PDN session against a PGW-C or legacy PGW.

### Required Procedures

- SGW-C sends Create Session Request to PGW.
- SGW-C receives Create Session Response from PGW.
- SGW-C sends Delete Session Request to PGW.
- SGW-C handles Delete Session Response.
- SGW-C handles PGW cause values and propagates correct S11 response.

### PGW Address Resolution (per TS 23.401 Section 5.3.2.1 and TS 29.274 Table 7.2.1-1)

The MME selects the PGW and communicates its S5/S8-C address in the Create Session Request via F-TEID IE (instance 1). The SGW-C MUST use this address to route the S5/S8-C Create Session Request. This is not optional.

A static PGW address in `configs/sgw-c.yaml` under `s5c.pgw.fallback_addr` is permitted **only as a lab fallback** for test setups where the MME does not include the PGW F-TEID. The config key must be named to make clear it is a fallback, not the primary mechanism. It must never be used if the MME supplied a PGW F-TEID in the CSReq.

### Required Behavior

On MME Create Session Request:

1. Validate S11 request per TS 29.274 Table 7.2.1-1.
2. Allocate SGW S11 control TEID.
3. Allocate SGW S5/S8-C control TEID.
4. Extract PGW S5/S8-C address from F-TEID IE (instance 1) in CSReq. If absent and fallback_addr is configured, use fallback. If both absent, reject with appropriate cause.
5. Send S5/S8-C Create Session Request to the PGW address from step 4. Forward APN verbatim from MME CSReq. Forward IMSI, MSISDN, MEI, RAT Type, Serving Network, ULI verbatim.
6. Receive PGW Create Session Response.
7. Store PGW S5/S8-C control F-TEID.
8. Store PGW S5/S8-U F-TEID (from bearer context in PGW CSResp).
9. Store UE IP from PAA IE in PGW CSResp.
10. Return S11 Create Session Response to MME with SGW F-TEIDs, PAA, and bearer context.

The Create Session Response header TEID must be the MME's S11 control TEID extracted from the CSReq Sender F-TEID IE (instance 0), per TS 29.274 Section 5.5.1.

### Deliverables

- S5/S8-C client.
- PGW address from MME CSReq F-TEID IE (instance 1) as primary; static fallback_addr as lab-only secondary.
- Control TEID mapping table.
- APN / IMSI / MSISDN / MEI / ULI forwarding from S11 CSReq to S5/S8-C CSReq.
- Cause mapping logic.
- Interop tests against Open5GS PGW-C/SMF or StarOS PGW where available.

### Acceptance Criteria

- MME Create Session triggers PGW Create Session sent to the address from MME CSReq F-TEID IE (instance 1), per Rule C3.
- PGW PAA/UE IP is returned to MME in Create Session Response.
- PGW S5/S8-C and S5/S8-U F-TEIDs are stored in session state.
- Create Session Response header TEID equals MME's S11 control TEID from CSReq F-TEID IE (instance 0), per Rule C4.
- APN forwarded verbatim from MME CSReq to PGW CSReq — not from config, per Rule C2.
- IMSI, MSISDN, MEI, RAT Type, Serving Network, ULI forwarded from S11 CSReq to S5/S8-C CSReq.
- Failure causes from PGW are propagated correctly with correct cause-value mapping.
- PCAP confirms correct wire behavior on S11 and S5/S8-C interfaces.

---

## Phase 4 — SGW-U PFCP Association Using go-pfcp

### Objectives

Create a real Sxa association between SGW-C and SGW-U.

### Required PFCP Procedures

- PFCP Association Setup Request / Response
- PFCP Association Update, optional later
- PFCP Association Release, optional later
- PFCP Heartbeat Request / Response
- Node Recovery Time Stamp handling

### SGW-C Behavior

- Discover configured SGW-U.
- Send PFCP Association Setup Request.
- Track SGW-U capabilities.
- Maintain heartbeat timer.
- Mark SGW-U unavailable after heartbeat failure.

### SGW-U Behavior

- Listen on PFCP UDP/8805.
- Respond to Association Setup Request.
- Include Node ID and Recovery Time Stamp.
- Maintain SGW-C peer state.
- Respond to heartbeats.

### Deliverables

- `internal/sgwc/pfcpclient`.
- `internal/sgwu/pfcpserver`.
- PFCP transaction logging.
- PFCP pcap capture tests.
- API endpoint for PFCP association status.

### Acceptance Criteria

- SGW-C and SGW-U establish Sxa association.
- Heartbeats work in both directions as required.
- Restart timestamp changes are detected.
- Association state visible via API and metrics.

---

## Phase 5 — PFCP Session Establishment Without eBPF

### Objectives

Build the PFCP session model first, before programming BPF.

### Required PFCP Objects

- F-SEID
- Create PDR
- Create FAR
- Create QER, minimal
- Create BAR, optional later
- PDI
- Source Interface
- F-TEID
- Outer Header Creation
- Apply Action

### Required Session Rules

For each default bearer, create two forwarding directions:

1. Access-to-Core:
   - Match SGW-U S1-U TEID.
   - Forward to PGW-U S5/S8-U TEID.

2. Core-to-Access:
   - Match SGW-U S5/S8-U TEID.
   - Forward to eNodeB S1-U TEID.

### Deliverables

- PFCP session establishment from SGW-C to SGW-U.
- SGW-U internal PDR/FAR/QER store.
- PFCP session deletion.
- PFCP session modification skeleton.
- Debug API showing PDRs/FARs/QERs.

### Acceptance Criteria

- SGW-C creates PFCP session after PGW Create Session Response.
- SGW-U stores PDR/FAR state.
- SGW-U returns successful PFCP Session Establishment Response.
- Delete Session removes PFCP session.

---

## Phase 6 — Userspace SGW-U Reference Forwarder

### Objectives

Build a simple userspace GTP-U forwarder as a correctness reference before enabling BPF.

This is not the final dataplane. It is a debugging and validation tool.

### Behavior

- Listen on UDP/2152 for S1-U and S5/S8-U.
- Parse GTP-U header.
- Lookup TEID in SGW-U internal PDR/FAR store.
- Rewrite TEID and outer peer.
- Send packet to peer.

### Deliverables

- Userspace GTP-U reference path.
- Packet counters.
- PCAP-driven forwarding tests.
- Unknown TEID handling.
- GTP-U Echo handler.

### Acceptance Criteria

- UE can pass traffic through userspace SGW-U reference mode.
- PCAP confirms correct TEID rewrite in both directions.
- Unknown TEID does not crash SGW-U.
- GTP-U Echo works.

---

## Phase 7 — TC-BPF GTP-U Fast Path

### Objectives

Move the GTP-U hot path into kernel TC-BPF.

### Implementation Steps

1. Write TC ingress program for S1-U and S5/S8-U interfaces.
2. Parse Ethernet/IP/UDP/GTP-U.
3. Validate G-PDU.
4. Lookup local TEID and ingress interface in BPF map.
5. Rewrite destination IP, source IP, and TEID.
6. Update IP/UDP checksums.
7. Increment counter map.
8. Redirect to egress interface.
9. Punt unsupported packets to userspace or pass/drop based on policy.

### Deliverables

- `ebpf/tc_sgw_gtpu.c`.
- BPF map definitions.
- Go BPF loader.
- BPF attach/detach tooling.
- BPF rule compiler from PFCP PDR/FAR.
- Counter reader.
- Fallback mode.

### Acceptance Criteria

- SGW-U programs BPF entries after PFCP session establishment.
- Uplink traffic is forwarded by BPF.
- Downlink traffic is forwarded by BPF.
- Counters increment per rule.
- Userspace reference path can be disabled/enabled by config.
- Throughput exceeds userspace reference path.

---

## Phase 8 — End-to-End Default Bearer Attach

### Objectives

Complete the first real EPC attach through VectorCore SGW.

### Expected Flow

```text
UE -> eNodeB -> MME
MME -> SGW-C: Create Session Request
SGW-C -> PGW: Create Session Request
PGW -> SGW-C: Create Session Response
SGW-C -> SGW-U: PFCP Session Establishment Request
SGW-U -> SGW-C: PFCP Session Establishment Response
SGW-C -> MME: Create Session Response
MME -> SGW-C: Modify Bearer Request with eNodeB S1-U F-TEID
SGW-C -> SGW-U: PFCP Session Modification Request
SGW-U -> SGW-C: PFCP Session Modification Response
SGW-C -> MME: Modify Bearer Response
UE traffic flows through SGW-U eBPF
```

### Deliverables

- Full attach support.
- Modify Bearer handling for eNodeB F-TEID update.
- PFCP Session Modification support.
- End-to-end traffic validation.
- Capture templates for S11, S5/S8-C, Sxa, S1-U, S5/S8-U.

### Acceptance Criteria

- UE attaches successfully.
- UE receives IP address from PGW.
- UE passes ICMP/DNS/TCP traffic.
- S1-U and S5/S8-U TEIDs are correct in pcaps.
- SGW-C API shows session state.
- SGW-U API shows PFCP/BPF rule state.

---

## Phase 9 — Dedicated Bearers and QoS Metadata

### Objectives

Add dedicated bearer procedures and preserve QCI/ARP metadata through control plane and dataplane.

### Required Procedures

- Create Bearer Request / Response
- Update Bearer Request / Response
- Delete Bearer Request / Response
- Bearer Resource Command, later optional

### Required Data

- EBI
- QCI
- ARP
- GBR / MBR if present
- TFT packet filters
- Charging ID, if present

### BPF Behavior

For this phase, BPF should still primarily match TEID. TFT/SDF filters should be compiled only when absolutely required.

Recommended initial model:

```text
bearer TEID decides forwarding path
QCI/ARP stored as metadata
per-bearer counters exposed
rate enforcement deferred
```

### Deliverables

- Dedicated bearer state machine.
- Additional PDR/FAR/QER creation per bearer.
- Per-bearer counters.
- API view by IMSI, APN, EBI, QCI.

### Acceptance Criteria

- PGW-triggered dedicated bearer is created.
- SGW-C sends correct bearer messages to MME.
- SGW-U receives updated PFCP state.
- BPF maps contain separate bearer rules.
- Deleting a dedicated bearer removes only that bearer rules.

---

## Phase 10 — GTP-U Control Messages and Robustness

### Objectives

Handle non-G-PDU GTP-U behavior correctly.

### Required Items

- Echo Request / Response
- Error Indication
- End Marker
- Unknown TEID behavior
- Peer restart behavior
- Recovery IE handling where applicable

### Deliverables

- Userspace GTP-U control-message handler.
- BPF punt path for non-G-PDU messages.
- Error Indication generation for invalid tunnel state.
- Restart/recovery tests.

### Acceptance Criteria

- SGW-U responds to GTP-U Echo.
- Unknown TEID is handled predictably.
- End Marker is not incorrectly forwarded as user traffic.
- Peer restart event triggers safe session cleanup or revalidation.

---

## Phase 11 — CUPS Recovery and Failure Handling

### Objectives

Make SGW-C / SGW-U behavior safe across process restarts and PFCP failures.

### Required Behavior

- SGW-C detects SGW-U PFCP association loss.
- SGW-C detects SGW-U Recovery Time Stamp change.
- SGW-U clears stale BPF maps on restart.
- SGW-C can re-establish PFCP sessions when appropriate.
- Active sessions are failed cleanly if re-establishment is not possible.

### Deliverables

- PFCP recovery manager.
- BPF map reconciliation.
- Session replay logic, optional.
- Failure-state API.
- Alert metrics.

### Acceptance Criteria

- Restarting SGW-U does not leave stale dataplane forwarding entries.
- SGW-C reports SGW-U unavailable.
- Sessions recover or fail deterministically.
- No ghost TEIDs remain active after restart.

---

## Phase 12 — Multi-SGW-U and Selection

### Objectives

Support more than one SGW-U behind one SGW-C.

### Selection Inputs

- Static configured SGW-U priority.
- SGW-U health.
- Interface/address reachability.
- Tracking area or eNodeB IP, optional.
- Load/capacity, later.

### Deliverables

- SGW-U registry.
- SGW-U selection policy.
- Per-SGW-U capacity/health metrics.
- Session pinning to selected SGW-U.

### Acceptance Criteria

- SGW-C can maintain PFCP association with multiple SGW-U nodes.
- New sessions are assigned to available SGW-U.
- Existing sessions remain pinned.
- Failure of one SGW-U does not break sessions on another SGW-U.

---

## Phase 13 — Interop Hardening

### Objectives

Validate against real EPC components and produce repeatable interop results.

### Target Interop Matrix

| Component | Role | Purpose |
|---|---|---|
| Open5GS MME | S11 peer | Baseline open-source MME interop |
| Open5GS PGW-C/SMF + UPF | S5/S8 peer | Baseline PGW interop |
| StarOS PGW | S5/S8 peer | Carrier-grade PGW interop if available |
| srsRAN eNodeB/eNB sim | S1-U traffic source | Lab attach testing |
| Real eNodeB | S1-U traffic source | Field/lab validation |

### Deliverables

- Interop test scripts.
- PCAP examples.
- Known-good configs.
- Cause-code matrix.
- Regression tests from captured messages.

### Acceptance Criteria

- Attach works with at least one open-source MME/PGW stack.
- Attach works with target lab PGW.
- PCAP validates correct S11/S5/S8-C/Sxa behavior.
- Regression tests prevent breaking known interop cases.

---

## Phase 14 — Performance Testing and Optimization

### Objectives

Prove that the eBPF dataplane materially outperforms userspace GTP-U forwarding.

### Test Types

- Single UE throughput.
- Multi-UE throughput.
- Small-packet PPS.
- IMS/VoLTE-like RTP packet rate.
- Mixed TCP/UDP traffic.
- Long-duration stability test.
- Attach/detach churn.
- Dedicated bearer churn.

### Metrics

- Gbps
- Packets per second
- CPU per Gbps
- CPU per Mpps
- p50/p95/p99 latency
- jitter
- drops
- BPF map lookup failures
- unknown TEID rate
- PFCP session modification latency

### Tools

- iperf3
- trafgen / pktgen
- tc counters
- bpftool
- perf
- tcpdump
- Prometheus/Grafana

### Acceptance Criteria

- BPF dataplane outperforms userspace reference path.
- No sustained packet drops at target throughput.
- CPU scales predictably with packet rate.
- No BPF verifier instability across supported kernels.

---

## Phase 15 — Production-Quality Controls

### Objectives

Add operational controls required for stable lab/field operation.

### Deliverables

- systemd unit files.
- Config validation command.
- Dry-run mode.
- BPF attach status command.
- Session dump command.
- PFCP peer dump command.
- TEID lookup command.
- Prometheus metrics.
- Structured logs.
- Pcap-on-error option.

### Acceptance Criteria

- Operator can inspect sessions by IMSI, APN, TEID, EBI, QCI.
- Operator can safely reload config where supported.
- Operator can clean stale BPF state.
- Logs are useful during interop debugging.

---

## 9. Minimal v0 Feature Set

The first truly useful version should support:

```text
S11:
  Echo
  Create Session
  Modify Bearer
  Delete Session
  Release Access Bearers

S5/S8-C:
  Echo
  Create Session
  Delete Session

Sxa/PFCP:
  Association Setup
  Heartbeat
  Session Establishment
  Session Modification
  Session Deletion

S1-U / S5/S8-U:
  G-PDU forwarding
  Echo in userspace
  Unknown TEID handling

Dataplane:
  TC-BPF GTP-U TEID rewrite and redirect
  per-rule counters

Bearer support:
  default bearer only
  IPv4 PDN only
```

---

## 10. Deferred Features

Do not include in v0:

- IPv6 PDN
- IPv4v6 PDN
- SGW relocation
- ISR
- S4 SGSN support
- S12 direct tunnel
- PMIP
- full dynamic DNS selection
- charging integration
- LI hooks
- multi-PLMN roaming
- rate enforcement in BPF
- complex TFT/SDF filter chains in BPF
- AF_XDP / DPDK

---

## 11. Test Gates

Each gate MUST include a spec traceability note identifying the relevant 3GPP procedure, message, and required IEs. Passing an interop test alone is not enough unless the wire behavior is also verified against the applicable 3GPP requirement.

### Gate A — Control Plane Parse

- SGW-C receives and parses MME Create Session Request.
- Required IEs validated.
- Bad messages rejected safely.

### Gate B — PGW Session

- SGW-C creates S5/S8-C session toward PGW.
- UE IP is received.
- PGW S5/S8-U F-TEID is stored.

### Gate C — PFCP Session

- SGW-C establishes PFCP session on SGW-U.
- SGW-U stores PDR/FAR/QER.
- PFCP deletion works.

### Gate D — Userspace Forwarding

- UE traffic passes through userspace SGW-U reference path.
- PCAP confirms TEID rewrite.

### Gate E — BPF Forwarding

- UE traffic passes through TC-BPF path.
- Userspace forwarding disabled.
- Counters increment.

### Gate F — End-to-End Attach

- Real UE attach succeeds.
- UE passes traffic.
- Detach cleans S11, S5/S8-C, PFCP, and BPF state.

### Gate G — Dedicated Bearer

- PGW-triggered dedicated bearer works.
- Per-bearer TEIDs and counters work.

---

## 12. Initial Config Example

### `configs/sgw-c.yaml`

```yaml
sgwc:
  node_id: "sgw-c-1"
  plmn:
    mcc: "311"
    mnc: "435"

s11:
  listen: "10.90.250.10:2123"

s5c:
  local_addr: "10.90.250.10"
  pgw:
    # fallback_addr is used ONLY if the MME does not supply PGW F-TEID in CSReq.
    # Primary PGW address MUST come from F-TEID IE (instance 1) in the MME Create Session Request.
    # Per TS 23.401 Section 5.3.2.1 and TS 29.274 Table 7.2.1-1.
    fallback_addr: "192.168.105.97:2123"
    # No apn field. SGW is APN-agnostic. APN comes from MME CSReq and is forwarded verbatim.

pfcp:
  local_addr: "10.90.250.10:8805"
  sgwu:
    - name: "sgw-u-1"
      node_id: "sgw-u-1"
      addr: "10.90.250.11:8805"

api:
  listen: "0.0.0.0:8080"

metrics:
  listen: "0.0.0.0:9090"
```

### `configs/sgw-u.yaml`

```yaml
sgwu:
  node_id: "sgw-u-1"

pfcp:
  listen: "10.90.250.11:8805"
  allowed_sgwc:
    - "10.90.250.10"

gtpu:
  access:
    ifname: "ens1f0"
    local_addr: "10.90.251.11"
  core:
    ifname: "ens1f1"
    local_addr: "10.90.252.11"

dataplane:
  mode: "tc-bpf"
  unknown_teid: "punt"
  attach_on_start: true
  cleanup_on_exit: true

api:
  listen: "0.0.0.0:8081"

metrics:
  listen: "0.0.0.0:9091"
```

---

## 13. Recommended Development Order

Build in this exact order:

1. SGW-C GTPv2-C parser and S11 Echo.
2. SGW-C session model.
3. S11 Create Session parsing.
4. S5/S8-C Create Session toward PGW.
5. S11 Create Session Response toward MME.
6. PFCP Association between SGW-C and SGW-U.
7. PFCP Session Establishment from SGW-C to SGW-U.
8. Userspace SGW-U reference forwarder.
9. S11 Modify Bearer and PFCP Session Modification.
10. End-to-end default bearer attach in userspace mode.
11. TC-BPF dataplane.
12. End-to-end default bearer attach in BPF mode.
13. Dedicated bearer support.
14. Recovery and robustness.
15. Multi-SGW-U.
16. Performance optimization.

---

## 14. Engineering Rules

### 14.1 General

- Any setting, parameter, or behavior not explicitly defined elsewhere in this plan defaults to a YAML configuration value sourced from the appropriate file in `configs/`. No hard-coded fallbacks; add a config key, document it, and validate it at startup.
- The `vectorcore-epdg_ipsec` project at `/usr/src/vectorcore-epdg_ipsec` is available as a read-only structural reference for BPF loader patterns (`internal/gtpu/`) and GTP-U header handling. It is a reference only — 3GPP specifications are the sole authority on correct behavior. Never copy behavior from the reference that is not traceable to a spec requirement.
- `vectorcore-sgwctl` is a CLI client that communicates exclusively with the SGW-C and SGW-U REST APIs over HTTP. It does not use any direct socket, shared memory, or private control protocol. Every operator action available in the CLI must be reachable via the Huma API, so that scripts, dashboards, and other tools can use the same interface.
- The Makefile must follow the layout established in `vectorcore-epdg_ipsec/Makefile`: explicit GOCACHE/GOMODCACHE env vars pointing to `/tmp/vectorcore-sgw-*`, a GOENV wrapper variable, VERSION and BUILD_DATE injected via LDFLAGS, `build` depending on `generate` (required for BPF object generation), and `install` placing binaries under `/opt/vectorcore/sgw/bin/` and config under `/etc/vectorcore/sgw/`. For the SGW project, build and install targets must cover both `sgw-c` and `sgw-u` binaries and the `sgwctl` tool.
- Build S11, S5/S8-C, Sxa, S1-U, and S5/S8-U to 3GPP specs within the declared feature scope.
- Do not treat Open5GS, StarOS, or any vendor behavior as the specification authority.
- Keep SGW-C and SGW-U as separate binaries from the start.
- Keep PFCP mandatory for SGW-C to SGW-U; do not use private control protocol as the primary path.
- Keep BPF map entries compact.
- Keep full PFCP objects in userspace.
- Keep userspace GTP-U reference path for debugging.
- Do not optimize before pcaps prove correctness.
- Every control-plane procedure must have a pcap-based regression test.
- Every BPF rule must be traceable back to SGW session, bearer, PDR, and FAR.
- Unknown TEID must never crash the SGW-U.
- Deleting a bearer must remove BPF rules immediately.
- Deleting a session must remove all related BPF rules.

### 14.2 3GPP Spec Compliance Rules (added after Phase 1/2 compliance audit)

These rules are binding. They exist because specific violations of each rule were found in Phase 1/2 code and are documented in `docs/3gpp-compliance-audit.md`.

**IE Conditionality — Rule C1**

Every GTPv2-C, PFCP, or GTP-U message implementation must reference its specific spec IE table. Conditionality must be implemented exactly:
- M (Mandatory): absence is an error; reject with `CauseMandatoryIEMissing`.
- C (Conditional): absence is not an error; apply context-dependent logic.
- CO (Conditional Optional): absence is not an error; ignore if absent.

The `validate()` function for each message MUST include a comment citing the spec table, e.g.:
```go
// Implements TS 29.274 Table 7.2.7-1.
// BearerContext instance 0: C — conditional; may be absent.
```

**SGW APN Agnosticism — Rule C2**

The SGW-C does not define, select, validate, or enforce APNs. No `apn` field may appear in the SGW-C config struct or config file. APN received from the MME in a Create Session Request is stored on the session for logging and API observability only. It is forwarded verbatim to the PGW in the S5/S8-C Create Session Request. It is never used for routing, selection, or policy decisions within the SGW-C.

**PGW Address From MME — Rule C3**

The SGW-C determines the PGW's S5/S8-C address from the Sender F-TEID IE (instance 1) in the received Create Session Request from the MME, per TS 29.274 Table 7.2.1-1 and TS 23.401 Section 5.3.2.1. A statically configured fallback address (`s5c.pgw.fallback_addr`) is permitted only for lab environments and must never override a PGW F-TEID that was provided by the MME.

**GTPv2-C Response Header TEID — Rule C4**

Per TS 29.274 Section 5.5.1, the TEID in a GTPv2-C response message header must be the TEID of the **receiver** of that response — i.e., the peer's control TEID, extracted from the Sender F-TEID IE in the received request. It is NOT the TEID from the received request's GTP header. Specifically:
- Create Session Response → header TEID = MME's S11 control TEID (from CSReq F-TEID IE instance 0).
- For subsequent messages (MBResp, DSResp, RABResp) → header TEID = value from request GTP header (which the MME correctly set to the SGW's TEID). This is the normal case and works as expected.
- The Create Session Response is the critical case because the initial CSReq arrives with header TEID=0 (no SGW TEID assigned yet).

**Response Message Type Mapping — Rule C5**

Response message types MUST be set from an explicit constant or mapping, never computed arithmetically from the request type (e.g., `msgType + 1` is forbidden). Each response type is defined in TS 29.274 Table 6.1-1.

**Bit-Field Encoding Verification — Rule C6**

For every IE with non-trivial bit-level encoding (ARP flags, PLMN BCD, TBCD, APN label-length, F-TEID CHOOSE bit, multi-byte rate values), the implementation must include a unit test that:
1. Encodes a known input value.
2. Compares the raw output bytes byte-by-byte against the expected value computed from the spec figure.
Round-trip tests (encode → decode → compare) are **not** sufficient and do not replace this requirement.

**Inbound Retransmit Detection — Rule C7**

The GTPv2-C transport layer must implement server-side retransmit detection per TS 29.274 Section 7.6.3. When an inbound request arrives with a sequence number and source address matching a recently processed request, the transport must resend the cached response without re-executing the procedure handler. The response cache must be maintained per (source address, sequence number) tuple and expired after a reasonable hold time (minimum: T3 × N3 of the peer).

**Re-attach Session Cleanup — Rule C8**

When a Create Session Request is received for an IMSI that already has an active session, the SGW-C must either:
- Tear down the existing session first (implicit detach), then process the new CSReq; or
- Reject the CSReq with an appropriate cause if the existing session cannot be removed cleanly.
Silent IMSI index replacement without cleaning up the old session is not acceptable — it leaks TEIDs and session state.

---

## 15. Suggested Milestone Names

| Milestone | Name | Result |
|---|---|---|
| M0 | Skeleton | binaries, config, APIs, metrics |
| M1 | S11 Listener | SGW-C parses MME messages |
| M2 | PGW Bridge | SGW-C creates PGW sessions |
| M3 | PFCP Link | SGW-C and SGW-U associate over Sxa |
| M4 | PFCP Sessions | PDR/FAR state reaches SGW-U |
| M5 | Userspace Data | traffic passes through reference path |
| M6 | BPF Data | traffic passes through TC-BPF path |
| M7 | Real Attach | real UE attach and data works |
| M8 | Bearers | dedicated bearers work |
| M9 | Recovery | restart/failure behavior safe |
| M10 | Scale | performance and multi-SGW-U |

---

## 16. Final Target State

The final intended architecture is:

```text
                    +----------------------+
                    |        MME           |
                    +----------+-----------+
                               |
                               | S11 / GTPv2-C
                               |
                    +----------v-----------+
                    |  VectorCore SGW-C    |
                    |----------------------|
                    | S11 handler          |
                    | S5/S8-C client       |
                    | session manager      |
                    | bearer manager       |
                    | PFCP/Sxa controller  |
                    +----+-------------+---+
                         |             |
            S5/S8-C      |             | Sxa / PFCP
                         |             |
        +----------------v--+       +--v-------------------+
        | PGW-C / legacy PGW |       | VectorCore SGW-U     |
        +-------------------+       |----------------------|
                                    | PFCP server          |
                                    | PDR/FAR compiler     |
                                    | BPF map programmer   |
                                    | TC-BPF GTP-U path    |
                                    +----+------------+----+
                                         |            |
                                  S1-U   |            | S5/S8-U
                                         |            |
                                  +------v--+      +--v------+
                                  | eNodeB  |      | PGW-U   |
                                  +---------+      +---------+
```

This gives VectorCore a standards-aligned EPC SGW with:

- real CUPS split,
- Sxa/PFCP control using Go,
- eBPF GTP-U forwarding,
- 3GPP-spec-targeted control semantics,
- higher-performance eBPF dataplane architecture,
- clean path to dedicated bearers and multi-SGW-U scaling.

---

## 17. Reference Links

- 3GPP CUPS overview: https://www.3gpp.org/news-events/3gpp-news/cups
- ETSI TS 123 214: https://www.etsi.org/deliver/etsi_ts/123200_123299/123214/
- 3GPP TS 29.244: https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=3111
- 3GPP TS 29.274: https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=1691
- 3GPP TS 29.281: https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=1696
- go-pfcp: https://github.com/wmnsk/go-pfcp
- Open5GS: https://github.com/open5gs/open5gs

