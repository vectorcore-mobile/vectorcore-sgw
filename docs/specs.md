# VectorCore SGW — Specification Coverage Matrix

This document tracks the 3GPP specification coverage for VectorCore SGW.
Each feature is marked **Supported**, **Partial**, or **Deferred**.

## Reference Specifications

| Spec | Title | Role |
|---|---|---|
| TS 23.401 | LTE/EPC Architecture | EPC attach, default bearer, dedicated bearer, SGW role |
| TS 23.214 | EPC CUPS Architecture | SGW-C / SGW-U split, Sxa behavior |
| TS 29.274 | GTPv2-C | S11 and S5/S8-C procedures |
| TS 29.244 | PFCP / Sxa | PFCP messages, PDR/FAR/QER/URR/BAR rules |
| TS 29.281 | GTP-U | G-PDU forwarding, TEID, Echo, Error Indication |
| TS 23.203 | QoS | QCI, ARP, GBR/MBR |

---

## S11 Interface (TS 29.274)

| Message | Status | Notes |
|---|---|---|
| Echo Request / Response | Supported | Phase 1 — with Recovery IE |
| Create Session Request / Response | Supported | Phase 3 — S11↔S5/S8-C relay; PFCP user-plane deferred (Phase 5) |
| Modify Bearer Request / Response | Supported | Phase 3 — eNodeB S1-U FTEID update; SGW-U programming deferred (Phase 5) |
| Delete Session Request / Response | Supported | Phase 3 — S5/S8-C relay with cause propagation |
| Release Access Bearers Request / Response | Supported | Phase 3 — eNodeB FTEID release; PFCP update deferred (Phase 5) |
| Create Bearer Request / Response | Deferred | Phase 9 |
| Update Bearer Request / Response | Deferred | Phase 9 |
| Delete Bearer Request / Response | Deferred | Phase 9 |
| Downlink Data Notification | Deferred | Post-v0 |
| Change Notification | Deferred | Post-v0 |
| Suspend Notification | Deferred | Post-v0 |
| Resume Notification | Deferred | Post-v0 |

---

## S5/S8-C Interface (TS 29.274)

| Message | Status | Notes |
|---|---|---|
| Echo Request / Response | Deferred | Phase 6 |
| Create Session Request / Response | Supported | Phase 3 — SGW-C→PGW relay |
| Delete Session Request / Response | Supported | Phase 3 — with cause propagation |
| Modify Bearer Request / Response | Deferred | Phase 6 |
| Create Bearer Request / Response | Deferred | Phase 9 |
| Update Bearer Request / Response | Deferred | Phase 9 |
| Delete Bearer Request / Response | Deferred | Phase 9 |

---

## Sxa / PFCP Interface (TS 29.244, TS 23.214)

| Procedure | Status | Notes |
|---|---|---|
| Association Setup | Supported | Phase 4 — SGW-C→SGW-U with Node ID keying |
| Association Release | Deferred | Phase 6 |
| Heartbeat | Supported | Phase 4 — with mandatory Recovery TS enforcement |
| Session Establishment | Deferred | Phase 5 |
| Session Modification | Deferred | Phase 5 |
| Session Deletion | Deferred | Phase 5 |
| Session Report | Deferred | Phase 10 |

---

## S1-U / S5/S8-U GTP-U (TS 29.281)

| Feature | Status | Notes |
|---|---|---|
| G-PDU forwarding | Deferred | Phase 6 (userspace), Phase 7 (BPF) |
| Echo Request / Response | Deferred | Phase 6 |
| Error Indication | Deferred | Phase 10 |
| End Marker | Deferred | Phase 10 |
| Unknown TEID handling | Deferred | Phase 6 |
| Extension header passthrough | Deferred | Phase 10 |

---

## PDR/FAR/QER/URR/BAR (TS 29.244)

| Object | Status | Notes |
|---|---|---|
| PDR (Packet Detection Rule) | Deferred | Phase 5 |
| FAR (Forwarding Action Rule) | Deferred | Phase 5 |
| QER (QoS Enforcement Rule) — minimal | Deferred | Phase 5 |
| URR (Usage Reporting Rule) | Deferred | Post-v0 |
| BAR (Buffering Action Rule) | Deferred | Post-v0 |

---

## Explicitly Deferred Features (v0 Non-Scope)

These features are out of scope for v0. Each deferred feature must remain documented
here rather than partially implemented.

| Feature | Reason |
|---|---|
| IPv6 PDN | v0 is IPv4 only |
| IPv4v6 PDN | v0 is IPv4 only |
| SGW relocation | Post-v0 |
| ISR (Idle-mode Signalling Reduction) | Post-v0 |
| S4 SGSN support | Post-v0 |
| S12 direct tunnel | Post-v0 |
| PMIP | Post-v0 |
| Dynamic DNS PGW selection (TS 29.303) | Post-v0 |
| Charging integration | Post-v0 |
| Lawful Intercept hooks | Post-v0 |
| Multi-PLMN roaming | Post-v0 |
| Rate enforcement in BPF | Phase 9+ |
| Complex TFT/SDF filter chains in BPF | Phase 9+ |
| AF_XDP / DPDK dataplane | Post-v0 |
| Dedicated bearers | Phase 9 |
