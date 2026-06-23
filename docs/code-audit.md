# VectorCore SGW Code Audit

Date: 2026-06-20  
Scope: current repository snapshot; review only, no implementation changes  
Target: 3GPP Release 15, as declared by the project

## Executive summary

The review found 13 actionable issues:

| Severity | Count |
|---|---:|
| Critical | 1 |
| High | 6 |
| Medium | 6 |

The most important risks are:

1. PFCP success responses are sent even when BPF rule installation, update, or removal fails.
2. PFCP peer restart cleanup removes in-memory sessions but leaves active BPF forwarding rules.
3. The default `tc-bpf` mode has no GTP-U signalling handler, so Echo, Error Indication, End Marker, and extension-header handling are effectively absent.
4. The BPF parser assumes a fixed 20-byte IPv4 header and does not reject fragments, which can make it read or rewrite the wrong bytes.
5. Management APIs expose IMSIs and tunnel identifiers without authentication and use HTTP servers without resource-control timeouts.

This is a work in progress. Explicitly deferred or obviously skeletal features were not treated as defects unless the running program advertises or accepts them as operational. Examples ignored as incomplete include `vectorcore-sgwctl`, charging, URR/BAR support, IPv6 PDN support, and unsupported mobility procedures. The report does flag incomplete behavior when the default runtime path reports readiness or protocol success despite the missing behavior.

## Specification set

The following local copies are the verification sources used by this audit:

| Specification | Local file | Version |
|---|---|---|
| 3GPP TS 23.214 | `docs/specs/23214-f50.doc` and source archive `23214-f50.zip` | V15.5.0 |
| 3GPP TS 23.401 | `docs/specs/23401-fd0.docx` and source archive `23401-fd0.zip` | V15.13.0 |
| 3GPP TS 29.244 | `docs/specs/29244-fa0.docx` | V15.10.0 |
| 3GPP TS 29.274 | `docs/specs/29274-f90.docx` | V15.9.0 |
| 3GPP TS 29.281 | `docs/specs/29281-f70.docx` and source archive `29281-f70.zip` | V15.7.0 |

The TS 23.214 and TS 23.401 archives were downloaded from the official 3GPP archive during this audit. Existing TS 29.244, 29.274, and 29.281 files were retained.

## Findings

### AUD-01 — Critical — PFCP reports success when dataplane programming failed

**Evidence**

- `internal/sgwu/pfcpserver/server.go:541-566` logs `InstallSession` failure but still returns `CauseRequestAccepted`.
- `internal/sgwu/pfcpserver/server.go:788-804` logs `UpdateSession` failure but still returns `CauseRequestAccepted`.
- `internal/sgwu/pfcpserver/server.go:894-914` logs `RemoveSession` failure, deletes the in-memory session, and returns `CauseRequestAccepted`.

**Impact**

The SGW-C believes the PFCP operation succeeded while the SGW-U may have missing, stale, or partially updated forwarding rules. This can cause traffic loss, forwarding to an old subscriber tunnel, or cross-session leakage after TEID reuse.

**3GPP reference**

- TS 29.244 clause 6.3.2.3: if a rule cannot be stored or applied, the UP function returns an error, discards the received rules, and does not create the PFCP session context.
- TS 29.244 clause 6.3.3.3: a failed session modification must not be partially applied.
- TS 29.244 clause 7.5.6: Session Deletion Response acceptance means the session and associated rules were deleted successfully.
- TS 29.244 clause 5.2.1: deleting a PFCP session deletes its context and associated non-preconfigured rules.

**Recommended fix**

Make PFCP state and BPF state transactional:

- Establishment: install all BPF rules before committing the session; on any failure, remove any rules already installed, release allocated TEIDs/SEIDs, and return `Rule creation/modification Failure`.
- Modification: build a copy of the session, program the complete new ruleset, then atomically replace stored state; roll back BPF changes on failure.
- Deletion: do not return acceptance or delete the only recovery metadata until all rules are removed. Return an appropriate failure cause and retain/retry cleanup.

### AUD-02 — High — PFCP restart invalidation leaves stale BPF forwarding rules

**Evidence**

- `internal/sgwu/pfcpserver/server.go:279-286` calls only `DeleteByCPNodeKey` when a changed Recovery Time Stamp is detected.
- `internal/sgwu/session/store.go:157-173` removes map entries but does not return sessions for dataplane cleanup.
- BPF cleanup is otherwise performed only through `BPFRuleInstaller.RemoveSession`.

**Impact**

After an SGW-C restart, the userspace store no longer owns the old sessions, but the kernel can continue forwarding their TEIDs indefinitely. A later TEID collision can route traffic according to stale subscriber state.

**3GPP reference**

- TS 29.244 clause 5.2.1 and Recovery Time Stamp IE clause 8.2.65: a changed recovery timestamp indicates a restarted PFCP entity and lost peer state.
- TS 29.244 clause 5.2.1: deletion of a PFCP session removes its context and associated rules.

**Recommended fix**

Have restart reconciliation obtain a snapshot of every affected session, call `RemoveSession` for each, and only then remove store entries. If cleanup fails, quarantine the peer/session, reject new session establishment for colliding TEIDs, and retry removal.

### AUD-03 — High — Default TC-BPF mode has no GTP-U signalling path

**Evidence**

- `cmd/vectorcore-sgw-u/main.go:95-127` starts only the BPF dataplane in `tc-bpf` mode.
- The userspace GTP-U socket and `EndMarkerSender` are created only in `userspace` mode at lines 129-148.
- `ebpf/tc_sgw_gtpu.c:134-147` and line 159 return `TC_ACT_OK` for signalling, extension headers, and unknown TEIDs, described as “punt to userspace,” but no GTP-U userspace listener exists in this mode.

**Impact**

In the default configuration, Echo Request/Response, Error Indication, End Marker, unknown-TEID handling, and extension-header handling are not processed by this program. PFCP-triggered tunnel switches also cannot send End Markers.

**3GPP reference**

- TS 29.281 clauses 7.2.1 and 7.2.2: GTP-U Echo procedures.
- TS 29.281 clause 7.3.1: unknown non-zero TEID requires discard plus Error Indication.
- TS 29.281 clause 7.3.2: End Marker behavior, including SGW tunnel switching.
- TS 29.281 clause 5.2.1: required handling rules for extension headers.

**Recommended fix**

Run a UDP/2152 signalling/control listener in both dataplane modes. The BPF path should redirect or clone punt traffic to that listener using a defined mechanism, not merely return `TC_ACT_OK`. Wire the listener as `EndMarkerSender` in BPF mode and test Echo, unknown TEID, extension headers, and handover End Marker behavior end to end.

### AUD-04 — High — BPF parser uses fixed offsets and can misparse IPv4 options or fragments

**Evidence**

- `ebpf/tc_sgw_gtpu.c:37-38` fixes the GTP-U offset at Ethernet + 20-byte IPv4 + UDP.
- Lines 106-109 construct UDP and GTP pointers without checking `ip->ihl`.
- There is no IPv4 fragment check before interpreting UDP/GTP-U headers.
- UDP length, IP total length, and GTP-U declared length are not validated before rewrite.

**Impact**

IPv4 options shift the UDP/GTP-U headers, so ordinary bytes can be interpreted as ports, flags, or TEIDs. Non-initial fragments do not contain a UDP header but are parsed as though they do. Malformed packets can therefore hit incorrect rules or have unrelated bytes rewritten.

**3GPP reference**

- TS 29.281 clause 4.3.2 requires receiving GTP-U endpoints to reassemble outer IP fragments according to the applicable IP specification.
- TS 29.281 clause 5.1 defines the GTP-U header and Length field.

**Recommended fix**

Use `ip->ihl * 4` after validating `ihl >= 5` and bounds-check every derived offset. Punt fragments to the kernel/userspace reassembly path before UDP parsing. Verify IPv4 total length, UDP length, GTP-U minimum size, and `8 + GTP Length <= UDP payload length`. Add BPF tests for IP options, first/non-first fragments, truncation, and inconsistent lengths.

### AUD-05 — High — GTP-U tunnel lookup does not authenticate the expected peer

**Evidence**

- `internal/sgwu/session/store.go:179-193` matches userspace traffic only by TEID.
- `ebpf/tc_sgw_gtpu.c:150-159` matches only TEID and ingress interface.
- `internal/sgwu/session/store.go:49-75` allocates predictable sequential TEIDs.

**Impact**

Any host able to send packets on the user-plane network can inject traffic into a known or guessed TEID. Sequential allocation substantially reduces the effort required to guess active TEIDs. The ingress interface prevents cross-side confusion but does not verify the eNodeB or PGW peer.

**Recommended fix**

Include expected outer source address, and where applicable UDP source port, in PDR state and BPF lookup/validation. Use cryptographically random non-zero TEIDs with collision detection. Enforce network ACLs and anti-spoofing at the interface/firewall layer. This is defense in depth; TEIDs must not be treated as authentication secrets.

### AUD-06 — High — Subscriber management API is unauthenticated and exposed on all interfaces

**Evidence**

- `internal/api/sgwc_routes.go:45-73` exposes session lists and individual sessions without authentication.
- The response includes IMSI, APN, serving network, and control-plane TEIDs at lines 14-27 and 76-89.
- Defaults and sample configuration bind APIs to `0.0.0.0` (`internal/config/sgwc/config.go:103`, `configs/sgw-c.yaml:30-31`).
- No TLS or authorization middleware is configured in `internal/api/server.go`.

**Impact**

Any reachable client can enumerate subscriber identifiers and control-plane topology. This is sensitive telecom metadata and can aid targeted packet injection or operational reconnaissance.

**Recommended fix**

Default the API to loopback or a dedicated management address. Require authenticated, authorized access, preferably mTLS plus role-based authorization. Redact IMSI and TEIDs from list views unless explicitly requested by a privileged operator. Put metrics behind the same management-plane controls where feasible.

### AUD-07 — High — Shared session pointers escape locks and are concurrently mutated

**Evidence**

- `internal/sgwu/session/store.go:101-112` and `179-193` return internal pointers after releasing `RLock`.
- `internal/sgwu/pfcpserver/server.go:730-779` mutates `sess.FARs` directly while the GTP-U forwarder and BPF compiler may read the same slices.
- `internal/sgwc/session/session.go:115-126` returns a bearer pointer under a lock, then callers mutate it after the lock is released, for example `internal/sgwc/s11/handler.go:447-460`.

**Impact**

Concurrent PFCP/GTP-U/control-plane activity can cause data races, inconsistent forwarding decisions, stale reads, or slice corruption. The race detector could not run in this environment, but the aliasing and unlocked writes are direct and deterministic in the source.

**Recommended fix**

Do not return mutable internal pointers. Return value copies/snapshots, and expose store/session methods that perform complete reads or updates while holding the appropriate lock. For PFCP modification, use copy-on-write session objects and atomically swap the committed pointer.

### AUD-08 — Medium — PFCP association identity is keyed inconsistently

**Evidence**

- `internal/sgwu/pfcpserver/server.go:205-230` stores associations by Node ID.
- `hasAssociation` at lines 310-317 checks by UDP source IP.
- Heartbeats similarly derive identity from source IP at lines 272-276.

**Impact**

A valid peer whose PFCP Node ID differs from its source transport address can establish an association and then have every session request rejected as “No established PFCP Association.” Restart cleanup can also target a different key from the stored association.

**3GPP reference**

- TS 29.244 clause 8.2.38 (Node ID in this version’s numbering/table): Node ID identifies the PFCP node independently of a particular session.
- TS 29.244 association procedures in clause 6.2.6 and clause 7.4 require session procedures to use an established association.

**Recommended fix**

Store both canonical Node ID and current validated transport address in one association record. Maintain an address-to-Node-ID index populated by Association Setup. Use that mapping consistently for heartbeat, session authorization, and restart cleanup.

### AUD-09 — Medium — Colliding session eviction leaves a stale S5/S8-C index

**Evidence**

- `internal/sgwc/session/manager.go:107-116` removes the old session from `byID`, `byS11`, `byPDN`, and possibly `byIMSI`, but not `byS5C`.
- PGW-initiated bearer procedures resolve through `FindByS5CTEID`.

**Impact**

After a reattach/session collision, a PGW request to the old SGW S5/S8-C TEID can still resolve to the evicted session object. It can mutate orphaned state, trigger PFCP operations, or produce a response using obsolete subscriber bindings.

**3GPP reference**

- TS 29.274 clause 7.2.1 collision handling identifies an existing PDN connection by `[IMSI, EPS Bearer ID]` and requires the old local context to be deleted before creating the replacement.

**Recommended fix**

Delete the old `byS5C` entry during eviction and free the S5/S8-C TEID through the owning allocator after remote cleanup. Add a regression test asserting every index is clear after collision replacement.

### AUD-10 — Medium — Delete Session Request does not validate Sender F-TEID

**Evidence**

- `internal/gtpv2/message/delete_session.go:6-32` does not parse Sender F-TEID.
- `internal/sgwc/s11/handler.go:556-620` accepts deletion based on header TEID alone and never compares a received Sender F-TEID with the last stored MME control F-TEID.

**Impact**

When the optional/conditional Sender F-TEID is present, a request from a stale or wrong peer can delete a live session instead of being rejected as an invalid peer.

**3GPP reference**

- TS 29.274 clause 7.2.9.1, Table 7.2.9.1-1: when Sender F-TEID for Control Plane is received, the SGW shall accept the request only if it matches the Sender F-TEID last received in Create Session Request or Modify Bearer Request.

**Recommended fix**

Parse the applicable Sender F-TEID instance in `DeleteSessionRequest`. If present, compare interface type, TEID, and address with the stored MME binding; reject mismatches with the specified invalid-peer behavior and do not alter state.

### AUD-11 — Medium — UDP transports permit unbounded goroutines and transaction/cache growth

**Evidence**

- `internal/gtpv2/transport/transport.go:122-137` and `internal/pfcp/transport/transport.go:116-128` start one goroutine per datagram without a concurrency limit.
- In-flight entries remain until handlers return; handlers can block on downstream T3/N3 or T1/N1 exchanges.
- Response caches are swept only when another response is stored.
- `Send` overwrites any existing pending transaction with the same `(address, sequence)` key instead of rejecting a collision.

**Impact**

A reachable peer can consume memory and scheduler capacity with request floods. Slow downstream peers amplify the problem because each inbound request can hold a goroutine for multiple retransmission intervals. Sequence wrap or accidental duplicate allocation can orphan a pending transaction.

**Recommended fix**

Add bounded worker pools and per-peer rate/concurrency limits. Bound caches with periodic expiry and maximum sizes. Reject duplicate pending keys. Track request type in transaction and retransmission keys, and apply overload shedding before expensive parsing or downstream calls.

### AUD-12 — Medium — HTTP servers lack timeouts and startup error propagation

**Evidence**

- `internal/api/server.go:69-84` and `internal/metrics/prometheus.go:35-52` configure no `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, `IdleTimeout`, or `MaxHeaderBytes`.
- `Start` returns success before the listener is known to have bound; asynchronous `ListenAndServe` errors are only logged.

**Impact**

Slow or incomplete HTTP requests can hold connections and memory. Port conflicts or permission failures can leave the process reporting “ready” even though the API or metrics endpoint never started.

**Recommended fix**

Bind with `net.Listen` synchronously and return bind errors from `Start`. Configure conservative HTTP timeouts and header limits. Add connection limits or place the endpoints behind a hardened management proxy.

### AUD-13 — Medium — Dataplane configuration contains ineffective readiness controls

**Evidence**

- `dataplane.unknown_teid` is validated in `internal/config/sgwu/validate.go:32-36` but is never passed to or used by the BPF program; BPF always punts unknown TEIDs.
- `cmd/vectorcore-sgw-u/main.go:109-112` allows `attach_on_start=false`, skips all dataplane setup, and later reports the SGW-U as ready.

**Impact**

Operators can configure `unknown_teid: drop` and receive different behavior. They can also start a PFCP-accepting SGW-U with no forwarding dataplane, causing PFCP success with guaranteed traffic failure.

**Recommended fix**

Make unknown-TEID behavior an explicit BPF configuration/map value and test both modes. Treat `attach_on_start=false` as an administrative/offline state: do not accept PFCP session establishment and do not report readiness unless an externally managed dataplane is positively detected.

## Incomplete/WIP behavior noted but not counted as defects

- `cmd/vectorcore-sgwctl` is explicitly unimplemented.
- BAR/BUFF/DDN support is deferred; Release Access Bearers currently uses DROP. This is clearly documented in code, but it must not be presented as full idle-mode downlink behavior.
- IPv6/IPv4v6, charging, URR, advanced TFT processing, SGW relocation, ISR, and several mobility procedures are documented as deferred.
- The userspace forwarder is a reference implementation and performs linear TEID lookup. This is a scalability limitation, not a correctness finding for the current phase.

## Validation performed

- `go vet ./...`: passed.
- `go test ./...`: all packages passed except UDP socket tests in `internal/sgwu/gtpu`; those failed because this audit sandbox prohibits `listen udp4 ...: socket: operation not permitted`.
- Non-socket GTP-U parser/store tests passed.
- A race-detector build was attempted but the installed Go environment could not build `runtime/race`; concurrency findings were therefore verified by source-level ownership and lock analysis.
- Specification clauses were checked against the local documents listed above.

## Recommended remediation order

1. Fix AUD-01 and AUD-02 before any production traffic test.
2. Provide the BPF-mode signalling path and harden BPF parsing (AUD-03 and AUD-04).
3. Remove mutable pointer escapes and make PFCP/BPF updates transactional (AUD-07).
4. Secure management and transport resource usage (AUD-06, AUD-11, AUD-12).
5. Correct association/index/request validation defects (AUD-08 through AUD-10).
6. Enforce peer-address validation and randomize TEIDs (AUD-05).
7. Make configuration and readiness accurately reflect dataplane state (AUD-13).
