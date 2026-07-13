# VectorCore SGW

VectorCore SGW is an LTE Serving Gateway implementation with separate SGW-C and
SGW-U processes. It follows a CUPS design: SGW-C handles GTPv2-C and PFCP
control-plane procedures, while SGW-U handles GTP-U forwarding with an eBPF
dataplane.

## Components

- `sgw-c`: SGW Control Plane
- `sgw-u`: SGW User Plane
- `sgwctl`: configuration validation and runtime inspection tool

## Current Feature Set

- CUPS split between SGW-C and SGW-U.
- S11 GTPv2-C toward the MME.
- S5/S8-C GTPv2-C toward the PGW.
- Sxa PFCP between SGW-C and SGW-U.
- S1-U and S5/S8-U GTP-U forwarding on SGW-U.
- eBPF/XDP dataplane for GTP-U TEID match, rewrite, redirect, punt, and drop.
- PFCP-driven PDR/FAR installation and removal on SGW-U.
- Default bearer Create Session, Modify Bearer, Delete Session, and Release
  Access Bearers handling.
- PGW-initiated Create Bearer handling for dedicated bearers.
- Piggybacked GTPv2-C message handling.
- Multi-PDN and multi-UE bearer ownership isolation by S11 context and EBI.
- GTPv2-C retransmission response caching.
- GTPv2-C transaction collision handling with configurable strict/permissive
  policy.
- Dynamic GTPv2-C Echo probing and peer health tracking for observed MME and
  PGW peers, including RTT, missed Echo counters, Recovery IE restart tracking,
  API visibility, Prometheus metrics, and down-peer procedure warnings.
- PGW restart and S5/S8-C path-failure manager with PGW-to-session indexing,
  affected-session marking, API visibility, Prometheus metrics, and
  configurable warning/blocking policy for procedures toward a down PGW.
- MME restoration and Network Triggered Service Restoration handling with
  MME path/restart tracking, APN/QCI/ARP preserve/delete policy, optional
  delete-policy cleanup, DDN triggering, DDN Ack/Failure handling, Modify
  Bearer completion, API visibility, and Prometheus metrics.
- Downlink Data Notification throttling and priority paging controls with
  per-MME token buckets, per-UE suppression, high-priority IMS/QCI/ARP bypass,
  MME low-priority throttling enforcement, bounded delayed DDN queue, optional
  Stop Paging after DDN Ack, API visibility, and Prometheus metrics.
- Static outer IP DSCP marking for SGW-C GTP-C, SGW-C PFCP, SGW-U PFCP, and
  SGW-U forwarded GTP-U.
- QCI-aware GTP-U outer DSCP marking in SGW-U using operator-configured
  QCI-to-DSCP mappings.
- 3GPP Release 15 NSA/DCNR awareness for GTPv2-C Secondary RAT Usage Data
  Report IE capture, owner-scoped session storage, S5/S8-C forwarding, API
  visibility, and Prometheus counters.
- Recovery counter support.
- JSON API listeners for SGW-C and SGW-U runtime state.
- Prometheus metrics listeners.
- YAML configuration with strict unknown-field rejection.

## Build Requirements

- Linux.
- Go `1.26.2` or newer compatible Go toolchain.
- `make`.
- `clang` and libbpf development headers for eBPF object generation.
- Kernel/eBPF support for XDP attachment.
- Runtime privileges for SGW-U to attach eBPF programs to network interfaces.

The eBPF bindings are generated with `github.com/cilium/ebpf/cmd/bpf2go` through
`go generate`.

## Build

```bash
make clean
make
```

This builds:

```text
bin/sgw-c
bin/sgw-u
bin/sgwctl
```

Useful targets:

```bash
make test
make vet
make verify
make install
make uninstall
```

Default install paths:

```text
/opt/vectorcore/bin/sgw-c
/opt/vectorcore/bin/sgw-u
/opt/vectorcore/bin/sgwctl
/opt/vectorcore/etc/sgw-c.yaml
/opt/vectorcore/etc/sgw-u.yaml
```

## Run

Validate configuration:

```bash
./bin/sgw-c -c configs/sgw-c.yaml -validate
./bin/sgw-u -c configs/sgw-u.yaml -validate
./bin/sgwctl validate -sgwc configs/sgw-c.yaml -sgwu configs/sgw-u.yaml
```

Start SGW-U:

```bash
./bin/sgw-u -d -c configs/sgw-u.yaml
```

Start SGW-C:

```bash
./bin/sgw-c -d -c configs/sgw-c.yaml
```

Start SGW-U before SGW-C so the PFCP peer is available when SGW-C starts.

## CLI Flags

`sgw-c`:

```text
-c string      path to SGW-C YAML config
               default: /etc/vectorcore/sgw/sgw-c.yaml
-d             enable debug console logging
-validate      load and validate config, then exit
-v             print version and exit
```

`sgw-u`:

```text
-c string      path to SGW-U YAML config
               default: /etc/vectorcore/sgw/sgw-u.yaml
-d             enable debug console logging
-validate      load and validate config, then exit
-v             print version and exit
```

`sgwctl`:

```text
validate       validate SGW-C and/or SGW-U config files
dry-run        alias for validate
health         show SGW-C health
sessions       list SGW-C sessions
bearers        list SGW-C sessions with bearer details
pfcp           show SGW-C and SGW-U PFCP association status
gtpc-peers     show SGW-C GTP-C peer health
pgw-failures   show SGW-C PGW path and restart state
recovery       show SGW-C checkpoint and recovery status
bearer-inactivity show SGW-C bearer inactivity cleanup status
idle-downlink show SGW-C idle downlink status and SGW-U GTP-U counters
bpf            show SGW-U BPF map state
```

Validation example:

```bash
./bin/sgwctl validate -sgwc configs/sgw-c.yaml -sgwu configs/sgw-u.yaml
```

## SGW-C Configuration

Default file: `configs/sgw-c.yaml`

### Configuration layout and migration

The canonical SGW-C schema separates transport from optional behavior:

- `gtpc:` contains S11/S5-C bindings, S11 retransmission timers, transaction handling, and GTP peer health.
- `pfcp:` contains the local endpoint, heartbeat settings, and SGW-U peers.
- `features:` contains NSA/DCNR, PGW failure handling, MME restoration, DDN control, idle-downlink notification, session recovery, and bearer-inactivity cleanup.
- `qos:`, `logging:`, `api:`, `metrics:`, and `shutdown:` remain independent top-level concerns.

This is a backward-incompatible schema change. Parsing is strict: the former top-level `s11:` block, feature blocks under `gtpc:`, flat feature settings, and policy `reason:` fields are rejected. Validate migrated files with `sgw-c -validate` or `sgwctl validate` before deployment.

Old:

```yaml
gtpc:
  mme_restoration:
    preserve:
      - apn: "ims"
        reason: "preserve IMS PDN for network triggered service restoration"

s11:
  t3_response_seconds: 3
  n3_requests: 5
```

New:

```yaml
gtpc:
  s11:
    bind: "sgwinterface"
    timers:
      t3_response_seconds: 3
      n3_requests: 5

features:
  mme_restoration:
    policy:
      preserve:
        # Preserve IMS PDNs for network-triggered service restoration.
        # Generated reason: mme-restoration-preserve-apn-ims
        - apn: "ims"
```

Policy reasons are generated internally; operators should put human rationale in YAML comments. Codes use `<feature>-<action>-<matchers>` with matcher fields ordered as APN, QCI, ARP range, bearer type, and idle timeout. Values are lowercased and sanitized. Examples include `ddn-high-priority-apn-ims`, `mme-restoration-delete-apn-internet-qci-9`, and `bearer-inactivity-cleanup-dedicated-idle-300`. Generated codes continue to appear in logs, APIs, session state, and recovery checkpoints. Procedural reasons such as `per-mme-rate-limit` remain unchanged.

Top-level sections:

```yaml
sgwc:
  node_id: "sgw-c-1"
  plmn:
    mcc: "311"
    mnc: "435"
  state_dir: "/var/lib/vectorcore-sgw"
  control_plane_ip: "10.90.250.59"

interfaces:
  control:
    sgwinterface:
      listen: "10.90.250.59:2123"

gtpc:
  s11:
    bind: "sgwinterface"
    timers:
      t3_response_seconds: 3
      n3_requests: 5
  s5c:
    bind: "sgwinterface"
  transactions:
    create_bearer_retry_guard:
      enabled: true
    collision_handling:
      mode: "strict"
      active_procedure_timeout_seconds: 120
  peer_health:
    enabled: true
    timers:
      echo_interval_seconds: 30
      echo_timeout_seconds: 3
    thresholds:
      suspect_after_missed: 2
      down_after_missed: 3
      degraded_rtt_ms: 500
    probe:
      mme: true
      pgw: true
    warn_on_down_peer_procedure: true

pfcp:
  local_addr: "127.0.0.1:8805"
  heartbeat:
    interval_seconds: 10
    timeout_seconds: 30
  sgwu:
    - name: "sgw-u-1"
      node_id: "sgw-u-1"
      addr: "127.0.0.2:8805"

features:
  nsa_dcnr:
    enabled: true
    forward_secondary_rat_usage_reports: true
  pgw_failure_handling:
    enabled: true
    detection:
      mark_sessions_on_path_down: true
      mark_sessions_on_restart: true
    actions:
      block_new_procedures_to_down_pgw: false
      notify_mme_on_pgw_restart: false
  mme_restoration:
    enabled: true
    detection:
      mark_sessions_on_path_down: true
      mark_sessions_on_restart: true
    actions:
      enforce_delete_policy: true
      trigger_ddn: true
      cleanup_timeout_seconds: 30
      default_action: "preserve"
    policy:
      preserve:
        - apn: "ims"
        - qci: 1
        - arp:
            priority_min: 1
            priority_max: 3
      delete:
        - apn: "internet"
          qci: 9
  ddn:
    enabled: true
    rate_limit:
      per_mme_per_second: 50
      per_mme_burst: 100
      per_ue_suppression_seconds: 10
    low_priority_throttling:
      honor_mme_throttling: true
      throttle_seconds: 30
      high_priority_bypass: true
    delayed_queue:
      max_entries: 1000
      max_entries_per_mme: 200
      max_age_seconds: 30
    stop_paging:
      enabled: false
      on_ddn_ack: false
    policy:
      high_priority:
        - apn: "ims"
        - qci: 1
        - arp:
            priority_min: 1
            priority_max: 3
      low_priority:
        - apn: "internet"
          qci: 9
  idle_downlink_notification:
    enabled: false
    actions:
      trigger_ddn: true
    conditions:
      require_release_access_drop: true
    throttling:
      report_throttle_seconds: 10
    policy:
      high_priority:
        - apn: "ims"
        - qci: 1
        - arp:
            priority_min: 1
            priority_max: 3
      suppress:
        - apn: "internet"
          qci: 9
  session_recovery:
    enabled: false
    storage:
      backend: "sqlite"
      sqlite_path: "/opt/vectorcore/data/sgwc-db"
    startup:
      restore: true
      reconcile: true
    checkpoint_interval_seconds: 5
  bearer_inactivity:
    enabled: false
    timers:
      check_interval_seconds: 30
      dedicated_bearer_idle_seconds: 300
      pending_bearer_timeout_seconds: 60
      default_bearer_idle_seconds: 0
    conditions:
      require_no_recent_control_activity: true
    actions:
      delete_default_bearers: false
    policy:
      preserve:
        - apn: "ims"
          qci: 5
          bearer_type: "default"
        - qci: 1
      cleanup:
        - bearer_type: "dedicated"
          idle_seconds: 300

qos:
  outer_marking:
    enabled: true
    gtpc:
      enabled: true
      dscp: 40
    pfcp:
      enabled: true
      dscp: 40

logging:
  level: info
  file: /var/log/vectorcore/sgw/sgw-c.log

api:
  listen: "127.0.0.1:8080"

metrics:
  listen: "127.0.0.1:9090"

shutdown:
  timeout_seconds: 5
```

SGW-C options:

| Path | Purpose |
| --- | --- |
| `sgwc.node_id` | SGW-C node identifier. |
| `sgwc.plmn.mcc` | MCC for the local PLMN. |
| `sgwc.plmn.mnc` | MNC for the local PLMN. |
| `sgwc.state_dir` | Directory for persisted runtime state such as the recovery counter. |
| `sgwc.control_plane_ip` | IP advertised in SGW-C control-plane F-TEIDs. |
| `interfaces.control.<name>.listen` | UDP listen address for a named control interface. |
| `gtpc.s11.bind` | Named control interface used for S11. |
| `gtpc.s11.timers.t3_response_seconds` | GTPv2-C retransmission timeout for unanswered S11 requests. |
| `gtpc.s11.timers.n3_requests` | Maximum S11 retransmission count before transaction failure. |
| `gtpc.s5c.bind` | Named control interface used for S5/S8-C. |
| `gtpc.transactions.create_bearer_retry_guard.enabled` | Enables repeated Create Bearer retry guard. |
| `gtpc.transactions.collision_handling.mode` | GTPv2-C transaction collision policy. `strict` rejects unsafe overlaps. `permissive` only relaxes bearer-scoped overlaps when one side has no decoded EBI scope. |
| `gtpc.transactions.collision_handling.active_procedure_timeout_seconds` | Timeout for stale active GTPv2-C procedure state. Default 120. |
| `gtpc.peer_health.enabled` | Enables SGW-C GTPv2-C peer health tracking and Echo probing. |
| `gtpc.peer_health.timers.echo_interval_seconds` | GTPv2-C Echo probe interval. Default 30. |
| `gtpc.peer_health.timers.echo_timeout_seconds` | GTPv2-C Echo response timeout. Default 3. |
| `gtpc.peer_health.thresholds.suspect_after_missed` | Consecutive missed Echo threshold for `suspect` state. Default 2. |
| `gtpc.peer_health.thresholds.down_after_missed` | Consecutive missed Echo threshold for `down` state. Default 3. |
| `gtpc.peer_health.thresholds.degraded_rtt_ms` | RTT threshold for `degraded` state. Default 500. |
| `gtpc.peer_health.probe.mme` | Enables Echo probing for observed MME GTP-C peers. |
| `gtpc.peer_health.probe.pgw` | Enables Echo probing for observed PGW GTP-C peers. |
| `gtpc.peer_health.warn_on_down_peer_procedure` | Logs a warning when a procedure starts toward a peer currently marked `down`. |
| `features.nsa_dcnr.enabled` | Enables Release 15 NSA/DCNR awareness in SGW-C. |
| `features.nsa_dcnr.forward_secondary_rat_usage_reports` | Forwards S11 Secondary RAT Usage Data Report IEs to the owner PGW session on S5/S8-C Modify Bearer. |
| `features.pgw_failure_handling.enabled` | Enables PGW restart/path-failure session marking. |
| `features.pgw_failure_handling.detection.mark_sessions_on_path_down` | Marks sessions indexed to a PGW when that PGW transitions down or back up. |
| `features.pgw_failure_handling.detection.mark_sessions_on_restart` | Marks sessions indexed to a PGW when that PGW's Recovery IE restart counter changes. |
| `features.pgw_failure_handling.actions.block_new_procedures_to_down_pgw` | If true, rejects new PGW-owned S5/S8-C procedures toward a PGW currently marked down. Default false, warning-only. |
| `features.pgw_failure_handling.actions.notify_mme_on_pgw_restart` | Reserved for future TS 29.274 PGW Restart Notification support. Must be false in this release. |
| `features.mme_restoration.enabled` | Enables MME restoration/NTSR handling. |
| `features.mme_restoration.detection.mark_sessions_on_path_down` | Marks sessions indexed to an MME when that MME transitions down or back up. |
| `features.mme_restoration.detection.mark_sessions_on_restart` | Marks sessions indexed to an MME when that MME's Recovery IE restart counter changes. |
| `features.mme_restoration.actions.enforce_delete_policy` | Enforces delete-policy sessions with S5/S8-C Delete Session and PFCP cleanup. PGW rejection retains local state. |
| `features.mme_restoration.actions.trigger_ddn` | Sends S11 Downlink Data Notification for preserved sessions during NTSR. |
| `features.mme_restoration.actions.cleanup_timeout_seconds` | Timeout for restoration cleanup and DDN send operations. Default 30. |
| `features.mme_restoration.actions.default_action` | Policy action for unmatched sessions. `preserve` or `delete`. Default `preserve`. |
| `features.mme_restoration.policy.preserve[]` | Preserve rules matched by APN, QCI, and/or ARP priority range. Preserve rules win over delete rules. |
| `features.mme_restoration.policy.delete[]` | Delete rules matched by APN, QCI, and/or ARP priority range. |
| `features.ddn.enabled` | Enables DDN throttling and priority paging decisions. |
| `features.ddn.rate_limit.per_mme_per_second` | Per-MME DDN token refill rate. Default 50. |
| `features.ddn.rate_limit.per_mme_burst` | Per-MME DDN token bucket burst size. Default 100. |
| `features.ddn.rate_limit.per_ue_suppression_seconds` | Suppresses duplicate non-high-priority DDNs for the same UE within this window. Default 10. |
| `features.ddn.low_priority_throttling.honor_mme_throttling` | Applies MME-provided DDN Ack low-priority throttling to future low-priority DDN decisions. |
| `features.ddn.low_priority_throttling.throttle_seconds` | Fallback low-priority throttle duration when the MME throttling IE lacks a usable duration. Default 30. |
| `features.ddn.low_priority_throttling.high_priority_bypass` | Allows high-priority DDNs to bypass an empty per-MME token bucket. |
| `features.ddn.delayed_queue.max_entries` | Global bound for delayed DDN queue entries. Default 1000. |
| `features.ddn.delayed_queue.max_entries_per_mme` | Per-MME bound for delayed DDN queue entries. Default 200. |
| `features.ddn.delayed_queue.max_age_seconds` | Maximum age for queued delayed DDN work. Default 30. |
| `features.ddn.stop_paging.enabled` | Enables Stop Paging support. Default false until ISR lab validation. |
| `features.ddn.stop_paging.on_ddn_ack` | If true, sends Stop Paging after accepted DDN Ack when restoration state proves it is eligible. Requires `enabled=true`. |
| `features.ddn.policy.high_priority[]` | High-priority DDN rules matched by APN, QCI, and/or ARP priority range. |
| `features.ddn.policy.low_priority[]` | Low-priority DDN rules matched by APN, QCI, and/or ARP priority range. |
| `features.idle_downlink_notification.enabled` | Enables idle downlink packet reporting/DDN trigger flow. Default false until live lab validation is complete. |
| `features.idle_downlink_notification.actions.trigger_ddn` | Allows SGW-C to send S11 DDN for accepted idle downlink reports. |
| `features.idle_downlink_notification.throttling.report_throttle_seconds` | Per bearer/session idle downlink report throttle. Default 10. |
| `features.idle_downlink_notification.conditions.require_release_access_drop` | Limits idle downlink reports to DROP state caused by Release Access Bearers. Default true. |
| `features.idle_downlink_notification.policy.high_priority[]` | Idle downlink report rules eligible for DDN, matched by APN, QCI, and/or ARP priority range. Defaults include IMS, QCI 1, and high ARP. |
| `features.idle_downlink_notification.policy.suppress[]` | Idle downlink report rules suppressed by policy. Defaults suppress low-priority internet QCI 9. |
| `features.session_recovery.enabled` | Enables SGW-C session checkpoint/recovery. Default false until restore/reconcile phases are complete. |
| `features.session_recovery.storage.backend` | Checkpoint backend. `sqlite` is the supported local restart-recovery backend; Redis/etcd are reserved for future HA. |
| `features.session_recovery.storage.sqlite_path` | SQLite checkpoint DB path. |
| `features.session_recovery.startup.restore` | Reload checkpointed SGW-C session state at startup. Restored sessions must reconcile before becoming active. |
| `features.session_recovery.startup.reconcile` | Reconcile restored sessions against SGW-U PFCP/eBPF state at startup. Requires `restore=true`. |
| `features.session_recovery.checkpoint_interval_seconds` | Minimum periodic checkpoint cadence for dirty sessions. Default 5. |
| `features.bearer_inactivity.enabled` | Enables bearer inactivity tracking/cleanup. Default false while activity detection and cleanup execution are phased in. |
| `features.bearer_inactivity.timers.check_interval_seconds` | Periodic inactivity scan interval. Default 30. |
| `features.bearer_inactivity.timers.dedicated_bearer_idle_seconds` | Default idle threshold for dedicated bearers. Default 300. |
| `features.bearer_inactivity.timers.pending_bearer_timeout_seconds` | Timeout for pending bearer procedures before they can be considered stale. Default 60. |
| `features.bearer_inactivity.timers.default_bearer_idle_seconds` | Default-bearer idle threshold. `0` disables default-bearer inactivity cleanup. |
| `features.bearer_inactivity.actions.delete_default_bearers` | Allows default-bearer inactivity cleanup when explicitly paired with a positive default-bearer idle timeout. Default false. |
| `features.bearer_inactivity.conditions.require_no_recent_control_activity` | Requires no recent bearer/session control activity before cleanup eligibility. Default true. |
| `features.bearer_inactivity.policy.preserve[]` | Preserve rules matched by APN, QCI, bearer type, and/or ARP priority range. Preserve rules are intended to protect IMS signaling, QCI 1, and high-priority sessions. |
| `features.bearer_inactivity.policy.cleanup[]` | Cleanup rules matched by bearer type/APN/QCI/ARP. Phase 1 only validates policy; later phases execute cleanup. |
| `pfcp.local_addr` | SGW-C PFCP local address. |
| `pfcp.heartbeat.interval_seconds` | PFCP heartbeat interval. |
| `pfcp.heartbeat.timeout_seconds` | PFCP heartbeat timeout. |
| `pfcp.sgwu[].name` | SGW-U peer name. |
| `pfcp.sgwu[].node_id` | SGW-U peer node ID. |
| `pfcp.sgwu[].addr` | SGW-U PFCP address. |
| `qos.outer_marking.enabled` | Enables outer IP DSCP marking. |
| `qos.outer_marking.gtpc.enabled` | Enables DSCP marking on SGW-C GTP-C sockets. |
| `qos.outer_marking.gtpc.dscp` | GTP-C DSCP value, range 0-63. Default 40. |
| `qos.outer_marking.pfcp.enabled` | Enables DSCP marking on SGW-C PFCP sockets. |
| `qos.outer_marking.pfcp.dscp` | PFCP DSCP value, range 0-63. Default 40. |
| `logging.level` | Log level. |
| `logging.file` | Log file path. |
| `api.listen` | SGW-C HTTP API listen address. |
| `metrics.listen` | SGW-C metrics listen address. |
| `shutdown.timeout_seconds` | Graceful shutdown timeout. |

Required SGW-C fields include `sgwc.node_id`, `sgwc.plmn.mcc`,
`sgwc.plmn.mnc`, `gtpc.s11.bind`, `gtpc.s5c.bind`, `pfcp.local_addr`, and at
least one `pfcp.sgwu` entry.

SGW-C exposes runtime state through its HTTP API listener:

| Endpoint | Purpose |
| --- | --- |
| `/health` | SGW-C health response. |
| `/sessions` | SGW-C session list. |
| `/sessions/{session_id}` | Detailed SGW-C session and bearer state, including PGW failure, MME restoration, and DDN control decision fields. |
| `/gtpc/peers` | Observed GTP-C peer health and Recovery IE state. |
| `/gtpc/pgw-failures` | PGW path/restart state and affected session counts. |
| `/gtpc/mme-restorations` | MME restoration/path/restart state and affected session counts. |
| `/gtpc/ddn-control` | DDN throttling, priority paging, token, throttle, delay, suppress, and per-UE state. |
| `/gtpc/idle-downlink` | Idle downlink report/DDN status counters. |
| `/pfcp/associations` | SGW-C PFCP association state. |
| `/recovery/status` | SGW-C checkpoint backend, restore counts, peer Recovery IE restore counts, and current recovery summary. |

SGW-U API endpoints include:

| Endpoint | Purpose |
| --- | --- |
| `/sessions` | SGW-U PFCP sessions with PDR/FAR state. |
| `/pfcp/associations` | SGW-U PFCP association state with SGW-C peers. |
| `/bpf/rules` | SGW-U eBPF forwarding rules and per-rule counters. |
| `/gtpu/counters` | SGW-U userspace GTP-U counters, including idle downlink hits. |

SGW-C exports the following control-plane metrics on its Prometheus listener:

| Metric | Purpose |
| --- | --- |
| `sgwc_gtpv2c_collision_rejections_total` | Count of rejected overlapping GTPv2-C procedures by action, policy, active procedure, new procedure, and owner. |
| `sgwc_gtpv2c_collision_stale_expired_total` | Count of stale active-procedure records expired before a new collision decision. |
| `sgwc_gtpc_peer_state` | One-hot peer health state gauge by role, peer, and state. |
| `sgwc_gtpc_peer_echo_rtt_seconds` | Last GTPv2-C Echo RTT by role and peer. |
| `sgwc_gtpc_peer_echo_sent_total` | Count of GTPv2-C Echo Requests sent by role and peer. |
| `sgwc_gtpc_peer_echo_responses_total` | Count of GTPv2-C Echo Responses received by role and peer. |
| `sgwc_gtpc_peer_echo_timeouts_total` | Count of GTPv2-C Echo timeouts by role and peer. |
| `sgwc_gtpc_peer_restarts_total` | Count of Recovery IE restart-counter changes by role and peer. |
| `sgwc_pgw_path_state` | One-hot PGW path/restart state gauge by PGW and state. |
| `sgwc_pgw_affected_sessions` | Current count of sessions affected by PGW path/restart state. |
| `sgwc_pgw_restarts_total` | Count of PGW Recovery IE restart-counter changes handled by SGW-C. |
| `sgwc_pgw_path_down_total` | Count of PGW path-down transitions handled by SGW-C. |
| `sgwc_mme_restoration_state` | One-hot MME restoration/path/restart state gauge by MME and state. |
| `sgwc_mme_restoration_affected_sessions` | Current count of sessions affected by MME restoration state. |
| `sgwc_mme_restarts_total` | Count of MME Recovery IE restart-counter changes handled by SGW-C restoration. |
| `sgwc_mme_path_down_total` | Count of MME path-down transitions handled by SGW-C restoration. |
| `sgwc_ddn_control_tokens` | Current per-MME DDN control token count. |
| `sgwc_ddn_control_sent_total` | Count of DDN sends allowed by DDN control per MME. |
| `sgwc_ddn_control_delayed_total` | Count of DDN delay decisions per MME. |
| `sgwc_ddn_control_suppressed_total` | Count of DDN suppress decisions per MME. |
| `sgwc_ddn_control_high_priority_bypassed_total` | Count of high-priority DDN bypass sends per MME. |
| `sgwc_ddn_control_low_priority_throttle_active` | Gauge showing whether MME low-priority DDN throttling is active. |
| `sgwc_ddn_control_ue_sent_total` | Count of DDN sends allowed by DDN control per UE. |
| `sgwc_ddn_control_ue_delayed_total` | Count of DDN delay decisions per UE. |
| `sgwc_ddn_control_ue_suppressed_total` | Count of DDN suppress decisions per UE. |
| `sgwc_checkpoint_enabled` | Gauge showing whether SGW-C session checkpointing is enabled. |
| `sgwc_checkpoint_sessions_loaded` | Session snapshots loaded from checkpoint storage at startup. |
| `sgwc_checkpoint_sessions_restored` | Session snapshots restored at startup. |
| `sgwc_checkpoint_peer_snapshots_loaded` | Peer Recovery IE snapshots loaded at startup. |
| `sgwc_checkpoint_gtpc_peers_restored` | MME/PGW Recovery IE snapshots restored at startup. |
| `sgwc_checkpoint_pfcp_peers_restored` | SGW-U Recovery Time Stamp snapshots restored at startup. |
| `sgwc_checkpoint_flushes_total` | Checkpoint writer flush attempts. |
| `sgwc_checkpoint_flush_failures_total` | Checkpoint writer flush failures. |
| `sgwc_checkpoint_session_saves_total` | Session snapshots saved by the checkpoint writer. |
| `sgwc_checkpoint_session_deletes_total` | Session snapshots deleted by the checkpoint writer. |
| `sgwc_checkpoint_peer_saves_total` | Peer Recovery IE snapshots saved by the checkpoint writer. |
| `sgwc_recovery_sessions` | Current SGW-C sessions by recovery/session state. |
| `sgwc_pfcp_reconciliation_sessions` | Current SGW-C sessions by PFCP reconciliation state. |
| `sgwc_pfcp_repair_plan_sessions` | Current SGW-C sessions by PFCP repair plan action. |
| `sgwc_nsa_secondary_rat_usage_reports_captured_total` | Count of Release 15 Secondary RAT Usage Data Report IEs captured on S11 by APN and source procedure. |
| `sgwc_nsa_secondary_rat_usage_reports_forwarded_total` | Count of Release 15 Secondary RAT Usage Data Report IEs forwarded on S5/S8-C by APN and resulting cause. |

Additional transaction collision behavior and validation notes are in
`docs/gtpv2c-transaction-collision.md`.

GTPv2-C peer health behavior and validation notes are in
`docs/gtpc-peer-health.md`.

PGW restart and path-failure behavior and validation notes are in
`docs/pgw-restart-path-failure.md`.

MME restoration/NTSR behavior and live validation notes are in
`docs/mme-ntsr-lab-validation.md`.

DDN throttling and priority paging validation notes are in
`docs/ddn-control-phase8-validation.md`.

Bearer inactivity cleanup behavior and live validation notes are in
`docs/bearer-inactivity-lab-validation.md`.

NSA/DCNR Secondary RAT report behavior and validation notes are in
`docs/5g-nsa-dcnr-awareness.md`.

## SGW-U Configuration

Default file: `configs/sgw-u.yaml`

Top-level sections:

```yaml
sgwu:
  node_id: "sgw-u-1"

pfcp:
  listen: "127.0.0.2:8805"
  allowed_sgwc:
    - "127.0.0.1"

interfaces:
  user:
    sgwinterface:
      ifname: "eth0"
      listen: "10.90.250.59:2152"

gtpu:
  s1u:
    bind: "sgwinterface"
  s5u:
    bind: "sgwinterface"

qos:
  outer_marking:
    enabled: true
    gtpu:
      enabled: true
      dscp: 0
    pfcp:
      enabled: true
      dscp: 40
  qci_marking:
    enabled: true
    override_default_gtpu: true
    default_gtpu_dscp: 0
    unknown_teid_dscp: 0
    trust_inner_dscp: false
    qci_to_dscp:
      1: 46
      2: 34
      3: 26
      4: 26
      5: 40
      6: 18
      7: 26
      8: 0
      9: 0

dataplane:
  driver_mode: "xdp-generic"
  unknown_teid: "punt"
  attach_on_start: true
  cleanup_on_exit: true
  map_max_entries: 65536

logging:
  level: info
  file: /var/log/vectorcore/sgw/sgw-u.log

api:
  listen: "127.0.0.1:8081"

metrics:
  listen: "127.0.0.1:9091"

shutdown:
  timeout_seconds: 5
```

SGW-U options:

| Path | Purpose |
| --- | --- |
| `sgwu.node_id` | SGW-U node identifier. |
| `pfcp.listen` | SGW-U PFCP listen address. |
| `pfcp.allowed_sgwc[]` | SGW-C control addresses allowed to use PFCP. |
| `interfaces.user.<name>.ifname` | Linux interface used by a named user-plane interface. |
| `interfaces.user.<name>.listen` | GTP-U local address for that named user-plane interface. |
| `gtpu.s1u.bind` | Named user-plane interface used for S1-U. |
| `gtpu.s5u.bind` | Named user-plane interface used for S5/S8-U. |
| `qos.outer_marking.enabled` | Enables outer IP DSCP marking. |
| `qos.outer_marking.gtpu.enabled` | Enables DSCP marking on forwarded GTP-U outer IPv4 headers. |
| `qos.outer_marking.gtpu.dscp` | GTP-U outer DSCP value, range 0-63. Default 0. |
| `qos.outer_marking.pfcp.enabled` | Enables DSCP marking on SGW-U PFCP sockets. |
| `qos.outer_marking.pfcp.dscp` | PFCP DSCP value, range 0-63. Default 40. |
| `qos.qci_marking.enabled` | Enables QCI-aware GTP-U outer DSCP marking for known bearer rules. |
| `qos.qci_marking.override_default_gtpu` | Uses QCI mapping instead of `outer_marking.gtpu.dscp` when bearer QCI metadata is available. |
| `qos.qci_marking.default_gtpu_dscp` | DSCP used when QCI marking is enabled but bearer QCI is missing or unmapped. |
| `qos.qci_marking.unknown_teid_dscp` | Reserved fallback DSCP setting for unknown TEID handling. |
| `qos.qci_marking.trust_inner_dscp` | Must be `false`; copying UE inner DSCP is not supported. |
| `qos.qci_marking.qci_to_dscp` | Operator QCI-to-DSCP map. QCI range 1-255, DSCP range 0-63. Defaults include QCI 1 to DSCP 46, QCI 5 to DSCP 40, QCI 9 to DSCP 0. |
| `dataplane.driver_mode` | XDP attach mode: `xdp-generic`, `xdp-native`, or `xdp-offload`. |
| `dataplane.unknown_teid` | Unknown TEID action: `punt` or `drop`. |
| `dataplane.attach_on_start` | Attach the eBPF dataplane during startup. |
| `dataplane.cleanup_on_exit` | Remove eBPF hooks during shutdown. |
| `dataplane.map_max_entries` | eBPF map capacity. |
| `logging.level` | Log level. |
| `logging.file` | Log file path. |
| `api.listen` | SGW-U HTTP API listen address. |
| `metrics.listen` | SGW-U metrics listen address. |
| `shutdown.timeout_seconds` | Graceful shutdown timeout. |

Required SGW-U fields include `sgwu.node_id`, `pfcp.listen`, at least one
`pfcp.allowed_sgwc` entry, `gtpu.s1u.bind`, and `gtpu.s5u.bind`.

S1-U and S5/S8-U listen addresses must use explicit IPv4 addresses, not
`0.0.0.0`.

## Interfaces and Ports

| Interface | Protocol | Default port |
| --- | --- | --- |
| S11 | GTPv2-C | UDP/2123 |
| S5/S8-C | GTPv2-C | UDP/2123 |
| Sxa | PFCP | UDP/8805 |
| S1-U | GTP-U | UDP/2152 |
| S5/S8-U | GTP-U | UDP/2152 |
| SGW-C API | HTTP | TCP/8080 |
| SGW-U API | HTTP | TCP/8081 |
| SGW-C metrics | HTTP | TCP/9090 |
| SGW-U metrics | HTTP | TCP/9091 |

## Example Lab Configs

`configs/interop/` contains lab templates for a two-node SGW-C/SGW-U deployment:

- `configs/interop/sgw-c-lab.yaml`
- `configs/interop/sgw-u-lab.yaml`

They set lab IP addresses, PFCP peer wiring, shared control-plane binding, and
VM-friendly `xdp-generic` dataplane mode.
