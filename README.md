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
bpf            show SGW-U BPF map state
```

Validation example:

```bash
./bin/sgwctl validate -sgwc configs/sgw-c.yaml -sgwu configs/sgw-u.yaml
```

## SGW-C Configuration

Default file: `configs/sgw-c.yaml`

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
  s5c:
    bind: "sgwinterface"
  create_bearer_retry_guard:
    enabled: true

s11:
  t3_response_seconds: 3
  n3_requests: 5

pfcp:
  local_addr: "127.0.0.1:8805"
  heartbeat_interval_seconds: 10
  heartbeat_timeout_seconds: 30
  sgwu:
    - name: "sgw-u-1"
      node_id: "sgw-u-1"
      addr: "127.0.0.2:8805"

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
| `gtpc.s5c.bind` | Named control interface used for S5/S8-C. |
| `gtpc.create_bearer_retry_guard.enabled` | Enables repeated Create Bearer retry guard. |
| `s11.t3_response_seconds` | GTPv2-C retransmission timeout. |
| `s11.n3_requests` | GTPv2-C retransmission count. |
| `pfcp.local_addr` | SGW-C PFCP local address. |
| `pfcp.heartbeat_interval_seconds` | PFCP heartbeat interval. |
| `pfcp.heartbeat_timeout_seconds` | PFCP heartbeat timeout. |
| `pfcp.sgwu[].name` | SGW-U peer name. |
| `pfcp.sgwu[].node_id` | SGW-U peer node ID. |
| `pfcp.sgwu[].addr` | SGW-U PFCP address. |
| `logging.level` | Log level. |
| `logging.file` | Log file path. |
| `api.listen` | SGW-C HTTP API listen address. |
| `metrics.listen` | SGW-C metrics listen address. |
| `shutdown.timeout_seconds` | Graceful shutdown timeout. |

Required SGW-C fields include `sgwc.node_id`, `sgwc.plmn.mcc`,
`sgwc.plmn.mnc`, `gtpc.s11.bind`, `gtpc.s5c.bind`, `pfcp.local_addr`, and at
least one `pfcp.sgwu` entry.

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
