package sgwcconfig

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

const DefaultPath = "/etc/vectorcore/sgw/sgw-c.yaml"

type Config struct {
	SGWC       SGWCConfig      `yaml:"sgwc"`
	Interfaces InterfaceConfig `yaml:"interfaces"`
	GTPC       GTPCConfig      `yaml:"gtpc"`
	S11        S11Config       `yaml:"s11"`
	PFCP       PFCPConfig      `yaml:"pfcp"`
	QoS        QoSConfig       `yaml:"qos"`
	Logging    LoggingConfig   `yaml:"logging"`
	API        APIConfig       `yaml:"api"`
	Metrics    MetricsConfig   `yaml:"metrics"`
	Shutdown   ShutdownConfig  `yaml:"shutdown"`
}

type SGWCConfig struct {
	NodeID string     `yaml:"node_id"`
	PLMN   PLMNConfig `yaml:"plmn"`
	// StateDir is the directory for persisted runtime state (e.g., recovery counter).
	// Defaults to /var/lib/vectorcore-sgw if empty.
	StateDir string `yaml:"state_dir"`
	// ControlPlaneIP is the SGW-C control-plane IP address included in Sender F-TEID IEs
	// on S11 and S5/S8-C per TS 29.274 §8.22. If empty, the IP is derived from the
	// respective listen address (not valid when listening on 0.0.0.0).
	ControlPlaneIP string `yaml:"control_plane_ip"`
}

type PLMNConfig struct {
	MCC string `yaml:"mcc"`
	MNC string `yaml:"mnc"`
}

type InterfaceConfig struct {
	Control map[string]ControlInterfaceConfig `yaml:"control"`
}

type ControlInterfaceConfig struct {
	Listen string `yaml:"listen"`
}

type GTPCConfig struct {
	S11                    GTPCLogical                  `yaml:"s11"`
	S5C                    GTPCLogical                  `yaml:"s5c"`
	CreateBearerRetryGuard CreateBearerRetryGuardConfig `yaml:"create_bearer_retry_guard"`
	TransactionCollision   TransactionCollisionConfig   `yaml:"transaction_collision"`
	NSADCNR                NSADCNRConfig                `yaml:"nsa_dcnr"`
}

type GTPCLogical struct {
	Bind string `yaml:"bind"`
}

type CreateBearerRetryGuardConfig struct {
	Enabled bool `yaml:"enabled"`
}

type TransactionCollisionConfig struct {
	// Mode controls GTPv2-C active procedure collision handling.
	// strict keeps conservative carrier-safe behavior.
	// permissive allows bearer-scoped overlaps only when one request has no decoded EBI scope.
	Mode string `yaml:"mode"`
	// ActiveProcedureTimeoutSeconds bounds stale in-flight procedure state.
	ActiveProcedureTimeoutSeconds int `yaml:"active_procedure_timeout_seconds"`
}

type NSADCNRConfig struct {
	// Enabled controls Rel-15 EPC NSA/DCNR awareness in SGW-C.
	Enabled bool `yaml:"enabled"`
	// ForwardSecondaryRATUsageReports forwards S11 Secondary RAT Usage Data Report IEs
	// to the owning PGW over S5/S8-C Modify Bearer.
	ForwardSecondaryRATUsageReports bool `yaml:"forward_secondary_rat_usage_reports"`
}

type S11Config struct {
	// T3ResponseSeconds is the retransmit timeout per TS 29.274 §7.6. Default 3.
	T3ResponseSeconds int `yaml:"t3_response_seconds"`
	// N3Requests is the max retransmit count per TS 29.274 §7.6. Default 5.
	N3Requests int `yaml:"n3_requests"`
}

type PFCPConfig struct {
	LocalAddr string     `yaml:"local_addr"`
	SGWU      []SGWUPeer `yaml:"sgwu"`
	// HeartbeatIntervalSeconds controls Sxa heartbeat cadence. Default 10.
	HeartbeatIntervalSeconds int `yaml:"heartbeat_interval_seconds"`
	// HeartbeatTimeoutSeconds before marking a peer unavailable. Default 30.
	HeartbeatTimeoutSeconds int `yaml:"heartbeat_timeout_seconds"`
}

type SGWUPeer struct {
	Name   string `yaml:"name"`
	NodeID string `yaml:"node_id"`
	Addr   string `yaml:"addr"`
}

type QoSConfig struct {
	OuterMarking OuterMarkingConfig `yaml:"outer_marking"`
}

type OuterMarkingConfig struct {
	Enabled bool                  `yaml:"enabled"`
	GTPC    ProtocolMarkingConfig `yaml:"gtpc"`
	PFCP    ProtocolMarkingConfig `yaml:"pfcp"`
}

type ProtocolMarkingConfig struct {
	Enabled bool `yaml:"enabled"`
	DSCP    int  `yaml:"dscp"`
}

type LoggingConfig struct {
	Level string `yaml:"level"`
	File  string `yaml:"file"`
}

type APIConfig struct {
	Listen string `yaml:"listen"`
}

type MetricsConfig struct {
	Listen string `yaml:"listen"`
}

type ShutdownConfig struct {
	TimeoutSeconds int `yaml:"timeout_seconds"`
}

func Default() *Config {
	return &Config{
		S11: S11Config{
			T3ResponseSeconds: 3,
			N3Requests:        5,
		},
		PFCP: PFCPConfig{
			HeartbeatIntervalSeconds: 10,
			HeartbeatTimeoutSeconds:  30,
		},
		GTPC: GTPCConfig{
			CreateBearerRetryGuard: CreateBearerRetryGuardConfig{
				Enabled: true,
			},
			TransactionCollision: TransactionCollisionConfig{
				Mode:                          "strict",
				ActiveProcedureTimeoutSeconds: 120,
			},
			NSADCNR: NSADCNRConfig{
				Enabled:                         true,
				ForwardSecondaryRATUsageReports: true,
			},
		},
		QoS: QoSConfig{
			OuterMarking: OuterMarkingConfig{
				Enabled: true,
				GTPC:    ProtocolMarkingConfig{Enabled: true, DSCP: 40},
				PFCP:    ProtocolMarkingConfig{Enabled: true, DSCP: 40},
			},
		},
		Logging: LoggingConfig{Level: "info"},
		// AUD-06: default to loopback so management interfaces are not exposed
		// on all interfaces without explicit operator configuration.
		API:      APIConfig{Listen: "127.0.0.1:8080"},
		Metrics:  MetricsConfig{Listen: "127.0.0.1:9090"},
		Shutdown: ShutdownConfig{TimeoutSeconds: 5},
	}
}

func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultPath
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config %q: %w", path, err)
	}
	defer f.Close()

	cfg := Default()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return cfg, nil
}

func (c *Config) S11Listen() string {
	return c.Interfaces.Control[c.GTPC.S11.Bind].Listen
}

func (c *Config) S5CListen() string {
	return c.Interfaces.Control[c.GTPC.S5C.Bind].Listen
}
