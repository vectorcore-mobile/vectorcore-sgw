package sgwuconfig

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

const DefaultPath = "/etc/vectorcore/sgw/sgw-u.yaml"

type Config struct {
	SGWU     SGWUConfig     `yaml:"sgwu"`
	PFCP     PFCPConfig     `yaml:"pfcp"`
	GTPU     GTPUConfig     `yaml:"gtpu"`
	Dataplane DataplaneConfig `yaml:"dataplane"`
	Logging  LoggingConfig  `yaml:"logging"`
	API      APIConfig      `yaml:"api"`
	Metrics  MetricsConfig  `yaml:"metrics"`
	Shutdown ShutdownConfig `yaml:"shutdown"`
}

type SGWUConfig struct {
	NodeID string `yaml:"node_id"`
}

type PFCPConfig struct {
	Listen      string   `yaml:"listen"`
	AllowedSGWC []string `yaml:"allowed_sgwc"`
}

type GTPUConfig struct {
	// Listen is the UDP address for the GTP-U userspace forwarder, default "0.0.0.0:2152".
	// Port 2152 is mandated by TS 29.281 §4.4.2.1:
	// "The port number for GTP-U request messages is 2152."
	// Only used when dataplane.mode = "userspace".
	Listen string       `yaml:"listen"`
	Access GTPUIfConfig `yaml:"access"`
	Core   GTPUIfConfig `yaml:"core"`
}

type GTPUIfConfig struct {
	Ifname    string `yaml:"ifname"`
	LocalAddr string `yaml:"local_addr"`
}

type DataplaneConfig struct {
	// Mode is "tc-bpf" or "userspace". Default "tc-bpf".
	Mode string `yaml:"mode"`
	// UnknownTEID controls unknown-TEID behavior: "punt" or "drop". Default "punt".
	UnknownTEID string `yaml:"unknown_teid"`
	// AttachOnStart programs TC hooks at startup when true. Default true.
	AttachOnStart bool `yaml:"attach_on_start"`
	// CleanupOnExit removes TC hooks on shutdown when true. Default true.
	CleanupOnExit bool `yaml:"cleanup_on_exit"`
	// BPFMapMaxEntries is the max entries per BPF forwarding map. Default 65536.
	BPFMapMaxEntries int `yaml:"bpf_map_max_entries"`
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
		GTPU: GTPUConfig{
			Listen: "0.0.0.0:2152",
		},
		Dataplane: DataplaneConfig{
			Mode:             "tc-bpf",
			UnknownTEID:      "punt",
			AttachOnStart:    true,
			CleanupOnExit:    true,
			BPFMapMaxEntries: 65536,
		},
		Logging:  LoggingConfig{Level: "info"},
		// AUD-06: default to loopback so management interfaces are not exposed
		// on all interfaces without explicit operator configuration.
		API:     APIConfig{Listen: "127.0.0.1:8081"},
		Metrics: MetricsConfig{Listen: "127.0.0.1:9091"},
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
