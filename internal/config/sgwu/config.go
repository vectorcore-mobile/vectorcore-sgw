package sgwuconfig

import (
	"fmt"
	"net"
	"net/netip"
	"os"

	"gopkg.in/yaml.v3"
)

const DefaultPath = "/etc/vectorcore/sgw/sgw-u.yaml"

type Config struct {
	SGWU       SGWUConfig      `yaml:"sgwu"`
	PFCP       PFCPConfig      `yaml:"pfcp"`
	Interfaces InterfaceConfig `yaml:"interfaces"`
	GTPU       GTPUConfig      `yaml:"gtpu"`
	Dataplane  DataplaneConfig `yaml:"dataplane"`
	Logging    LoggingConfig   `yaml:"logging"`
	API        APIConfig       `yaml:"api"`
	Metrics    MetricsConfig   `yaml:"metrics"`
	Shutdown   ShutdownConfig  `yaml:"shutdown"`
}

type SGWUConfig struct {
	NodeID string `yaml:"node_id"`
}

type PFCPConfig struct {
	Listen      string   `yaml:"listen"`
	AllowedSGWC []string `yaml:"allowed_sgwc"`
}

type InterfaceConfig struct {
	User map[string]UserInterfaceConfig `yaml:"user"`
}

type UserInterfaceConfig struct {
	Ifname string `yaml:"ifname"`
	Listen string `yaml:"listen"`
}

type GTPUConfig struct {
	S1U GTPULogical `yaml:"s1u"`
	S5U GTPULogical `yaml:"s5u"`
}

type GTPULogical struct {
	Bind string `yaml:"bind"`
}

type DataplaneConfig struct {
	// DriverMode selects the XDP attach mode: xdp-generic, xdp-native, or xdp-offload.
	DriverMode string `yaml:"driver_mode"`
	// UnknownTEID controls unknown-TEID behavior: "punt" or "drop". Default "punt".
	UnknownTEID string `yaml:"unknown_teid"`
	// AttachOnStart programs XDP hooks at startup when true. Default true.
	AttachOnStart bool `yaml:"attach_on_start"`
	// CleanupOnExit removes XDP hooks on shutdown when true. Default true.
	CleanupOnExit bool `yaml:"cleanup_on_exit"`
	// MapMaxEntries is the operator-facing eBPF map capacity setting.
	MapMaxEntries int `yaml:"map_max_entries"`
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
		Dataplane: DataplaneConfig{
			DriverMode:    "xdp-generic",
			UnknownTEID:   "punt",
			AttachOnStart: true,
			CleanupOnExit: true,
			MapMaxEntries: 65536,
		},
		Logging: LoggingConfig{Level: "info"},
		// AUD-06: default to loopback so management interfaces are not exposed
		// on all interfaces without explicit operator configuration.
		API:      APIConfig{Listen: "127.0.0.1:8081"},
		Metrics:  MetricsConfig{Listen: "127.0.0.1:9091"},
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

func (c *Config) S1UInterface() UserInterfaceConfig {
	return c.Interfaces.User[c.GTPU.S1U.Bind]
}

func (c *Config) S5UInterface() UserInterfaceConfig {
	return c.Interfaces.User[c.GTPU.S5U.Bind]
}

func (c *Config) GTPUListen() string {
	return c.S1UInterface().Listen
}

func (c *Config) S1ULocalAddr() (netip.Addr, error) {
	return listenHostAddr(c.S1UInterface().Listen)
}

func (c *Config) S5ULocalAddr() (netip.Addr, error) {
	return listenHostAddr(c.S5UInterface().Listen)
}

func listenHostAddr(listen string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("split listen address %q: %w", listen, err)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parse listen host %q: %w", host, err)
	}
	return addr.Unmap(), nil
}
