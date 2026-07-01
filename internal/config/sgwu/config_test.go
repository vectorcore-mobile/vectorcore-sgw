package sgwuconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadNewLogicalGTPUSingleNICExample(t *testing.T) {
	cfg := loadExample(t, "sgw-u-single-nic.yaml")

	if cfg.GTPU.S1U.Bind != "my_user_plane" || cfg.GTPU.S5U.Bind != "my_user_plane" {
		t.Fatalf("single-NIC binds = %q/%q, want same arbitrary label my_user_plane", cfg.GTPU.S1U.Bind, cfg.GTPU.S5U.Bind)
	}
	if cfg.S1UInterface().Ifname != "eth0" {
		t.Fatalf("S1-U runtime ifname = %q, want eth0", cfg.S1UInterface().Ifname)
	}
	if cfg.S5UInterface().Ifname != "eth0" {
		t.Fatalf("S5-U runtime ifname = %q, want eth0", cfg.S5UInterface().Ifname)
	}
	s1uAddr, err := cfg.S1ULocalAddr()
	if err != nil {
		t.Fatalf("S1ULocalAddr: %v", err)
	}
	if s1uAddr.String() != "10.90.250.59" {
		t.Fatalf("S1-U local addr = %s", s1uAddr)
	}
	s5uAddr, err := cfg.S5ULocalAddr()
	if err != nil {
		t.Fatalf("S5ULocalAddr: %v", err)
	}
	if s5uAddr.String() != "10.90.250.59" {
		t.Fatalf("S5-U local addr = %s", s5uAddr)
	}
	if cfg.Dataplane.DriverMode != "xdp-generic" {
		t.Fatalf("driver mode = %q, want xdp-generic", cfg.Dataplane.DriverMode)
	}
}

func TestLoadNewLogicalGTPUDualNICExample(t *testing.T) {
	cfg := loadExample(t, "sgw-u-dual-nic.yaml")

	if cfg.GTPU.S1U.Bind != "my_enb_side" || cfg.GTPU.S5U.Bind != "my_pgw_side" {
		t.Fatalf("dual-NIC binds = %q/%q, want arbitrary labels my_enb_side/my_pgw_side", cfg.GTPU.S1U.Bind, cfg.GTPU.S5U.Bind)
	}
	if cfg.S1UInterface().Ifname != "eth0" {
		t.Fatalf("S1-U runtime ifname = %q, want eth0", cfg.S1UInterface().Ifname)
	}
	if cfg.S5UInterface().Ifname != "eth1" {
		t.Fatalf("S5-U runtime ifname = %q, want eth1", cfg.S5UInterface().Ifname)
	}
}

func TestLoadInteropLabConfig(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "..", "configs", "interop", "sgw-u-lab.yaml"))
	if err != nil {
		t.Fatalf("Load interop SGW-U lab config: %v", err)
	}

	if cfg.PFCP.Listen != "10.90.250.11:8805" {
		t.Fatalf("PFCP listen = %q; want 10.90.250.11:8805", cfg.PFCP.Listen)
	}
	if cfg.GTPU.S1U.Bind != "lab_user_plane" || cfg.GTPU.S5U.Bind != "lab_user_plane" {
		t.Fatalf("GTP-U binds = %q/%q; want shared lab_user_plane", cfg.GTPU.S1U.Bind, cfg.GTPU.S5U.Bind)
	}
	if cfg.S1UInterface().Ifname != "eth0" || cfg.S5UInterface().Ifname != "eth0" {
		t.Fatalf("GTP-U ifnames = %q/%q; want eth0/eth0", cfg.S1UInterface().Ifname, cfg.S5UInterface().Ifname)
	}
}

func TestValidateAcceptsArbitraryUserBindLabels(t *testing.T) {
	cfg := Default()
	cfg.SGWU.NodeID = "sgw-u-1"
	cfg.PFCP.Listen = "127.0.0.2:8805"
	cfg.PFCP.AllowedSGWC = []string{"127.0.0.1"}
	cfg.Interfaces.User = map[string]UserInterfaceConfig{
		"alpha": {Ifname: "eth0", Listen: "10.90.250.59:2152"},
		"bravo": {Ifname: "eth1", Listen: "10.90.251.59:2152"},
	}
	cfg.GTPU.S1U = GTPULogical{Bind: "alpha"}
	cfg.GTPU.S5U = GTPULogical{Bind: "bravo"}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate with arbitrary user bind labels: %v", err)
	}
}

func TestValidateAcceptsXDPNativeDriverMode(t *testing.T) {
	cfg := Default()
	cfg.SGWU.NodeID = "sgw-u-1"
	cfg.PFCP.Listen = "127.0.0.2:8805"
	cfg.PFCP.AllowedSGWC = []string{"127.0.0.1"}
	cfg.Interfaces.User = map[string]UserInterfaceConfig{
		"alpha": {Ifname: "eth0", Listen: "10.90.250.59:2152"},
		"bravo": {Ifname: "eth1", Listen: "10.90.251.59:2152"},
	}
	cfg.GTPU.S1U = GTPULogical{Bind: "alpha"}
	cfg.GTPU.S5U = GTPULogical{Bind: "bravo"}
	cfg.Dataplane.DriverMode = "xdp-native"

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate rejected xdp-native driver_mode: %v", err)
	}
}

func TestValidateRejectsUnsupportedDriverMode(t *testing.T) {
	cfg := Default()
	cfg.SGWU.NodeID = "sgw-u-1"
	cfg.PFCP.Listen = "127.0.0.2:8805"
	cfg.PFCP.AllowedSGWC = []string{"127.0.0.1"}
	cfg.Interfaces.User = map[string]UserInterfaceConfig{
		"alpha": {Ifname: "eth0", Listen: "10.90.250.59:2152"},
	}
	cfg.GTPU.S1U = GTPULogical{Bind: "alpha"}
	cfg.GTPU.S5U = GTPULogical{Bind: "alpha"}
	cfg.Dataplane.DriverMode = "tc"

	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate succeeded with unsupported driver_mode")
	}
}

func TestLoadRejectsOldUserPlaneConfigFields(t *testing.T) {
	path := writeTempConfig(t, `
sgwu:
  node_id: "sgw-u-1"
pfcp:
  listen: "127.0.0.2:8805"
  allowed_sgwc:
    - "127.0.0.1"
gtpu:
  access:
    ifname: "eth0"
    local_addr: "10.90.250.59"
  core:
    ifname: "eth1"
    local_addr: "10.90.251.59"
dataplane:
  driver_mode: "generic"
  unknown_teid: "punt"
  attach_on_start: true
  cleanup_on_exit: true
  map_max_entries: 65536
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load succeeded with old gtpu.access and gtpu.core fields")
	}
	if !strings.Contains(err.Error(), "field access not found") {
		t.Fatalf("Load error = %v, want unknown-field error for old user-plane config", err)
	}
}

func loadExample(t *testing.T, name string) *Config {
	t.Helper()
	cfg, err := Load(filepath.Join("..", "..", "..", "configs", "examples", name))
	if err != nil {
		t.Fatalf("Load(%s): %v", name, err)
	}
	return cfg
}

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "config-*.yaml")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	if _, err := f.WriteString(body); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close temp config: %v", err)
	}
	return f.Name()
}
