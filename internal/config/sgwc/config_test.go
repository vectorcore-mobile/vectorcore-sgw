package sgwcconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadSharedControlExample(t *testing.T) {
	cfg := loadExample(t, "sgw-c-shared-control.yaml")

	if cfg.GTPC.S11.Bind != "my_control_plane" || cfg.GTPC.S5C.Bind != "my_control_plane" {
		t.Fatalf("shared-control binds = %q/%q, want same arbitrary label my_control_plane", cfg.GTPC.S11.Bind, cfg.GTPC.S5C.Bind)
	}
	if cfg.S11Listen() != "10.90.250.59:2123" {
		t.Fatalf("S11 listen = %q", cfg.S11Listen())
	}
	if cfg.S5CListen() != "10.90.250.59:2123" {
		t.Fatalf("S5-C local addr = %q", cfg.S5CListen())
	}
}

func TestLoadSplitControlExample(t *testing.T) {
	cfg := loadExample(t, "sgw-c-split-control.yaml")

	if cfg.GTPC.S11.Bind != "my_mme_side" || cfg.GTPC.S5C.Bind != "my_pgw_control_side" {
		t.Fatalf("split-control binds = %q/%q, want arbitrary labels my_mme_side/my_pgw_control_side", cfg.GTPC.S11.Bind, cfg.GTPC.S5C.Bind)
	}
	if cfg.S11Listen() != "10.90.250.59:2123" {
		t.Fatalf("S11 listen = %q", cfg.S11Listen())
	}
	if cfg.S5CListen() != "10.90.251.59:2123" {
		t.Fatalf("S5-C local addr = %q", cfg.S5CListen())
	}
}

func TestLoadMultiSGWUExample(t *testing.T) {
	cfg := loadExample(t, "sgw-c-multi-sgwu.yaml")

	if len(cfg.PFCP.SGWU) != 2 {
		t.Fatalf("PFCP SGW-U peers = %d; want 2", len(cfg.PFCP.SGWU))
	}
	if cfg.PFCP.SGWU[0].Name != "sgw-u-east" || cfg.PFCP.SGWU[1].Name != "sgw-u-west" {
		t.Fatalf("PFCP SGW-U peers = %+v; want east/west peers", cfg.PFCP.SGWU)
	}
	if cfg.S11Listen() != cfg.S5CListen() {
		t.Fatalf("multi-SGW-U example should use shared control bind, got %s/%s", cfg.S11Listen(), cfg.S5CListen())
	}
}

func TestLoadInteropLabConfig(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "..", "configs", "interop", "sgw-c-lab.yaml"))
	if err != nil {
		t.Fatalf("Load interop SGW-C lab config: %v", err)
	}

	if cfg.SGWC.ControlPlaneIP != "10.90.250.10" {
		t.Fatalf("control_plane_ip = %q; want 10.90.250.10", cfg.SGWC.ControlPlaneIP)
	}
	if cfg.S11Listen() != "10.90.250.10:2123" || cfg.S5CListen() != "10.90.250.10:2123" {
		t.Fatalf("interop control listens = %s/%s; want shared 10.90.250.10:2123",
			cfg.S11Listen(), cfg.S5CListen())
	}
	if len(cfg.PFCP.SGWU) != 1 || cfg.PFCP.SGWU[0].Addr != "10.90.250.11:8805" {
		t.Fatalf("PFCP SGW-U peers = %+v; want lab SGW-U at 10.90.250.11:8805", cfg.PFCP.SGWU)
	}
}

func TestValidateAcceptsArbitrarySharedControlBindLabel(t *testing.T) {
	cfg := Default()
	cfg.SGWC.NodeID = "sgw-c-1"
	cfg.SGWC.PLMN.MCC = "311"
	cfg.SGWC.PLMN.MNC = "435"
	cfg.Interfaces.Control = map[string]ControlInterfaceConfig{
		"zulu": {Listen: "10.90.250.59:2123"},
	}
	cfg.GTPC.S11 = GTPCLogical{Bind: "zulu"}
	cfg.GTPC.S5C = GTPCLogical{Bind: "zulu"}
	cfg.PFCP.LocalAddr = "127.0.0.1:8805"
	cfg.PFCP.SGWU = []SGWUPeer{{Name: "sgw-u-1", Addr: "127.0.0.2:8805"}}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate with arbitrary shared control bind label: %v", err)
	}
}

func TestValidateRejectsMissingControlBind(t *testing.T) {
	cfg := Default()
	cfg.SGWC.NodeID = "sgw-c-1"
	cfg.SGWC.PLMN.MCC = "311"
	cfg.SGWC.PLMN.MNC = "435"
	cfg.GTPC.S11.Bind = "missing"
	cfg.GTPC.S5C.Bind = "missing"
	cfg.PFCP.LocalAddr = "127.0.0.1:8805"
	cfg.PFCP.SGWU = []SGWUPeer{{Name: "sgw-u-1", Addr: "127.0.0.2:8805"}}

	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate succeeded with missing control bind")
	}
}

func TestDefaultCreateBearerRetryGuardEnabled(t *testing.T) {
	cfg := Default()
	if !cfg.GTPC.CreateBearerRetryGuard.Enabled {
		t.Fatal("default Create Bearer retry guard disabled; want enabled")
	}
}

func TestDefaultQoSOuterMarking(t *testing.T) {
	cfg := Default()
	if !cfg.QoS.OuterMarking.Enabled {
		t.Fatal("default QoS outer marking disabled; want enabled")
	}
	if !cfg.QoS.OuterMarking.GTPC.Enabled || cfg.QoS.OuterMarking.GTPC.DSCP != 40 {
		t.Fatalf("default GTP-C QoS = enabled:%v dscp:%d; want enabled:true dscp:40",
			cfg.QoS.OuterMarking.GTPC.Enabled, cfg.QoS.OuterMarking.GTPC.DSCP)
	}
	if !cfg.QoS.OuterMarking.PFCP.Enabled || cfg.QoS.OuterMarking.PFCP.DSCP != 40 {
		t.Fatalf("default PFCP QoS = enabled:%v dscp:%d; want enabled:true dscp:40",
			cfg.QoS.OuterMarking.PFCP.Enabled, cfg.QoS.OuterMarking.PFCP.DSCP)
	}
}

func TestValidateRejectsInvalidQoSDSCP(t *testing.T) {
	cfg := validTestConfig()
	cfg.QoS.OuterMarking.GTPC.DSCP = 64
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate succeeded with qos.outer_marking.gtpc.dscp=64")
	}

	cfg = validTestConfig()
	cfg.QoS.OuterMarking.PFCP.DSCP = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate succeeded with qos.outer_marking.pfcp.dscp=-1")
	}
}

func TestLoadPrimaryConfigHasNoCreateBearerInteropLimit(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "..", "configs", "sgw-c.yaml"))
	if err != nil {
		t.Fatalf("Load primary SGW-C config: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "configs", "sgw-c.yaml"))
	if err != nil {
		t.Fatalf("Read primary SGW-C config: %v", err)
	}
	if strings.Contains(string(raw), "s11_create_bearer_max_contexts") {
		t.Fatal("primary SGW-C config still contains removed s11_create_bearer_max_contexts key")
	}
	_ = cfg
}

func TestLoadRejectsOldControlConfigFields(t *testing.T) {
	path := writeTempConfig(t, `
sgwc:
  node_id: "sgw-c-1"
  plmn:
    mcc: "311"
    mnc: "435"
s11:
  listen: "10.90.250.59:2123"
s5c:
  local_addr: "10.90.250.59"
pfcp:
  local_addr: "127.0.0.1:8805"
  sgwu:
    - name: "sgw-u-1"
      addr: "127.0.0.2:8805"
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load succeeded with old s11.listen and s5c.local_addr fields")
	}
	if !strings.Contains(err.Error(), "field listen not found") {
		t.Fatalf("Load error = %v, want unknown-field error for old control config", err)
	}
}

func TestLoadRejectsTopLevelS5CConfig(t *testing.T) {
	path := writeTempConfig(t, `
sgwc:
  node_id: "sgw-c-1"
  plmn:
    mcc: "311"
    mnc: "435"
interfaces:
  control:
    control_plane:
      listen: "10.90.250.59:2123"
gtpc:
  s11:
    bind: "control_plane"
  s5c:
    bind: "control_plane"
s11:
  t3_response_seconds: 3
  n3_requests: 5
s5c:
  t3_response_seconds: 3
  n3_requests: 5
pfcp:
  local_addr: "127.0.0.1:8805"
  sgwu:
    - name: "sgw-u-1"
      addr: "127.0.0.2:8805"
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load succeeded with removed top-level s5c config")
	}
	if !strings.Contains(err.Error(), "field s5c not found") {
		t.Fatalf("Load error = %v, want unknown-field error for removed top-level s5c config", err)
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

func validTestConfig() *Config {
	cfg := Default()
	cfg.SGWC.NodeID = "sgw-c-1"
	cfg.SGWC.PLMN.MCC = "311"
	cfg.SGWC.PLMN.MNC = "435"
	cfg.Interfaces.Control = map[string]ControlInterfaceConfig{
		"control": {Listen: "127.0.0.1:2123"},
	}
	cfg.GTPC.S11 = GTPCLogical{Bind: "control"}
	cfg.GTPC.S5C = GTPCLogical{Bind: "control"}
	cfg.PFCP.LocalAddr = "127.0.0.1:8805"
	cfg.PFCP.SGWU = []SGWUPeer{{Name: "sgw-u-1", Addr: "127.0.0.2:8805"}}
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
