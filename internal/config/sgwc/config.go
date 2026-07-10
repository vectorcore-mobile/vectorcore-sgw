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
	PeerHealth             PeerHealthConfig             `yaml:"peer_health"`
	PGWFailure             PGWFailureConfig             `yaml:"pgw_failure"`
	MMERestoration         MMERestorationConfig         `yaml:"mme_restoration"`
	DDNControl             DDNControlConfig             `yaml:"ddn_control"`
	IdleDownlink           IdleDownlinkConfig           `yaml:"idle_downlink_notification"`
	SessionRecovery        SessionRecoveryConfig        `yaml:"session_recovery"`
	BearerInactivity       BearerInactivityConfig       `yaml:"bearer_inactivity"`
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

type PeerHealthConfig struct {
	Enabled                 bool `yaml:"enabled"`
	EchoIntervalSeconds     int  `yaml:"echo_interval_seconds"`
	EchoTimeoutSeconds      int  `yaml:"echo_timeout_seconds"`
	SuspectAfterMissed      int  `yaml:"suspect_after_missed"`
	DownAfterMissed         int  `yaml:"down_after_missed"`
	DegradedRTTMS           int  `yaml:"degraded_rtt_ms"`
	ProbeMMEPeers           bool `yaml:"probe_mme_peers"`
	ProbePGWPeers           bool `yaml:"probe_pgw_peers"`
	WarnOnDownPeerProcedure bool `yaml:"warn_on_down_peer_procedure"`
}

type PGWFailureConfig struct {
	Enabled                     bool `yaml:"enabled"`
	MarkSessionsOnPathDown      bool `yaml:"mark_sessions_on_path_down"`
	MarkSessionsOnRestart       bool `yaml:"mark_sessions_on_restart"`
	BlockNewProceduresToDownPGW bool `yaml:"block_new_procedures_to_down_pgw"`
	NotifyMMEOnPGWRestart       bool `yaml:"notify_mme_on_pgw_restart"`
}

type MMERestorationConfig struct {
	Enabled                bool                             `yaml:"enabled"`
	MarkSessionsOnPathDown bool                             `yaml:"mark_sessions_on_path_down"`
	MarkSessionsOnRestart  bool                             `yaml:"mark_sessions_on_restart"`
	EnforceDeletePolicy    bool                             `yaml:"enforce_delete_policy"`
	TriggerDDN             bool                             `yaml:"trigger_ddn"`
	CleanupTimeoutSeconds  int                              `yaml:"cleanup_timeout_seconds"`
	DefaultAction          string                           `yaml:"default_action"`
	Preserve               []MMERestorationPolicyRuleConfig `yaml:"preserve"`
	Delete                 []MMERestorationPolicyRuleConfig `yaml:"delete"`
}

type MMERestorationPolicyRuleConfig struct {
	APN            string `yaml:"apn"`
	QCI            uint8  `yaml:"qci"`
	ARPPriorityMin uint8  `yaml:"arp_priority_min"`
	ARPPriorityMax uint8  `yaml:"arp_priority_max"`
	Reason         string `yaml:"reason"`
}

type DDNControlConfig struct {
	Enabled                       bool                           `yaml:"enabled"`
	PerMMERateLimitPerSecond      int                            `yaml:"per_mme_rate_limit_per_second"`
	PerMMEBurst                   int                            `yaml:"per_mme_burst"`
	PerUESuppressionSeconds       int                            `yaml:"per_ue_suppression_seconds"`
	HonorMMELowPriorityThrottling bool                           `yaml:"honor_mme_low_priority_throttling"`
	LowPriorityThrottleSeconds    int                            `yaml:"low_priority_throttle_seconds"`
	HighPriorityBypass            bool                           `yaml:"high_priority_bypass"`
	DelayedQueueMax               int                            `yaml:"delayed_queue_max"`
	DelayedQueuePerMME            int                            `yaml:"delayed_queue_per_mme"`
	DelayedMaxAgeSeconds          int                            `yaml:"delayed_max_age_seconds"`
	StopPagingEnabled             bool                           `yaml:"stop_paging_enabled"`
	StopPagingOnDDNAck            bool                           `yaml:"stop_paging_on_ddn_ack"`
	HighPriority                  []DDNControlPriorityRuleConfig `yaml:"high_priority"`
	LowPriority                   []DDNControlPriorityRuleConfig `yaml:"low_priority"`
}

type DDNControlPriorityRuleConfig struct {
	APN            string `yaml:"apn"`
	QCI            uint8  `yaml:"qci"`
	ARPPriorityMin uint8  `yaml:"arp_priority_min"`
	ARPPriorityMax uint8  `yaml:"arp_priority_max"`
	Reason         string `yaml:"reason"`
}

type IdleDownlinkConfig struct {
	Enabled                  bool                           `yaml:"enabled"`
	TriggerDDN               bool                           `yaml:"trigger_ddn"`
	ReportThrottleSeconds    int                            `yaml:"report_throttle_seconds"`
	RequireReleaseAccessDrop bool                           `yaml:"require_release_access_drop"`
	HighPriority             []DDNControlPriorityRuleConfig `yaml:"high_priority"`
	Suppress                 []DDNControlPriorityRuleConfig `yaml:"suppress"`
}

type SessionRecoveryConfig struct {
	Enabled                   bool   `yaml:"enabled"`
	Backend                   string `yaml:"backend"`
	SQLitePath                string `yaml:"sqlite_path"`
	RestoreOnStartup          bool   `yaml:"restore_on_startup"`
	ReconcileOnStartup        bool   `yaml:"reconcile_on_startup"`
	CheckpointIntervalSeconds int    `yaml:"checkpoint_interval_seconds"`
}

type BearerInactivityConfig struct {
	Enabled                        bool                         `yaml:"enabled"`
	CheckIntervalSeconds           int                          `yaml:"check_interval_seconds"`
	DedicatedBearerIdleSeconds     int                          `yaml:"dedicated_bearer_idle_seconds"`
	PendingBearerTimeoutSeconds    int                          `yaml:"pending_bearer_timeout_seconds"`
	DefaultBearerIdleSeconds       int                          `yaml:"default_bearer_idle_seconds"`
	DeleteDefaultBearers           bool                         `yaml:"delete_default_bearers"`
	RequireNoRecentControlActivity bool                         `yaml:"require_no_recent_control_activity"`
	Preserve                       []BearerInactivityRuleConfig `yaml:"preserve"`
	Cleanup                        []BearerInactivityRuleConfig `yaml:"cleanup"`
}

type BearerInactivityRuleConfig struct {
	APN            string `yaml:"apn"`
	QCI            uint8  `yaml:"qci"`
	BearerType     string `yaml:"bearer_type"`
	IdleSeconds    int    `yaml:"idle_seconds"`
	ARPPriorityMin uint8  `yaml:"arp_priority_min"`
	ARPPriorityMax uint8  `yaml:"arp_priority_max"`
	Reason         string `yaml:"reason"`
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
			PeerHealth: PeerHealthConfig{
				Enabled:                 true,
				EchoIntervalSeconds:     30,
				EchoTimeoutSeconds:      3,
				SuspectAfterMissed:      2,
				DownAfterMissed:         3,
				DegradedRTTMS:           500,
				ProbeMMEPeers:           true,
				ProbePGWPeers:           true,
				WarnOnDownPeerProcedure: true,
			},
			PGWFailure: PGWFailureConfig{
				Enabled:                     true,
				MarkSessionsOnPathDown:      true,
				MarkSessionsOnRestart:       true,
				BlockNewProceduresToDownPGW: false,
				NotifyMMEOnPGWRestart:       false,
			},
			MMERestoration: MMERestorationConfig{
				Enabled:                true,
				MarkSessionsOnPathDown: true,
				MarkSessionsOnRestart:  true,
				EnforceDeletePolicy:    true,
				TriggerDDN:             true,
				CleanupTimeoutSeconds:  30,
				DefaultAction:          "preserve",
				Preserve: []MMERestorationPolicyRuleConfig{
					{APN: "ims", Reason: "default-preserve-ims"},
					{QCI: 1, Reason: "default-preserve-qci-1"},
					{ARPPriorityMin: 1, ARPPriorityMax: 3, Reason: "default-preserve-high-priority-arp"},
				},
			},
			DDNControl: DDNControlConfig{
				Enabled:                       true,
				PerMMERateLimitPerSecond:      50,
				PerMMEBurst:                   100,
				PerUESuppressionSeconds:       10,
				HonorMMELowPriorityThrottling: true,
				LowPriorityThrottleSeconds:    30,
				HighPriorityBypass:            true,
				DelayedQueueMax:               1000,
				DelayedQueuePerMME:            200,
				DelayedMaxAgeSeconds:          30,
				StopPagingEnabled:             false,
				StopPagingOnDDNAck:            false,
				HighPriority: []DDNControlPriorityRuleConfig{
					{APN: "ims", Reason: "default-high-priority-ims"},
					{QCI: 1, Reason: "default-high-priority-qci-1"},
					{ARPPriorityMin: 1, ARPPriorityMax: 3, Reason: "default-high-priority-arp"},
				},
				LowPriority: []DDNControlPriorityRuleConfig{
					{APN: "internet", QCI: 9, Reason: "default-low-priority-internet-qci-9"},
				},
			},
			IdleDownlink: IdleDownlinkConfig{
				Enabled:                  false,
				TriggerDDN:               true,
				ReportThrottleSeconds:    10,
				RequireReleaseAccessDrop: true,
				HighPriority: []DDNControlPriorityRuleConfig{
					{APN: "ims", Reason: "default-idle-downlink-ims"},
					{QCI: 1, Reason: "default-idle-downlink-qci-1"},
					{ARPPriorityMin: 1, ARPPriorityMax: 3, Reason: "default-idle-downlink-high-arp"},
				},
				Suppress: []DDNControlPriorityRuleConfig{
					{APN: "internet", QCI: 9, Reason: "default-idle-downlink-suppress-low-priority-internet"},
				},
			},
			SessionRecovery: SessionRecoveryConfig{
				Enabled:                   false,
				Backend:                   "sqlite",
				SQLitePath:                "",
				RestoreOnStartup:          true,
				ReconcileOnStartup:        true,
				CheckpointIntervalSeconds: 5,
			},
			BearerInactivity: BearerInactivityConfig{
				Enabled:                        false,
				CheckIntervalSeconds:           30,
				DedicatedBearerIdleSeconds:     300,
				PendingBearerTimeoutSeconds:    60,
				DefaultBearerIdleSeconds:       0,
				DeleteDefaultBearers:           false,
				RequireNoRecentControlActivity: true,
				Preserve: []BearerInactivityRuleConfig{
					{APN: "ims", QCI: 5, BearerType: "default", Reason: "default-preserve-ims-signaling"},
					{QCI: 1, Reason: "default-preserve-conversational-bearer"},
				},
				Cleanup: []BearerInactivityRuleConfig{
					{BearerType: "dedicated", IdleSeconds: 300, Reason: "default-cleanup-idle-dedicated-bearer"},
				},
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
