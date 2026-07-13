package sgwcconfig

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const DefaultPath = "/etc/vectorcore/sgw/sgw-c.yaml"

type Config struct {
	SGWC       SGWCConfig      `yaml:"sgwc"`
	Interfaces InterfaceConfig `yaml:"interfaces"`
	GTPC       GTPCConfig      `yaml:"gtpc"`
	PFCP       PFCPConfig      `yaml:"pfcp"`
	Features   FeaturesConfig  `yaml:"features"`
	QoS        QoSConfig       `yaml:"qos"`
	Logging    LoggingConfig   `yaml:"logging"`
	API        APIConfig       `yaml:"api"`
	Metrics    MetricsConfig   `yaml:"metrics"`
	Shutdown   ShutdownConfig  `yaml:"shutdown"`
	S11        S11Config       `yaml:"-"`
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
	S11                    S11Logical                   `yaml:"s11"`
	S5C                    GTPCLogical                  `yaml:"s5c"`
	Transactions           TransactionsConfig           `yaml:"transactions"`
	PeerHealth             PeerHealthConfig             `yaml:"peer_health"`
	CreateBearerRetryGuard CreateBearerRetryGuardConfig `yaml:"-"`
	TransactionCollision   TransactionCollisionConfig   `yaml:"-"`
	NSADCNR                NSADCNRConfig                `yaml:"-"`
	PGWFailure             PGWFailureConfig             `yaml:"-"`
	MMERestoration         MMERestorationConfig         `yaml:"-"`
	DDNControl             DDNControlConfig             `yaml:"-"`
	IdleDownlink           IdleDownlinkConfig           `yaml:"-"`
	SessionRecovery        SessionRecoveryConfig        `yaml:"-"`
	BearerInactivity       BearerInactivityConfig       `yaml:"-"`
}

type GTPCLogical struct {
	Bind string `yaml:"bind"`
}

type S11Logical struct {
	Bind   string    `yaml:"bind"`
	Timers S11Config `yaml:"timers"`
}

type TransactionsConfig struct {
	CreateBearerRetryGuard CreateBearerRetryGuardConfig `yaml:"create_bearer_retry_guard"`
	CollisionHandling      TransactionCollisionConfig   `yaml:"collision_handling"`
}

type FeaturesConfig struct {
	NSADCNR          NSADCNRConfig          `yaml:"nsa_dcnr"`
	PGWFailure       PGWFailureConfig       `yaml:"pgw_failure_handling"`
	MMERestoration   MMERestorationConfig   `yaml:"mme_restoration"`
	DDN              DDNControlConfig       `yaml:"ddn"`
	IdleDownlink     IdleDownlinkConfig     `yaml:"idle_downlink_notification"`
	SessionRecovery  SessionRecoveryConfig  `yaml:"session_recovery"`
	BearerInactivity BearerInactivityConfig `yaml:"bearer_inactivity"`
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
	Enabled                 bool                       `yaml:"enabled"`
	Timers                  PeerHealthTimersConfig     `yaml:"timers"`
	Thresholds              PeerHealthThresholdsConfig `yaml:"thresholds"`
	Probe                   PeerHealthProbeConfig      `yaml:"probe"`
	WarnOnDownPeerProcedure bool                       `yaml:"warn_on_down_peer_procedure"`
	EchoIntervalSeconds     int                        `yaml:"-"`
	EchoTimeoutSeconds      int                        `yaml:"-"`
	SuspectAfterMissed      int                        `yaml:"-"`
	DownAfterMissed         int                        `yaml:"-"`
	DegradedRTTMS           int                        `yaml:"-"`
	ProbeMMEPeers           bool                       `yaml:"-"`
	ProbePGWPeers           bool                       `yaml:"-"`
}

type PeerHealthTimersConfig struct {
	EchoIntervalSeconds int `yaml:"echo_interval_seconds"`
	EchoTimeoutSeconds  int `yaml:"echo_timeout_seconds"`
}
type PeerHealthThresholdsConfig struct {
	SuspectAfterMissed int `yaml:"suspect_after_missed"`
	DownAfterMissed    int `yaml:"down_after_missed"`
	DegradedRTTMS      int `yaml:"degraded_rtt_ms"`
}
type PeerHealthProbeConfig struct {
	MME bool `yaml:"mme"`
	PGW bool `yaml:"pgw"`
}

type PGWFailureConfig struct {
	Enabled                     bool                      `yaml:"enabled"`
	Detection                   PGWFailureDetectionConfig `yaml:"detection"`
	Actions                     PGWFailureActionsConfig   `yaml:"actions"`
	MarkSessionsOnPathDown      bool                      `yaml:"-"`
	MarkSessionsOnRestart       bool                      `yaml:"-"`
	BlockNewProceduresToDownPGW bool                      `yaml:"-"`
	NotifyMMEOnPGWRestart       bool                      `yaml:"-"`
}
type PGWFailureDetectionConfig struct {
	MarkSessionsOnPathDown bool `yaml:"mark_sessions_on_path_down"`
	MarkSessionsOnRestart  bool `yaml:"mark_sessions_on_restart"`
}
type PGWFailureActionsConfig struct {
	BlockNewProceduresToDownPGW bool `yaml:"block_new_procedures_to_down_pgw"`
	NotifyMMEOnPGWRestart       bool `yaml:"notify_mme_on_pgw_restart"`
}

type MMERestorationConfig struct {
	Enabled                bool                             `yaml:"enabled"`
	Detection              MMERestorationDetectionConfig    `yaml:"detection"`
	Actions                MMERestorationActionsConfig      `yaml:"actions"`
	Policy                 MMERestorationPolicyConfig       `yaml:"policy"`
	MarkSessionsOnPathDown bool                             `yaml:"-"`
	MarkSessionsOnRestart  bool                             `yaml:"-"`
	EnforceDeletePolicy    bool                             `yaml:"-"`
	TriggerDDN             bool                             `yaml:"-"`
	CleanupTimeoutSeconds  int                              `yaml:"-"`
	DefaultAction          string                           `yaml:"-"`
	Preserve               []MMERestorationPolicyRuleConfig `yaml:"-"`
	Delete                 []MMERestorationPolicyRuleConfig `yaml:"-"`
}
type MMERestorationDetectionConfig struct {
	MarkSessionsOnPathDown bool `yaml:"mark_sessions_on_path_down"`
	MarkSessionsOnRestart  bool `yaml:"mark_sessions_on_restart"`
}
type MMERestorationActionsConfig struct {
	EnforceDeletePolicy   bool   `yaml:"enforce_delete_policy"`
	TriggerDDN            bool   `yaml:"trigger_ddn"`
	CleanupTimeoutSeconds int    `yaml:"cleanup_timeout_seconds"`
	DefaultAction         string `yaml:"default_action"`
}
type MMERestorationPolicyConfig struct {
	Preserve []MMERestorationPolicyRuleConfig `yaml:"preserve"`
	Delete   []MMERestorationPolicyRuleConfig `yaml:"delete"`
}

type MMERestorationPolicyRuleConfig struct {
	APN            string    `yaml:"apn"`
	QCI            uint8     `yaml:"qci"`
	ARP            ARPConfig `yaml:"arp"`
	ARPPriorityMin uint8     `yaml:"-"`
	ARPPriorityMax uint8     `yaml:"-"`
}

type ARPConfig struct {
	PriorityMin uint8 `yaml:"priority_min"`
	PriorityMax uint8 `yaml:"priority_max"`
}

type DDNControlConfig struct {
	Enabled                       bool                           `yaml:"enabled"`
	RateLimit                     DDNRateLimitConfig             `yaml:"rate_limit"`
	LowPriorityThrottling         DDNLowPriorityConfig           `yaml:"low_priority_throttling"`
	DelayedQueue                  DDNDelayedQueueConfig          `yaml:"delayed_queue"`
	StopPaging                    DDNStopPagingConfig            `yaml:"stop_paging"`
	Policy                        DDNPolicyConfig                `yaml:"policy"`
	PerMMERateLimitPerSecond      int                            `yaml:"-"`
	PerMMEBurst                   int                            `yaml:"-"`
	PerUESuppressionSeconds       int                            `yaml:"-"`
	HonorMMELowPriorityThrottling bool                           `yaml:"-"`
	LowPriorityThrottleSeconds    int                            `yaml:"-"`
	HighPriorityBypass            bool                           `yaml:"-"`
	DelayedQueueMax               int                            `yaml:"-"`
	DelayedQueuePerMME            int                            `yaml:"-"`
	DelayedMaxAgeSeconds          int                            `yaml:"-"`
	StopPagingEnabled             bool                           `yaml:"-"`
	StopPagingOnDDNAck            bool                           `yaml:"-"`
	HighPriority                  []DDNControlPriorityRuleConfig `yaml:"-"`
	LowPriority                   []DDNControlPriorityRuleConfig `yaml:"-"`
}
type DDNRateLimitConfig struct {
	PerMMEPerSecond         int `yaml:"per_mme_per_second"`
	PerMMEBurst             int `yaml:"per_mme_burst"`
	PerUESuppressionSeconds int `yaml:"per_ue_suppression_seconds"`
}
type DDNLowPriorityConfig struct {
	HonorMMEThrottling bool `yaml:"honor_mme_throttling"`
	ThrottleSeconds    int  `yaml:"throttle_seconds"`
	HighPriorityBypass bool `yaml:"high_priority_bypass"`
}
type DDNDelayedQueueConfig struct {
	MaxEntries       int `yaml:"max_entries"`
	MaxEntriesPerMME int `yaml:"max_entries_per_mme"`
	MaxAgeSeconds    int `yaml:"max_age_seconds"`
}
type DDNStopPagingConfig struct {
	Enabled  bool `yaml:"enabled"`
	OnDDNAck bool `yaml:"on_ddn_ack"`
}
type DDNPolicyConfig struct {
	HighPriority []DDNControlPriorityRuleConfig `yaml:"high_priority"`
	LowPriority  []DDNControlPriorityRuleConfig `yaml:"low_priority"`
}

type DDNControlPriorityRuleConfig struct {
	APN            string    `yaml:"apn"`
	QCI            uint8     `yaml:"qci"`
	ARP            ARPConfig `yaml:"arp"`
	ARPPriorityMin uint8     `yaml:"-"`
	ARPPriorityMax uint8     `yaml:"-"`
}

type IdleDownlinkConfig struct {
	Enabled                  bool                           `yaml:"enabled"`
	Actions                  IdleDownlinkActionsConfig      `yaml:"actions"`
	Conditions               IdleDownlinkConditionsConfig   `yaml:"conditions"`
	Throttling               IdleDownlinkThrottlingConfig   `yaml:"throttling"`
	Policy                   IdleDownlinkPolicyConfig       `yaml:"policy"`
	TriggerDDN               bool                           `yaml:"-"`
	ReportThrottleSeconds    int                            `yaml:"-"`
	RequireReleaseAccessDrop bool                           `yaml:"-"`
	HighPriority             []DDNControlPriorityRuleConfig `yaml:"-"`
	Suppress                 []DDNControlPriorityRuleConfig `yaml:"-"`
}
type IdleDownlinkActionsConfig struct {
	TriggerDDN bool `yaml:"trigger_ddn"`
}
type IdleDownlinkConditionsConfig struct {
	RequireReleaseAccessDrop bool `yaml:"require_release_access_drop"`
}
type IdleDownlinkThrottlingConfig struct {
	ReportThrottleSeconds int `yaml:"report_throttle_seconds"`
}
type IdleDownlinkPolicyConfig struct {
	HighPriority []DDNControlPriorityRuleConfig `yaml:"high_priority"`
	Suppress     []DDNControlPriorityRuleConfig `yaml:"suppress"`
}

type SessionRecoveryConfig struct {
	Enabled                   bool                         `yaml:"enabled"`
	Storage                   SessionRecoveryStorageConfig `yaml:"storage"`
	Startup                   SessionRecoveryStartupConfig `yaml:"startup"`
	CheckpointIntervalSeconds int                          `yaml:"checkpoint_interval_seconds"`
	Backend                   string                       `yaml:"-"`
	SQLitePath                string                       `yaml:"-"`
	RestoreOnStartup          bool                         `yaml:"-"`
	ReconcileOnStartup        bool                         `yaml:"-"`
}
type SessionRecoveryStorageConfig struct {
	Backend    string `yaml:"backend"`
	SQLitePath string `yaml:"sqlite_path"`
}
type SessionRecoveryStartupConfig struct {
	Restore   bool `yaml:"restore"`
	Reconcile bool `yaml:"reconcile"`
}

type BearerInactivityConfig struct {
	Enabled                        bool                             `yaml:"enabled"`
	Timers                         BearerInactivityTimersConfig     `yaml:"timers"`
	Conditions                     BearerInactivityConditionsConfig `yaml:"conditions"`
	Actions                        BearerInactivityActionsConfig    `yaml:"actions"`
	Policy                         BearerInactivityPolicyConfig     `yaml:"policy"`
	CheckIntervalSeconds           int                              `yaml:"-"`
	DedicatedBearerIdleSeconds     int                              `yaml:"-"`
	PendingBearerTimeoutSeconds    int                              `yaml:"-"`
	DefaultBearerIdleSeconds       int                              `yaml:"-"`
	DeleteDefaultBearers           bool                             `yaml:"-"`
	RequireNoRecentControlActivity bool                             `yaml:"-"`
	Preserve                       []BearerInactivityRuleConfig     `yaml:"-"`
	Cleanup                        []BearerInactivityRuleConfig     `yaml:"-"`
}
type BearerInactivityTimersConfig struct {
	CheckIntervalSeconds        int `yaml:"check_interval_seconds"`
	DedicatedBearerIdleSeconds  int `yaml:"dedicated_bearer_idle_seconds"`
	PendingBearerTimeoutSeconds int `yaml:"pending_bearer_timeout_seconds"`
	DefaultBearerIdleSeconds    int `yaml:"default_bearer_idle_seconds"`
}
type BearerInactivityConditionsConfig struct {
	RequireNoRecentControlActivity bool `yaml:"require_no_recent_control_activity"`
}
type BearerInactivityActionsConfig struct {
	DeleteDefaultBearers bool `yaml:"delete_default_bearers"`
}
type BearerInactivityPolicyConfig struct {
	Preserve []BearerInactivityRuleConfig `yaml:"preserve"`
	Cleanup  []BearerInactivityRuleConfig `yaml:"cleanup"`
}

type BearerInactivityRuleConfig struct {
	APN            string    `yaml:"apn"`
	QCI            uint8     `yaml:"qci"`
	BearerType     string    `yaml:"bearer_type"`
	IdleSeconds    int       `yaml:"idle_seconds"`
	ARP            ARPConfig `yaml:"arp"`
	ARPPriorityMin uint8     `yaml:"-"`
	ARPPriorityMax uint8     `yaml:"-"`
}

type S11Config struct {
	// T3ResponseSeconds is the retransmit timeout per TS 29.274 §7.6. Default 3.
	T3ResponseSeconds int `yaml:"t3_response_seconds"`
	// N3Requests is the max retransmit count per TS 29.274 §7.6. Default 5.
	N3Requests int `yaml:"n3_requests"`
}

type PFCPConfig struct {
	LocalAddr string              `yaml:"local_addr"`
	SGWU      []SGWUPeer          `yaml:"sgwu"`
	Heartbeat PFCPHeartbeatConfig `yaml:"heartbeat"`
}
type PFCPHeartbeatConfig struct {
	HeartbeatIntervalSeconds int `yaml:"interval_seconds"`
	HeartbeatTimeoutSeconds  int `yaml:"timeout_seconds"`
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
	cfg := &Config{
		PFCP: PFCPConfig{
			Heartbeat: PFCPHeartbeatConfig{HeartbeatIntervalSeconds: 10, HeartbeatTimeoutSeconds: 30},
		},
		GTPC: GTPCConfig{
			S11: S11Logical{Timers: S11Config{T3ResponseSeconds: 3, N3Requests: 5}},
			Transactions: TransactionsConfig{
				CreateBearerRetryGuard: CreateBearerRetryGuardConfig{Enabled: true},
				CollisionHandling:      TransactionCollisionConfig{Mode: "strict", ActiveProcedureTimeoutSeconds: 120},
			},
			PeerHealth: PeerHealthConfig{
				Enabled:                 true,
				Timers:                  PeerHealthTimersConfig{EchoIntervalSeconds: 30, EchoTimeoutSeconds: 3},
				Thresholds:              PeerHealthThresholdsConfig{SuspectAfterMissed: 2, DownAfterMissed: 3, DegradedRTTMS: 500},
				Probe:                   PeerHealthProbeConfig{MME: true, PGW: true},
				WarnOnDownPeerProcedure: true,
			},
		},
		Features: FeaturesConfig{
			NSADCNR: NSADCNRConfig{Enabled: true, ForwardSecondaryRATUsageReports: true},
			PGWFailure: PGWFailureConfig{
				Enabled:   true,
				Detection: PGWFailureDetectionConfig{MarkSessionsOnPathDown: true, MarkSessionsOnRestart: true},
			},
			MMERestoration: MMERestorationConfig{
				Enabled:   true,
				Detection: MMERestorationDetectionConfig{MarkSessionsOnPathDown: true, MarkSessionsOnRestart: true},
				Actions:   MMERestorationActionsConfig{EnforceDeletePolicy: true, TriggerDDN: true, CleanupTimeoutSeconds: 30, DefaultAction: "preserve"},
				Policy: MMERestorationPolicyConfig{Preserve: []MMERestorationPolicyRuleConfig{
					{APN: "ims"}, {QCI: 1}, {ARP: ARPConfig{PriorityMin: 1, PriorityMax: 3}},
				}},
			},
			DDN: DDNControlConfig{
				Enabled:               true,
				RateLimit:             DDNRateLimitConfig{PerMMEPerSecond: 50, PerMMEBurst: 100, PerUESuppressionSeconds: 10},
				LowPriorityThrottling: DDNLowPriorityConfig{HonorMMEThrottling: true, ThrottleSeconds: 30, HighPriorityBypass: true},
				DelayedQueue:          DDNDelayedQueueConfig{MaxEntries: 1000, MaxEntriesPerMME: 200, MaxAgeSeconds: 30},
				Policy: DDNPolicyConfig{
					HighPriority: []DDNControlPriorityRuleConfig{{APN: "ims"}, {QCI: 1}, {ARP: ARPConfig{PriorityMin: 1, PriorityMax: 3}}},
					LowPriority:  []DDNControlPriorityRuleConfig{{APN: "internet", QCI: 9}},
				},
			},
			IdleDownlink: IdleDownlinkConfig{
				Actions:    IdleDownlinkActionsConfig{TriggerDDN: true},
				Conditions: IdleDownlinkConditionsConfig{RequireReleaseAccessDrop: true},
				Throttling: IdleDownlinkThrottlingConfig{ReportThrottleSeconds: 10},
				Policy: IdleDownlinkPolicyConfig{
					HighPriority: []DDNControlPriorityRuleConfig{{APN: "ims"}, {QCI: 1}, {ARP: ARPConfig{PriorityMin: 1, PriorityMax: 3}}},
					Suppress:     []DDNControlPriorityRuleConfig{{APN: "internet", QCI: 9}},
				},
			},
			SessionRecovery: SessionRecoveryConfig{
				Enabled:                   false,
				Storage:                   SessionRecoveryStorageConfig{Backend: "sqlite"},
				Startup:                   SessionRecoveryStartupConfig{Restore: true, Reconcile: true},
				CheckpointIntervalSeconds: 5,
			},
			BearerInactivity: BearerInactivityConfig{
				Timers:     BearerInactivityTimersConfig{CheckIntervalSeconds: 30, DedicatedBearerIdleSeconds: 300, PendingBearerTimeoutSeconds: 60},
				Conditions: BearerInactivityConditionsConfig{RequireNoRecentControlActivity: true},
				Policy: BearerInactivityPolicyConfig{
					Preserve: []BearerInactivityRuleConfig{{APN: "ims", QCI: 5, BearerType: "default"}, {QCI: 1}},
					Cleanup:  []BearerInactivityRuleConfig{{BearerType: "dedicated", IdleSeconds: 300}},
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
	cfg.linkRuntimeAliases()
	return cfg
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
		if strings.Contains(err.Error(), "field reason not found") {
			return nil, fmt.Errorf("parse config %q: policy reason fields are no longer supported; reasons are generated internally: %w", path, err)
		}
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}
	cfg.linkRuntimeAliases()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return cfg, nil
}

func (c *Config) linkRuntimeAliases() {
	c.S11 = c.GTPC.S11.Timers
	c.GTPC.CreateBearerRetryGuard = c.GTPC.Transactions.CreateBearerRetryGuard
	c.GTPC.TransactionCollision = c.GTPC.Transactions.CollisionHandling
	c.GTPC.NSADCNR = c.Features.NSADCNR
	c.GTPC.PGWFailure = c.Features.PGWFailure
	c.GTPC.MMERestoration = c.Features.MMERestoration
	c.GTPC.DDNControl = c.Features.DDN
	c.GTPC.IdleDownlink = c.Features.IdleDownlink
	c.GTPC.SessionRecovery = c.Features.SessionRecovery
	c.GTPC.BearerInactivity = c.Features.BearerInactivity
	p := &c.GTPC.PeerHealth
	p.EchoIntervalSeconds, p.EchoTimeoutSeconds = p.Timers.EchoIntervalSeconds, p.Timers.EchoTimeoutSeconds
	p.SuspectAfterMissed, p.DownAfterMissed, p.DegradedRTTMS = p.Thresholds.SuspectAfterMissed, p.Thresholds.DownAfterMissed, p.Thresholds.DegradedRTTMS
	p.ProbeMMEPeers, p.ProbePGWPeers = p.Probe.MME, p.Probe.PGW
	f := &c.Features.PGWFailure
	f.MarkSessionsOnPathDown, f.MarkSessionsOnRestart = f.Detection.MarkSessionsOnPathDown, f.Detection.MarkSessionsOnRestart
	f.BlockNewProceduresToDownPGW, f.NotifyMMEOnPGWRestart = f.Actions.BlockNewProceduresToDownPGW, f.Actions.NotifyMMEOnPGWRestart
	m := &c.Features.MMERestoration
	m.MarkSessionsOnPathDown, m.MarkSessionsOnRestart = m.Detection.MarkSessionsOnPathDown, m.Detection.MarkSessionsOnRestart
	m.EnforceDeletePolicy, m.TriggerDDN, m.CleanupTimeoutSeconds, m.DefaultAction = m.Actions.EnforceDeletePolicy, m.Actions.TriggerDDN, m.Actions.CleanupTimeoutSeconds, m.Actions.DefaultAction
	m.Preserve, m.Delete = m.Policy.Preserve, m.Policy.Delete
	d := &c.Features.DDN
	d.PerMMERateLimitPerSecond, d.PerMMEBurst, d.PerUESuppressionSeconds = d.RateLimit.PerMMEPerSecond, d.RateLimit.PerMMEBurst, d.RateLimit.PerUESuppressionSeconds
	d.HonorMMELowPriorityThrottling, d.LowPriorityThrottleSeconds, d.HighPriorityBypass = d.LowPriorityThrottling.HonorMMEThrottling, d.LowPriorityThrottling.ThrottleSeconds, d.LowPriorityThrottling.HighPriorityBypass
	d.DelayedQueueMax, d.DelayedQueuePerMME, d.DelayedMaxAgeSeconds = d.DelayedQueue.MaxEntries, d.DelayedQueue.MaxEntriesPerMME, d.DelayedQueue.MaxAgeSeconds
	d.StopPagingEnabled, d.StopPagingOnDDNAck = d.StopPaging.Enabled, d.StopPaging.OnDDNAck
	d.HighPriority, d.LowPriority = d.Policy.HighPriority, d.Policy.LowPriority
	i := &c.Features.IdleDownlink
	i.TriggerDDN, i.ReportThrottleSeconds, i.RequireReleaseAccessDrop = i.Actions.TriggerDDN, i.Throttling.ReportThrottleSeconds, i.Conditions.RequireReleaseAccessDrop
	i.HighPriority, i.Suppress = i.Policy.HighPriority, i.Policy.Suppress
	s := &c.Features.SessionRecovery
	s.Backend, s.SQLitePath, s.RestoreOnStartup, s.ReconcileOnStartup = s.Storage.Backend, s.Storage.SQLitePath, s.Startup.Restore, s.Startup.Reconcile
	b := &c.Features.BearerInactivity
	b.CheckIntervalSeconds, b.DedicatedBearerIdleSeconds, b.PendingBearerTimeoutSeconds, b.DefaultBearerIdleSeconds = b.Timers.CheckIntervalSeconds, b.Timers.DedicatedBearerIdleSeconds, b.Timers.PendingBearerTimeoutSeconds, b.Timers.DefaultBearerIdleSeconds
	b.DeleteDefaultBearers, b.RequireNoRecentControlActivity = b.Actions.DeleteDefaultBearers, b.Conditions.RequireNoRecentControlActivity
	b.Preserve, b.Cleanup = b.Policy.Preserve, b.Policy.Cleanup
	for n := range m.Preserve {
		linkMMERule(&m.Preserve[n])
	}
	for n := range m.Delete {
		linkMMERule(&m.Delete[n])
	}
	for n := range d.HighPriority {
		linkDDNRule(&d.HighPriority[n])
	}
	for n := range d.LowPriority {
		linkDDNRule(&d.LowPriority[n])
	}
	for n := range i.HighPriority {
		linkDDNRule(&i.HighPriority[n])
	}
	for n := range i.Suppress {
		linkDDNRule(&i.Suppress[n])
	}
	for n := range b.Preserve {
		linkBearerRule(&b.Preserve[n])
	}
	for n := range b.Cleanup {
		linkBearerRule(&b.Cleanup[n])
	}
	// Runtime code historically consumes these Go fields. They are excluded
	// from YAML and mirror the canonical nested schema after decoding.
	c.GTPC.PGWFailure = c.Features.PGWFailure
	c.GTPC.MMERestoration = c.Features.MMERestoration
	c.GTPC.DDNControl = c.Features.DDN
	c.GTPC.IdleDownlink = c.Features.IdleDownlink
	c.GTPC.SessionRecovery = c.Features.SessionRecovery
	c.GTPC.BearerInactivity = c.Features.BearerInactivity
}

func linkMMERule(r *MMERestorationPolicyRuleConfig) {
	r.ARPPriorityMin, r.ARPPriorityMax = r.ARP.PriorityMin, r.ARP.PriorityMax
}
func linkDDNRule(r *DDNControlPriorityRuleConfig) {
	r.ARPPriorityMin, r.ARPPriorityMax = r.ARP.PriorityMin, r.ARP.PriorityMax
}
func linkBearerRule(r *BearerInactivityRuleConfig) {
	r.ARPPriorityMin, r.ARPPriorityMax = r.ARP.PriorityMin, r.ARP.PriorityMax
}

func (c *Config) S11Listen() string {
	return c.Interfaces.Control[c.GTPC.S11.Bind].Listen
}

func (c *Config) S5CListen() string {
	return c.Interfaces.Control[c.GTPC.S5C.Bind].Listen
}
