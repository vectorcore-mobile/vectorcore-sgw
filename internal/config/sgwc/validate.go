package sgwcconfig

import "fmt"

func (c *Config) Validate() error {
	if c.SGWC.NodeID == "" {
		return fmt.Errorf("sgwc.node_id is required")
	}
	if c.SGWC.PLMN.MCC == "" {
		return fmt.Errorf("sgwc.plmn.mcc is required")
	}
	if c.SGWC.PLMN.MNC == "" {
		return fmt.Errorf("sgwc.plmn.mnc is required")
	}
	for name, iface := range c.Interfaces.Control {
		if iface.Listen == "" {
			return fmt.Errorf("interfaces.control.%s.listen is required", name)
		}
	}
	if c.GTPC.S11.Bind == "" {
		return fmt.Errorf("gtpc.s11.bind is required")
	}
	if _, ok := c.Interfaces.Control[c.GTPC.S11.Bind]; !ok {
		return fmt.Errorf("gtpc.s11.bind %q does not reference interfaces.control", c.GTPC.S11.Bind)
	}
	if c.GTPC.S5C.Bind == "" {
		return fmt.Errorf("gtpc.s5c.bind is required")
	}
	if _, ok := c.Interfaces.Control[c.GTPC.S5C.Bind]; !ok {
		return fmt.Errorf("gtpc.s5c.bind %q does not reference interfaces.control", c.GTPC.S5C.Bind)
	}
	if c.PFCP.LocalAddr == "" {
		return fmt.Errorf("pfcp.local_addr is required")
	}
	if len(c.PFCP.SGWU) == 0 {
		return fmt.Errorf("pfcp.sgwu must have at least one entry")
	}
	for i, peer := range c.PFCP.SGWU {
		if peer.Name == "" {
			return fmt.Errorf("pfcp.sgwu[%d].name is required", i)
		}
		if peer.Addr == "" {
			return fmt.Errorf("pfcp.sgwu[%d].addr is required", i)
		}
	}
	if c.S11.T3ResponseSeconds <= 0 {
		return fmt.Errorf("s11.t3_response_seconds must be positive")
	}
	if c.S11.N3Requests <= 0 {
		return fmt.Errorf("s11.n3_requests must be positive")
	}
	switch c.GTPC.TransactionCollision.Mode {
	case "strict", "permissive":
	default:
		return fmt.Errorf("gtpc.transaction_collision.mode must be strict or permissive, got %q", c.GTPC.TransactionCollision.Mode)
	}
	if c.GTPC.TransactionCollision.ActiveProcedureTimeoutSeconds <= 0 {
		return fmt.Errorf("gtpc.transaction_collision.active_procedure_timeout_seconds must be positive")
	}
	if err := c.validatePeerHealth(); err != nil {
		return err
	}
	if err := c.validatePGWFailure(); err != nil {
		return err
	}
	if err := c.validateMMERestoration(); err != nil {
		return err
	}
	if err := c.validateDDNControl(); err != nil {
		return err
	}
	if err := c.validateIdleDownlink(); err != nil {
		return err
	}
	if err := c.validateSessionRecovery(); err != nil {
		return err
	}
	if err := c.validateBearerInactivity(); err != nil {
		return err
	}
	if err := validateDSCP("qos.outer_marking.gtpc.dscp", c.QoS.OuterMarking.GTPC.DSCP); err != nil {
		return err
	}
	if err := validateDSCP("qos.outer_marking.pfcp.dscp", c.QoS.OuterMarking.PFCP.DSCP); err != nil {
		return err
	}
	return nil
}

func (c *Config) validatePGWFailure() error {
	if c.GTPC.PGWFailure.NotifyMMEOnPGWRestart {
		return fmt.Errorf("gtpc.pgw_failure.notify_mme_on_pgw_restart is not supported yet; PGW restart notification requires TS 29.274 message support and MME lab validation")
	}
	return nil
}

func (c *Config) validateMMERestoration() error {
	mr := c.GTPC.MMERestoration
	if mr.CleanupTimeoutSeconds <= 0 {
		return fmt.Errorf("gtpc.mme_restoration.cleanup_timeout_seconds must be positive")
	}
	switch mr.DefaultAction {
	case "", "preserve", "delete":
	default:
		return fmt.Errorf("gtpc.mme_restoration.default_action must be preserve or delete, got %q", mr.DefaultAction)
	}
	for i, rule := range mr.Preserve {
		if err := validateMMERestorationRule(fmt.Sprintf("gtpc.mme_restoration.preserve[%d]", i), rule); err != nil {
			return err
		}
	}
	for i, rule := range mr.Delete {
		if err := validateMMERestorationRule(fmt.Sprintf("gtpc.mme_restoration.delete[%d]", i), rule); err != nil {
			return err
		}
	}
	return nil
}

func validateMMERestorationRule(path string, rule MMERestorationPolicyRuleConfig) error {
	if rule.ARPPriorityMin > 15 {
		return fmt.Errorf("%s.arp_priority_min must be in range 0-15, got %d", path, rule.ARPPriorityMin)
	}
	if rule.ARPPriorityMax > 15 {
		return fmt.Errorf("%s.arp_priority_max must be in range 0-15, got %d", path, rule.ARPPriorityMax)
	}
	if rule.ARPPriorityMin != 0 && rule.ARPPriorityMax != 0 && rule.ARPPriorityMin > rule.ARPPriorityMax {
		return fmt.Errorf("%s ARP priority min must be less than or equal to max", path)
	}
	return nil
}

func (c *Config) validateDDNControl() error {
	ddn := c.GTPC.DDNControl
	if ddn.PerMMERateLimitPerSecond <= 0 {
		return fmt.Errorf("gtpc.ddn_control.per_mme_rate_limit_per_second must be positive")
	}
	if ddn.PerMMEBurst <= 0 {
		return fmt.Errorf("gtpc.ddn_control.per_mme_burst must be positive")
	}
	if ddn.PerUESuppressionSeconds < 0 {
		return fmt.Errorf("gtpc.ddn_control.per_ue_suppression_seconds must be non-negative")
	}
	if ddn.LowPriorityThrottleSeconds < 0 {
		return fmt.Errorf("gtpc.ddn_control.low_priority_throttle_seconds must be non-negative")
	}
	if ddn.DelayedQueueMax <= 0 {
		return fmt.Errorf("gtpc.ddn_control.delayed_queue_max must be positive")
	}
	if ddn.DelayedQueuePerMME <= 0 {
		return fmt.Errorf("gtpc.ddn_control.delayed_queue_per_mme must be positive")
	}
	if ddn.DelayedMaxAgeSeconds <= 0 {
		return fmt.Errorf("gtpc.ddn_control.delayed_max_age_seconds must be positive")
	}
	if ddn.StopPagingOnDDNAck && !ddn.StopPagingEnabled {
		return fmt.Errorf("gtpc.ddn_control.stop_paging_on_ddn_ack requires stop_paging_enabled")
	}
	for i, rule := range ddn.HighPriority {
		if err := validateDDNControlPriorityRule(fmt.Sprintf("gtpc.ddn_control.high_priority[%d]", i), rule); err != nil {
			return err
		}
	}
	for i, rule := range ddn.LowPriority {
		if err := validateDDNControlPriorityRule(fmt.Sprintf("gtpc.ddn_control.low_priority[%d]", i), rule); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) validateSessionRecovery() error {
	sr := c.GTPC.SessionRecovery
	switch sr.Backend {
	case "", "sqlite":
	case "redis", "etcd":
		return fmt.Errorf("gtpc.session_recovery.backend %q is reserved for future HA support; only sqlite is supported now", sr.Backend)
	default:
		return fmt.Errorf("gtpc.session_recovery.backend must be sqlite, got %q", sr.Backend)
	}
	if sr.CheckpointIntervalSeconds <= 0 {
		return fmt.Errorf("gtpc.session_recovery.checkpoint_interval_seconds must be positive")
	}
	if sr.ReconcileOnStartup && !sr.RestoreOnStartup {
		return fmt.Errorf("gtpc.session_recovery.reconcile_on_startup requires restore_on_startup")
	}
	return nil
}

func (c *Config) validateBearerInactivity() error {
	bi := c.GTPC.BearerInactivity
	if bi.CheckIntervalSeconds <= 0 {
		return fmt.Errorf("gtpc.bearer_inactivity.check_interval_seconds must be positive")
	}
	if bi.DedicatedBearerIdleSeconds <= 0 {
		return fmt.Errorf("gtpc.bearer_inactivity.dedicated_bearer_idle_seconds must be positive")
	}
	if bi.PendingBearerTimeoutSeconds <= 0 {
		return fmt.Errorf("gtpc.bearer_inactivity.pending_bearer_timeout_seconds must be positive")
	}
	if bi.DefaultBearerIdleSeconds < 0 {
		return fmt.Errorf("gtpc.bearer_inactivity.default_bearer_idle_seconds must be non-negative")
	}
	if bi.DeleteDefaultBearers && bi.DefaultBearerIdleSeconds <= 0 {
		return fmt.Errorf("gtpc.bearer_inactivity.delete_default_bearers requires default_bearer_idle_seconds > 0")
	}
	for i, rule := range bi.Preserve {
		if err := validateBearerInactivityRule(fmt.Sprintf("gtpc.bearer_inactivity.preserve[%d]", i), rule, false); err != nil {
			return err
		}
	}
	for i, rule := range bi.Cleanup {
		if err := validateBearerInactivityRule(fmt.Sprintf("gtpc.bearer_inactivity.cleanup[%d]", i), rule, true); err != nil {
			return err
		}
		if rule.BearerType == "default" && !bi.DeleteDefaultBearers {
			return fmt.Errorf("gtpc.bearer_inactivity.cleanup[%d] targets default bearers but delete_default_bearers is false", i)
		}
	}
	return nil
}

func validateBearerInactivityRule(path string, rule BearerInactivityRuleConfig, cleanup bool) error {
	switch rule.BearerType {
	case "", "default", "dedicated":
	default:
		return fmt.Errorf("%s.bearer_type must be default or dedicated, got %q", path, rule.BearerType)
	}
	if cleanup && rule.IdleSeconds <= 0 {
		return fmt.Errorf("%s.idle_seconds must be positive", path)
	}
	if !cleanup && rule.IdleSeconds < 0 {
		return fmt.Errorf("%s.idle_seconds must be non-negative", path)
	}
	if rule.ARPPriorityMin > 15 {
		return fmt.Errorf("%s.arp_priority_min must be in range 0-15, got %d", path, rule.ARPPriorityMin)
	}
	if rule.ARPPriorityMax > 15 {
		return fmt.Errorf("%s.arp_priority_max must be in range 0-15, got %d", path, rule.ARPPriorityMax)
	}
	if rule.ARPPriorityMin != 0 && rule.ARPPriorityMax != 0 && rule.ARPPriorityMin > rule.ARPPriorityMax {
		return fmt.Errorf("%s ARP priority min must be less than or equal to max", path)
	}
	return nil
}

func validateDDNControlPriorityRule(path string, rule DDNControlPriorityRuleConfig) error {
	if rule.ARPPriorityMin > 15 {
		return fmt.Errorf("%s.arp_priority_min must be in range 0-15, got %d", path, rule.ARPPriorityMin)
	}
	if rule.ARPPriorityMax > 15 {
		return fmt.Errorf("%s.arp_priority_max must be in range 0-15, got %d", path, rule.ARPPriorityMax)
	}
	if rule.ARPPriorityMin != 0 && rule.ARPPriorityMax != 0 && rule.ARPPriorityMin > rule.ARPPriorityMax {
		return fmt.Errorf("%s ARP priority min must be less than or equal to max", path)
	}
	return nil
}

func (c *Config) validateIdleDownlink() error {
	idle := c.GTPC.IdleDownlink
	if idle.ReportThrottleSeconds <= 0 {
		return fmt.Errorf("gtpc.idle_downlink_notification.report_throttle_seconds must be positive")
	}
	for i, rule := range idle.HighPriority {
		if err := validateDDNControlPriorityRule(fmt.Sprintf("gtpc.idle_downlink_notification.high_priority[%d]", i), rule); err != nil {
			return err
		}
	}
	for i, rule := range idle.Suppress {
		if err := validateDDNControlPriorityRule(fmt.Sprintf("gtpc.idle_downlink_notification.suppress[%d]", i), rule); err != nil {
			return err
		}
	}
	if idle.Enabled && idle.TriggerDDN && len(idle.HighPriority) == 0 {
		return fmt.Errorf("gtpc.idle_downlink_notification.high_priority must not be empty when trigger_ddn is enabled")
	}
	return nil
}

func (c *Config) validatePeerHealth() error {
	ph := c.GTPC.PeerHealth
	if ph.EchoIntervalSeconds <= 0 {
		return fmt.Errorf("gtpc.peer_health.echo_interval_seconds must be positive")
	}
	if ph.EchoTimeoutSeconds <= 0 {
		return fmt.Errorf("gtpc.peer_health.echo_timeout_seconds must be positive")
	}
	if ph.EchoTimeoutSeconds >= ph.EchoIntervalSeconds {
		return fmt.Errorf("gtpc.peer_health.echo_timeout_seconds must be less than echo_interval_seconds")
	}
	if ph.SuspectAfterMissed <= 0 {
		return fmt.Errorf("gtpc.peer_health.suspect_after_missed must be positive")
	}
	if ph.DownAfterMissed < ph.SuspectAfterMissed {
		return fmt.Errorf("gtpc.peer_health.down_after_missed must be greater than or equal to suspect_after_missed")
	}
	if ph.DegradedRTTMS <= 0 {
		return fmt.Errorf("gtpc.peer_health.degraded_rtt_ms must be positive")
	}
	return nil
}

func validateDSCP(path string, dscp int) error {
	if dscp < 0 || dscp > 63 {
		return fmt.Errorf("%s must be in range 0-63, got %d", path, dscp)
	}
	return nil
}
