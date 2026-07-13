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
	if err := c.validateBind("gtpc.s11.bind", c.GTPC.S11.Bind); err != nil {
		return err
	}
	if err := c.validateBind("gtpc.s5c.bind", c.GTPC.S5C.Bind); err != nil {
		return err
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
		return fmt.Errorf("gtpc.s11.timers.t3_response_seconds must be positive")
	}
	if c.S11.N3Requests <= 0 {
		return fmt.Errorf("gtpc.s11.timers.n3_requests must be positive")
	}
	collision := c.GTPC.TransactionCollision
	if collision.Mode != "strict" && collision.Mode != "permissive" {
		return fmt.Errorf("gtpc.transactions.collision_handling.mode must be strict or permissive, got %q", collision.Mode)
	}
	if collision.ActiveProcedureTimeoutSeconds <= 0 {
		return fmt.Errorf("gtpc.transactions.collision_handling.active_procedure_timeout_seconds must be positive")
	}
	if err := c.validatePeerHealth(); err != nil {
		return err
	}
	if c.GTPC.PGWFailure.NotifyMMEOnPGWRestart {
		return fmt.Errorf("features.pgw_failure_handling.actions.notify_mme_on_pgw_restart is not supported yet")
	}
	if err := c.validateMMERestoration(); err != nil {
		return err
	}
	if err := c.validateDDN(); err != nil {
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
	return validateDSCP("qos.outer_marking.pfcp.dscp", c.QoS.OuterMarking.PFCP.DSCP)
}

func (c *Config) validateBind(path, bind string) error {
	if bind == "" {
		return fmt.Errorf("%s is required", path)
	}
	if _, ok := c.Interfaces.Control[bind]; !ok {
		return fmt.Errorf("%s %q does not reference interfaces.control", path, bind)
	}
	return nil
}

func (c *Config) validatePeerHealth() error {
	p := c.GTPC.PeerHealth
	if p.EchoIntervalSeconds <= 0 || p.EchoTimeoutSeconds <= 0 {
		return fmt.Errorf("gtpc.peer_health timers must be positive")
	}
	if p.EchoTimeoutSeconds >= p.EchoIntervalSeconds {
		return fmt.Errorf("gtpc.peer_health.timers.echo_timeout_seconds must be less than echo_interval_seconds")
	}
	if p.SuspectAfterMissed <= 0 {
		return fmt.Errorf("gtpc.peer_health.thresholds.suspect_after_missed must be positive")
	}
	if p.DownAfterMissed < p.SuspectAfterMissed {
		return fmt.Errorf("gtpc.peer_health.thresholds.down_after_missed must be greater than or equal to suspect_after_missed")
	}
	if p.DegradedRTTMS <= 0 {
		return fmt.Errorf("gtpc.peer_health.thresholds.degraded_rtt_ms must be positive")
	}
	return nil
}

func (c *Config) validateMMERestoration() error {
	m := c.GTPC.MMERestoration
	if m.CleanupTimeoutSeconds <= 0 {
		return fmt.Errorf("features.mme_restoration.actions.cleanup_timeout_seconds must be positive")
	}
	if m.DefaultAction != "" && m.DefaultAction != "preserve" && m.DefaultAction != "delete" {
		return fmt.Errorf("features.mme_restoration.actions.default_action must be preserve or delete, got %q", m.DefaultAction)
	}
	for action, rules := range map[string][]MMERestorationPolicyRuleConfig{"preserve": m.Preserve, "delete": m.Delete} {
		for i, rule := range rules {
			if err := validatePolicyRule(fmt.Sprintf("features.mme_restoration.policy.%s[%d]", action, i), rule.APN, rule.QCI, rule.ARP, "", 0); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Config) validateDDN() error {
	d := c.GTPC.DDNControl
	if d.PerMMERateLimitPerSecond <= 0 || d.PerMMEBurst <= 0 || d.PerUESuppressionSeconds < 0 {
		return fmt.Errorf("features.ddn.rate_limit values must be nonnegative")
	}
	if d.LowPriorityThrottleSeconds < 0 {
		return fmt.Errorf("features.ddn.low_priority_throttling.throttle_seconds must be nonnegative")
	}
	if d.DelayedQueueMax <= 0 || d.DelayedQueuePerMME <= 0 || d.DelayedMaxAgeSeconds <= 0 {
		return fmt.Errorf("features.ddn.delayed_queue values must be nonnegative")
	}
	if d.StopPagingOnDDNAck && !d.StopPagingEnabled {
		return fmt.Errorf("features.ddn.stop_paging.on_ddn_ack requires enabled")
	}
	for class, rules := range map[string][]DDNControlPriorityRuleConfig{"high_priority": d.HighPriority, "low_priority": d.LowPriority} {
		for i, rule := range rules {
			if err := validatePolicyRule(fmt.Sprintf("features.ddn.policy.%s[%d]", class, i), rule.APN, rule.QCI, rule.ARP, "", 0); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Config) validateIdleDownlink() error {
	i := c.GTPC.IdleDownlink
	if i.ReportThrottleSeconds <= 0 {
		return fmt.Errorf("features.idle_downlink_notification.throttling.report_throttle_seconds must be nonnegative")
	}
	for class, rules := range map[string][]DDNControlPriorityRuleConfig{"high_priority": i.HighPriority, "suppress": i.Suppress} {
		for n, rule := range rules {
			if err := validatePolicyRule(fmt.Sprintf("features.idle_downlink_notification.policy.%s[%d]", class, n), rule.APN, rule.QCI, rule.ARP, "", 0); err != nil {
				return err
			}
		}
	}
	if i.Enabled && i.TriggerDDN && len(i.HighPriority) == 0 {
		return fmt.Errorf("features.idle_downlink_notification.policy.high_priority must not be empty when trigger_ddn is enabled")
	}
	return nil
}

func (c *Config) validateSessionRecovery() error {
	s := c.GTPC.SessionRecovery
	if s.Backend != "" && s.Backend != "sqlite" {
		return fmt.Errorf("features.session_recovery.storage.backend must be sqlite, got %q", s.Backend)
	}
	if s.CheckpointIntervalSeconds <= 0 {
		return fmt.Errorf("features.session_recovery.checkpoint_interval_seconds must be positive")
	}
	if s.ReconcileOnStartup && !s.RestoreOnStartup {
		return fmt.Errorf("features.session_recovery.startup.reconcile requires restore")
	}
	return nil
}

func (c *Config) validateBearerInactivity() error {
	b := c.GTPC.BearerInactivity
	if b.CheckIntervalSeconds <= 0 || b.DedicatedBearerIdleSeconds <= 0 || b.PendingBearerTimeoutSeconds <= 0 || b.DefaultBearerIdleSeconds < 0 {
		return fmt.Errorf("features.bearer_inactivity timers are invalid")
	}
	if b.DeleteDefaultBearers && b.DefaultBearerIdleSeconds == 0 {
		return fmt.Errorf("features.bearer_inactivity.actions.delete_default_bearers requires default_bearer_idle_seconds > 0")
	}
	for action, rules := range map[string][]BearerInactivityRuleConfig{"preserve": b.Preserve, "cleanup": b.Cleanup} {
		for i, rule := range rules {
			path := fmt.Sprintf("features.bearer_inactivity.policy.%s[%d]", action, i)
			if err := validatePolicyRule(path, rule.APN, rule.QCI, rule.ARP, rule.BearerType, rule.IdleSeconds); err != nil {
				return err
			}
			if action == "cleanup" && rule.IdleSeconds <= 0 {
				return fmt.Errorf("%s.idle_seconds must be positive", path)
			}
			if rule.BearerType == "default" && action == "cleanup" && !b.DeleteDefaultBearers {
				return fmt.Errorf("%s targets default bearers but delete_default_bearers is false", path)
			}
		}
	}
	return nil
}

func validatePolicyRule(path, apn string, qci uint8, arp ARPConfig, bearerType string, idle int) error {
	if apn == "" && qci == 0 && arp.PriorityMin == 0 && arp.PriorityMax == 0 && bearerType == "" && idle == 0 {
		return fmt.Errorf("%s must contain at least one matcher", path)
	}
	if qci > 9 {
		return fmt.Errorf("%s.qci must be in range 1-9, got %d", path, qci)
	}
	if arp.PriorityMin > 15 || arp.PriorityMax > 15 {
		return fmt.Errorf("%s ARP priorities must be in range 0-15", path)
	}
	if arp.PriorityMin != 0 && arp.PriorityMax != 0 && arp.PriorityMin > arp.PriorityMax {
		return fmt.Errorf("%s ARP priority min must be less than or equal to max", path)
	}
	if bearerType != "" && bearerType != "default" && bearerType != "dedicated" {
		return fmt.Errorf("%s.bearer_type must be default or dedicated, got %q", path, bearerType)
	}
	if idle < 0 {
		return fmt.Errorf("%s.idle_seconds must be nonnegative", path)
	}
	return nil
}

func validateDSCP(path string, dscp int) error {
	if dscp < 0 || dscp > 63 {
		return fmt.Errorf("%s must be in range 0-63, got %d", path, dscp)
	}
	return nil
}
