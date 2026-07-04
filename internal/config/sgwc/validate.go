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
