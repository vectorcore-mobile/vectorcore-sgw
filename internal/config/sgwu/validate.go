package sgwuconfig

import "fmt"

func (c *Config) Validate() error {
	if c.SGWU.NodeID == "" {
		return fmt.Errorf("sgwu.node_id is required")
	}
	if c.PFCP.Listen == "" {
		return fmt.Errorf("pfcp.listen is required")
	}
	if len(c.PFCP.AllowedSGWC) == 0 {
		return fmt.Errorf("pfcp.allowed_sgwc must list at least one SGW-C address")
	}
	for name, iface := range c.Interfaces.User {
		if iface.Ifname == "" {
			return fmt.Errorf("interfaces.user.%s.ifname is required", name)
		}
		if iface.Listen == "" {
			return fmt.Errorf("interfaces.user.%s.listen is required", name)
		}
		if _, err := listenHostAddr(iface.Listen); err != nil {
			return fmt.Errorf("interfaces.user.%s.listen is invalid: %w", name, err)
		}
	}
	if c.GTPU.S1U.Bind == "" {
		return fmt.Errorf("gtpu.s1u.bind is required")
	}
	if _, ok := c.Interfaces.User[c.GTPU.S1U.Bind]; !ok {
		return fmt.Errorf("gtpu.s1u.bind %q does not reference interfaces.user", c.GTPU.S1U.Bind)
	}
	s1uAddr, err := c.S1ULocalAddr()
	if err != nil {
		return fmt.Errorf("gtpu.s1u.bind %q has invalid listen address: %w", c.GTPU.S1U.Bind, err)
	}
	if s1uAddr.IsUnspecified() {
		return fmt.Errorf("gtpu.s1u.bind %q must not use an unspecified listen IP", c.GTPU.S1U.Bind)
	}
	if !s1uAddr.Is4() {
		return fmt.Errorf("gtpu.s1u.bind %q must use an IPv4 listen IP", c.GTPU.S1U.Bind)
	}
	if c.GTPU.S5U.Bind == "" {
		return fmt.Errorf("gtpu.s5u.bind is required")
	}
	if _, ok := c.Interfaces.User[c.GTPU.S5U.Bind]; !ok {
		return fmt.Errorf("gtpu.s5u.bind %q does not reference interfaces.user", c.GTPU.S5U.Bind)
	}
	s5uAddr, err := c.S5ULocalAddr()
	if err != nil {
		return fmt.Errorf("gtpu.s5u.bind %q has invalid listen address: %w", c.GTPU.S5U.Bind, err)
	}
	if s5uAddr.IsUnspecified() {
		return fmt.Errorf("gtpu.s5u.bind %q must not use an unspecified listen IP", c.GTPU.S5U.Bind)
	}
	if !s5uAddr.Is4() {
		return fmt.Errorf("gtpu.s5u.bind %q must use an IPv4 listen IP", c.GTPU.S5U.Bind)
	}
	switch c.Dataplane.DriverMode {
	case "", "generic", "native", "xdp-generic", "xdp-native", "xdp-offload":
	default:
		return fmt.Errorf("dataplane.driver_mode must be \"xdp-generic\", \"xdp-native\", or \"xdp-offload\", got %q", c.Dataplane.DriverMode)
	}
	switch c.Dataplane.UnknownTEID {
	case "punt", "drop":
	default:
		return fmt.Errorf("dataplane.unknown_teid must be \"punt\" or \"drop\", got %q", c.Dataplane.UnknownTEID)
	}
	if c.Dataplane.MapMaxEntries <= 0 {
		return fmt.Errorf("dataplane.map_max_entries must be positive")
	}
	if err := validateDSCP("qos.outer_marking.gtpu.dscp", c.QoS.OuterMarking.GTPU.DSCP); err != nil {
		return err
	}
	if err := validateDSCP("qos.outer_marking.pfcp.dscp", c.QoS.OuterMarking.PFCP.DSCP); err != nil {
		return err
	}
	return nil
}

func validateDSCP(path string, dscp int) error {
	if dscp < 0 || dscp > 63 {
		return fmt.Errorf("%s must be in range 0-63, got %d", path, dscp)
	}
	return nil
}
