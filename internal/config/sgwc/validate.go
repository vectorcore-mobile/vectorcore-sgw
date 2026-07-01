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
	return nil
}
