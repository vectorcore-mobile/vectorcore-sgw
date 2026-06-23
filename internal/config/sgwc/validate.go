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
	if c.S11.Listen == "" {
		return fmt.Errorf("s11.listen is required")
	}
	if c.S5C.LocalAddr == "" {
		return fmt.Errorf("s5c.local_addr is required")
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
	if c.S5C.T3ResponseSeconds <= 0 {
		return fmt.Errorf("s5c.t3_response_seconds must be positive")
	}
	if c.S5C.N3Requests <= 0 {
		return fmt.Errorf("s5c.n3_requests must be positive")
	}
	return nil
}
