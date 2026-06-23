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
	if c.GTPU.Access.Ifname == "" {
		return fmt.Errorf("gtpu.access.ifname is required")
	}
	if c.GTPU.Access.LocalAddr == "" {
		return fmt.Errorf("gtpu.access.local_addr is required")
	}
	if c.GTPU.Core.Ifname == "" {
		return fmt.Errorf("gtpu.core.ifname is required")
	}
	if c.GTPU.Core.LocalAddr == "" {
		return fmt.Errorf("gtpu.core.local_addr is required")
	}
	switch c.Dataplane.Mode {
	case "tc-bpf", "userspace":
	default:
		return fmt.Errorf("dataplane.mode must be \"tc-bpf\" or \"userspace\", got %q", c.Dataplane.Mode)
	}
	switch c.Dataplane.UnknownTEID {
	case "punt", "drop":
	default:
		return fmt.Errorf("dataplane.unknown_teid must be \"punt\" or \"drop\", got %q", c.Dataplane.UnknownTEID)
	}
	if c.Dataplane.BPFMapMaxEntries <= 0 {
		return fmt.Errorf("dataplane.bpf_map_max_entries must be positive")
	}
	return nil
}
