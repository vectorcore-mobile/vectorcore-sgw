package bpf

import (
	"fmt"
	"log/slog"
	"net/netip"

	pfcpie "vectorcore-sgw/internal/pfcp/ie"
	"vectorcore-sgw/internal/sgwu/session"
)

// Compiler translates PFCP session PDR/FAR state into BPF forwarding rules
// in sgw_fwd_map. Called by the PFCP server after session establishment,
// modification, and deletion.
//
// PFCP Apply Action to BPF action mapping:
//   - FORW (0x02, Figure 8.2.26-1 of TS 29.244): ACTION_FORWARD (1)
//   - DROP (0x01, Figure 8.2.26-1 of TS 29.244): ACTION_DROP (2)
//   - other or unset: ACTION_PUNT (3)
//
// PFCP Source Interface to BPF direction:
//   - Access (0, Table 8.2.2-1 of TS 29.244): uplink — key uses S1-U ifindex
//   - Core (1, Table 8.2.2-1 of TS 29.244):   downlink — key uses S5/S8-U ifindex
type Compiler struct {
	dp         *TCDataplane
	s1uLocalIP netip.Addr // SGW-U S1-U local GTP-U IP (used as outer_src_ip for downlink)
	s5uLocalIP netip.Addr // SGW-U S5/S8-U local GTP-U IP (used as outer_src_ip for uplink)
	log        *slog.Logger
}

// NewCompiler creates a rule compiler for the given TCDataplane.
// s1uLocalIP and s5uLocalIP are the SGW-U's own GTP-U addresses on each side.
func NewCompiler(dp *TCDataplane, s1uLocalIP, s5uLocalIP netip.Addr, log *slog.Logger) *Compiler {
	return &Compiler{
		dp:         dp,
		s1uLocalIP: s1uLocalIP,
		s5uLocalIP: s5uLocalIP,
		log:        log,
	}
}

// InstallSession installs BPF forwarding rules for all PDRs in the session.
// Called after PFCP Session Establishment.
func (c *Compiler) InstallSession(sess *session.Session) error {
	return c.syncRules(sess, false)
}

// UpdateSession re-installs BPF forwarding rules after a PFCP Session Modification.
// Existing rules for the session are overwritten with the updated FAR values.
func (c *Compiler) UpdateSession(sess *session.Session) error {
	return c.syncRules(sess, false)
}

// RemoveSession deletes all BPF forwarding rules for the session.
// Called after PFCP Session Deletion.
func (c *Compiler) RemoveSession(sess *session.Session) error {
	return c.syncRules(sess, true)
}

// syncRules installs or removes all BPF rules for a session.
// When remove=true, all rules are deleted. When false, they are installed/updated.
func (c *Compiler) syncRules(sess *session.Session, remove bool) error {
	// Build FAR lookup map from FAR ID → FAR (for O(1) resolution per PDR).
	farByID := make(map[uint32]*session.FAR, len(sess.FARs))
	for i := range sess.FARs {
		farByID[sess.FARs[i].ID] = &sess.FARs[i]
	}

	var firstErr error
	var added, updated, removed, unchanged int
	for i := range sess.PDRs {
		pdr := &sess.PDRs[i]
		if pdr.LocalTEID == 0 {
			// No local TEID allocated (e.g., predefined rules); skip.
			continue
		}

		key, err := c.buildKey(pdr)
		if err != nil {
			c.log.Warn("BPF compiler: skipping PDR — key build failed",
				"cp_seid", sess.CPSEID, "pdr_id", pdr.ID, "error", err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		if remove {
			_, exists, lookupErr := c.dp.LookupRule(key)
			if lookupErr != nil {
				c.log.Warn("BPF compiler: rule lookup failed before remove",
					"cp_seid", sess.CPSEID, "pdr_id", pdr.ID, "teid", pdr.LocalTEID, "error", lookupErr)
				if firstErr == nil {
					firstErr = lookupErr
				}
				continue
			}
			if err := c.dp.RemoveRule(key); err != nil {
				c.log.Warn("BPF compiler: rule remove failed",
					"cp_seid", sess.CPSEID, "pdr_id", pdr.ID, "teid", pdr.LocalTEID, "error", err)
				if firstErr == nil {
					firstErr = err
				}
			} else if exists {
				removed++
				c.log.Debug("BPF compiler: rule removed",
					"cp_seid", sess.CPSEID, "pdr_id", pdr.ID, "teid", pdr.LocalTEID)
			} else {
				unchanged++
			}
			if err := c.dp.RemoveStats(pdr.LocalTEID); err != nil {
				c.log.Warn("BPF compiler: stats remove failed",
					"cp_seid", sess.CPSEID, "teid", pdr.LocalTEID, "error", err)
			}
			continue
		}

		far, ok := farByID[pdr.FARID]
		if !ok {
			c.log.Warn("BPF compiler: PDR references unknown FAR — installing DROP rule",
				"cp_seid", sess.CPSEID, "pdr_id", pdr.ID, "far_id", pdr.FARID)
			val := TcSgwGtpuSgwRuleValue{Action: actionDrop, CounterId: pdr.LocalTEID}
			ruleAdded, ruleUpdated, ruleUnchanged, err := c.installRuleIfChanged(sess, pdr, key, val)
			added += ruleAdded
			updated += ruleUpdated
			unchanged += ruleUnchanged
			if err != nil && firstErr == nil {
				firstErr = err
			}
			continue
		}

		val, err := c.buildValue(pdr, far)
		if err != nil {
			c.log.Warn("BPF compiler: skipping PDR — value build failed",
				"cp_seid", sess.CPSEID, "pdr_id", pdr.ID, "error", err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		// Only the ACTION_FORWARD path in ebpf/tc_sgw_gtpu.c reads/increments
		// sgw_rule_stats; the map entry must exist before traffic arrives
		// (PERCPU_HASH lookup does not auto-create — see InitStats). A stats
		// map failure (e.g. a full sgw_rule_stats map) must not block the
		// forwarding rule itself from being installed: traffic forwarding is
		// the core function, counters are observability-only, and the BPF
		// program tolerates a missing stats entry by simply skipping the
		// increment (no impact on forwarding correctness).
		if val.Action == actionForward {
			if err := c.dp.InitStats(val.CounterId); err != nil {
				c.log.Warn("BPF compiler: stats init failed — rule will still be installed without counters",
					"cp_seid", sess.CPSEID, "pdr_id", pdr.ID, "counter_id", val.CounterId, "error", err)
			}
		}

		ruleAdded, ruleUpdated, ruleUnchanged, err := c.installRuleIfChanged(sess, pdr, key, val)
		added += ruleAdded
		updated += ruleUpdated
		unchanged += ruleUnchanged
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
	}
	c.log.Debug("BPF compiler: sync summary",
		"cp_seid", sess.CPSEID,
		"remove", remove,
		"rules_added", added,
		"rules_updated", updated,
		"rules_removed", removed,
		"rules_unchanged", unchanged,
	)
	return firstErr
}

func (c *Compiler) installRuleIfChanged(sess *session.Session, pdr *session.PDR, key TcSgwGtpuSgwRuleKey, val TcSgwGtpuSgwRuleValue) (added, updated, unchanged int, err error) {
	current, exists, err := c.dp.LookupRule(key)
	if err != nil {
		c.log.Warn("BPF compiler: rule lookup failed",
			"cp_seid", sess.CPSEID, "pdr_id", pdr.ID, "teid", pdr.LocalTEID, "error", err)
		return 0, 0, 0, err
	}
	if exists && current == val {
		return 0, 0, 1, nil
	}

	if err := c.dp.InstallRule(key, val); err != nil {
		c.log.Warn("BPF compiler: rule install failed",
			"cp_seid", sess.CPSEID, "pdr_id", pdr.ID, "teid", pdr.LocalTEID, "error", err)
		return 0, 0, 0, err
	}
	if exists {
		c.log.Debug("BPF compiler: rule updated",
			"cp_seid", sess.CPSEID, "pdr_id", pdr.ID, "teid", pdr.LocalTEID,
			"action", val.Action, "egress", val.EgressIfindex)
		return 0, 1, 0, nil
	}
	c.log.Debug("BPF compiler: rule added",
		"cp_seid", sess.CPSEID, "pdr_id", pdr.ID, "teid", pdr.LocalTEID,
		"action", val.Action, "egress", val.EgressIfindex)
	return 1, 0, 0, nil
}

// buildKey constructs the BPF map key for a PDR.
// The ingress ifindex is determined by the PDR's Source Interface:
//   - Access (0) per TS 29.244 Table 8.2.2-1 → packet enters on S1-U
//   - Core (1)   per TS 29.244 Table 8.2.2-1 → packet enters on S5/S8-U
func (c *Compiler) buildKey(pdr *session.PDR) (TcSgwGtpuSgwRuleKey, error) {
	var ifindex uint32
	switch pdr.SourceInterface {
	case pfcpie.SourceInterfaceAccess: // 0 = Access per TS 29.244 Table 8.2.2-1
		ifindex = c.dp.S1UIfindex()
	case pfcpie.SourceInterfaceCore: // 1 = Core per TS 29.244 Table 8.2.2-1
		ifindex = c.dp.S5UIfindex()
	default:
		return TcSgwGtpuSgwRuleKey{}, fmt.Errorf("unsupported source interface %d", pdr.SourceInterface)
	}
	return TcSgwGtpuSgwRuleKey{
		Teid:    pdr.LocalTEID,
		Ifindex: ifindex,
	}, nil
}

// buildValue constructs the BPF map value for a PDR/FAR pair.
// Apply Action mapping per TS 29.244 Figure 8.2.26-1:
//   - FORW (bit 2 = 0x02) → ACTION_FORWARD with outer IP/TEID rewrite
//   - DROP (bit 1 = 0x01) → ACTION_DROP (TC_ACT_SHOT)
//   - other              → ACTION_PUNT (TC_ACT_OK to userspace)
func (c *Compiler) buildValue(pdr *session.PDR, far *session.FAR) (TcSgwGtpuSgwRuleValue, error) {
	val := TcSgwGtpuSgwRuleValue{
		CounterId: pdr.LocalTEID, // use local TEID as counter index
	}

	switch {
	case far.ApplyAction&pfcpie.ApplyActionFORW != 0:
		// FORW per TS 29.244 Figure 8.2.26-1: "Bit 2 FORW=0x02"
		val.Action = actionForward

		// Destination outer IP (peer): FAR.OuterIP (eNB IP for downlink, PGW IP for uplink).
		if !far.OuterIP.IsValid() {
			// FAR does not yet have a peer address (initial DROP→FORW transition
			// before eNB TEID arrives). Install a PUNT rule until the modify arrives.
			val.Action = actionPunt
			break
		}

		dstIP := far.OuterIP.As4()
		copy(val.OuterDstIp[:], dstIP[:])
		val.NewTeid = far.OuterTEID

		// Source outer IP (SGW-U's own IP on the egress side):
		//   Uplink (PDR.SourceInterface=Access): egress is S5/S8-U → use s5uLocalIP, redirect to S5U ifindex.
		//   Downlink (PDR.SourceInterface=Core): egress is S1-U → use s1uLocalIP, redirect to S1U ifindex.
		switch pdr.SourceInterface {
		case pfcpie.SourceInterfaceAccess:
			srcIP := c.s5uLocalIP.As4()
			copy(val.OuterSrcIp[:], srcIP[:])
			val.EgressIfindex = c.dp.S5UIfindex()
		case pfcpie.SourceInterfaceCore:
			srcIP := c.s1uLocalIP.As4()
			copy(val.OuterSrcIp[:], srcIP[:])
			val.EgressIfindex = c.dp.S1UIfindex()
		}

	case far.ApplyAction&pfcpie.ApplyActionDROP != 0:
		// DROP per TS 29.244 Figure 8.2.26-1: "Bit 1 DROP=0x01"
		val.Action = actionDrop

	default:
		// BUFF or other — punt to userspace for handling.
		val.Action = actionPunt
	}

	return val, nil
}

// BPF action code constants (project-internal, from project §6.3).
// Must match ACTION_* defines in ebpf/tc_sgw_gtpu.c.
const (
	actionForward uint8 = 1
	actionDrop    uint8 = 2
	actionPunt    uint8 = 3
)

// ActionName returns a human-readable name for a BPF rule action code, for
// debug/inspection APIs. Unrecognized values are not expected — the kernel
// program only ever stores values written by this package — but are
// rendered rather than panicking.
func ActionName(action uint8) string {
	switch action {
	case actionForward:
		return "FORWARD"
	case actionDrop:
		return "DROP"
	case actionPunt:
		return "PUNT"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", action)
	}
}
