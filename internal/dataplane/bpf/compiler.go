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
	dp         *XDPDataplane
	s1uLocalIP netip.Addr // SGW-U S1-U local GTP-U IP (used as outer_src_ip for downlink)
	s5uLocalIP netip.Addr // SGW-U S5/S8-U local GTP-U IP (used as outer_src_ip for uplink)
	log        *slog.Logger
	qos        QCIMarkingConfig
}

type QCIMarkingConfig struct {
	Enabled             bool
	OverrideDefaultGTPU bool
	DefaultGTPUDSCP     uint8
	QCIToDSCP           map[uint8]uint8
}

// NewCompiler creates a rule compiler for the given XDPDataplane.
// s1uLocalIP and s5uLocalIP are the SGW-U's own GTP-U addresses on each side.
func NewCompiler(dp *XDPDataplane, s1uLocalIP, s5uLocalIP netip.Addr, log *slog.Logger, qos QCIMarkingConfig) *Compiler {
	return &Compiler{
		dp:         dp,
		s1uLocalIP: s1uLocalIP,
		s5uLocalIP: s5uLocalIP,
		log:        log,
		qos:        qos,
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
	sess.Mu.RLock()
	pdrs := append([]session.PDR(nil), sess.PDRs...)
	fars := append([]session.FAR(nil), sess.FARs...)
	sess.Mu.RUnlock()

	// Build FAR lookup map from FAR ID → FAR (for O(1) resolution per PDR).
	farByID := make(map[uint32]*session.FAR, len(fars))
	for i := range fars {
		farByID[fars[i].ID] = &fars[i]
	}

	var firstErr error
	var added, updated, removed, unchanged int
	for i := range pdrs {
		pdr := &pdrs[i]
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
			val := XdpSgwGtpuSgwRuleValue{Action: actionDrop, CounterId: pdr.LocalTEID}
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

		// Only the ACTION_FORWARD path in ebpf/xdp_sgw_gtpu.c reads/increments
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

func (c *Compiler) installRuleIfChanged(sess *session.Session, pdr *session.PDR, key XdpSgwGtpuSgwRuleKey, val XdpSgwGtpuSgwRuleValue) (added, updated, unchanged int, err error) {
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
			"action", val.Action, "egress", val.EgressIfindex,
			"ebi", val.Ebi, "qci", val.Qci, "outer_dscp", val.OuterDscp, "qos_valid", val.QosValid)
		return 0, 1, 0, nil
	}
	c.log.Debug("BPF compiler: rule added",
		"cp_seid", sess.CPSEID, "pdr_id", pdr.ID, "teid", pdr.LocalTEID,
		"action", val.Action, "egress", val.EgressIfindex,
		"ebi", val.Ebi, "qci", val.Qci, "outer_dscp", val.OuterDscp, "qos_valid", val.QosValid)
	return 1, 0, 0, nil
}

// buildKey constructs the BPF map key for a PDR.
// The ingress ifindex is determined by the PDR's Source Interface:
//   - Access (0) per TS 29.244 Table 8.2.2-1 → packet enters on S1-U
//   - Core (1)   per TS 29.244 Table 8.2.2-1 → packet enters on S5/S8-U
func (c *Compiler) buildKey(pdr *session.PDR) (XdpSgwGtpuSgwRuleKey, error) {
	var ifindex uint32
	switch pdr.SourceInterface {
	case pfcpie.SourceInterfaceAccess: // 0 = Access per TS 29.244 Table 8.2.2-1
		ifindex = c.dp.S1UIfindex()
	case pfcpie.SourceInterfaceCore: // 1 = Core per TS 29.244 Table 8.2.2-1
		ifindex = c.dp.S5UIfindex()
	default:
		return XdpSgwGtpuSgwRuleKey{}, fmt.Errorf("unsupported source interface %d", pdr.SourceInterface)
	}
	return XdpSgwGtpuSgwRuleKey{
		Teid:    pdr.LocalTEID,
		Ifindex: ifindex,
	}, nil
}

// buildValue constructs the BPF map value for a PDR/FAR pair.
// Apply Action mapping per TS 29.244 Figure 8.2.26-1:
//   - FORW (bit 2 = 0x02) → ACTION_FORWARD with outer IP/TEID rewrite
//   - DROP (bit 1 = 0x01) → ACTION_DROP (XDP_DROP)
//   - other              → ACTION_PUNT (XDP_PASS to userspace)
func (c *Compiler) buildValue(pdr *session.PDR, far *session.FAR) (XdpSgwGtpuSgwRuleValue, error) {
	val := XdpSgwGtpuSgwRuleValue{
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
		c.applyQoSMetadata(pdr, &val)

	case far.ApplyAction&pfcpie.ApplyActionDROP != 0:
		// DROP per TS 29.244 Figure 8.2.26-1: "Bit 1 DROP=0x01"
		val.Action = actionDrop
		if pdr.SourceInterface == pfcpie.SourceInterfaceCore &&
			far.DropReason == session.DropReasonReleaseAccessBearers {
			// Release Access Bearers idle downlink packets must reach userspace
			// so SGW-U can count/report them to SGW-C in later phases. Userspace
			// still drops the packet until MME paging/Modify Bearer restores the
			// access-side FAR.
			val.Action = actionPunt
		}

	default:
		// BUFF or other — punt to userspace for handling.
		val.Action = actionPunt
	}

	return val, nil
}

func (c *Compiler) applyQoSMetadata(pdr *session.PDR, val *XdpSgwGtpuSgwRuleValue) {
	if !c.qos.Enabled || !c.qos.OverrideDefaultGTPU || !pdr.QoSValid || pdr.QCI == 0 {
		return
	}
	val.Ebi = pdr.EBI
	val.Qci = pdr.QCI
	val.QosValid = 1
	if dscp, ok := c.qos.QCIToDSCP[pdr.QCI]; ok {
		val.OuterDscp = dscp
	} else {
		val.OuterDscp = c.qos.DefaultGTPUDSCP
		c.log.Warn("SGW-U: QCI unmapped, using default GTP-U DSCP",
			"teid", fmt.Sprintf("0x%08X", pdr.LocalTEID),
			"qci", pdr.QCI,
			"default_gtpu_dscp", c.qos.DefaultGTPUDSCP)
	}
	c.log.Info("SGW-U: GTP-U QoS marking rule installed",
		"teid", fmt.Sprintf("0x%08X", pdr.LocalTEID),
		"direction", sourceInterfaceDirection(pdr.SourceInterface),
		"ebi", pdr.EBI,
		"qci", pdr.QCI,
		"outer_dscp", val.OuterDscp)
}

func sourceInterfaceDirection(sourceInterface uint8) string {
	switch sourceInterface {
	case pfcpie.SourceInterfaceAccess:
		return "uplink"
	case pfcpie.SourceInterfaceCore:
		return "downlink"
	default:
		return "unknown"
	}
}

// BPF action code constants (project-internal, from project §6.3).
// Must match ACTION_* defines in ebpf/xdp_sgw_gtpu.c.
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
