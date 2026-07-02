// Package bpf provides the XDP GTP-U fast-path dataplane for SGW-U.
// The BPF program (ebpf/xdp_sgw_gtpu.c) attaches to S1-U and S5/S8-U ingress
// and performs in-place outer IP/TEID rewrite for G-PDU packets.
package bpf

import (
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// XDPDataplane manages the XDP GTP-U forwarding program and its BPF maps.
// It attaches to the S1-U and S5/S8-U ingress interfaces. If both logical
// interfaces resolve to the same Linux ifindex, it attaches once.
// Zero value is not valid; use New.
type XDPDataplane struct {
	objs        XdpSgwGtpuObjects
	accessLink  link.Link // XDP hook on S1-U ingress
	coreLink    link.Link // XDP hook on S5/S8-U ingress
	s1uIfindex  uint32
	s5uIfindex  uint32
	sharedIface bool
	testRules   map[XdpSgwGtpuSgwRuleKey]XdpSgwGtpuSgwRuleValue
}

// QoSOuterMarkingConfig is the SGW-U XDP default outer DSCP marking policy.
type QoSOuterMarkingConfig struct {
	Enabled        bool
	GTPUEnabled    bool
	GTPUDSCP       uint8
	QCIEnabled     bool
	QCIDefaultDSCP uint8
}

type qosOuterMarkingMapValue struct {
	Enabled        uint8
	GTPUEnabled    uint8
	GTPUDSCP       uint8
	QCIEnabled     uint8
	QCIDefaultDSCP uint8
	Reserved       [3]uint8
}

// New loads the XDP GTP-U program in xdp-generic mode. maxEntries controls
// the BPF map capacity.
func New(s1uIfname, s5uIfname string, maxEntries int) (*XDPDataplane, error) {
	return NewWithMode(s1uIfname, s5uIfname, maxEntries, "xdp-generic")
}

// NewWithMode loads the XDP GTP-U program and attaches it to the S1-U and
// S5/S8-U interface ingress hooks. driverMode must be xdp-generic,
// xdp-native, or xdp-offload.
func NewWithMode(s1uIfname, s5uIfname string, maxEntries int, driverMode string) (*XDPDataplane, error) {
	s1uIface, err := net.InterfaceByName(s1uIfname)
	if err != nil {
		return nil, fmt.Errorf("bpf: S1-U interface %q not found: %w", s1uIfname, err)
	}
	s5uIface, err := net.InterfaceByName(s5uIfname)
	if err != nil {
		return nil, fmt.Errorf("bpf: S5/S8-U interface %q not found: %w", s5uIfname, err)
	}

	spec, err := LoadXdpSgwGtpu()
	if err != nil {
		return nil, fmt.Errorf("bpf: load BPF spec: %w", err)
	}

	if maxEntries > 0 {
		if m, ok := spec.Maps["sgw_fwd_map"]; ok {
			m.MaxEntries = uint32(maxEntries)
		}
		if m, ok := spec.Maps["sgw_rule_stats"]; ok {
			m.MaxEntries = uint32(maxEntries)
		}
	}

	flags, err := xdpAttachFlags(driverMode)
	if err != nil {
		return nil, err
	}

	d := &XDPDataplane{
		s1uIfindex:  uint32(s1uIface.Index),
		s5uIfindex:  uint32(s5uIface.Index),
		sharedIface: s1uIface.Index == s5uIface.Index,
	}

	if err := spec.LoadAndAssign(&d.objs, nil); err != nil {
		return nil, fmt.Errorf("bpf: load BPF objects: %w", err)
	}

	d.accessLink, err = link.AttachXDP(link.XDPOptions{
		Interface: s1uIface.Index,
		Program:   d.objs.XdpSgwGtpuFunc,
		Flags:     flags,
	})
	if err != nil {
		d.objs.Close()
		return nil, fmt.Errorf("bpf: attach XDP to S1-U interface %q mode %s: %w", s1uIfname, driverMode, err)
	}

	if d.sharedIface {
		return d, nil
	}

	d.coreLink, err = link.AttachXDP(link.XDPOptions{
		Interface: s5uIface.Index,
		Program:   d.objs.XdpSgwGtpuFunc,
		Flags:     flags,
	})
	if err != nil {
		d.accessLink.Close()
		d.objs.Close()
		return nil, fmt.Errorf("bpf: attach XDP to S5/S8-U interface %q mode %s: %w", s5uIfname, driverMode, err)
	}

	return d, nil
}

func xdpAttachFlags(driverMode string) (link.XDPAttachFlags, error) {
	switch driverMode {
	case "", "xdp-generic", "generic":
		return link.XDPGenericMode, nil
	case "xdp-native", "native":
		return link.XDPDriverMode, nil
	case "xdp-offload":
		return link.XDPOffloadMode, nil
	default:
		return 0, fmt.Errorf("bpf: unsupported XDP driver mode %q", driverMode)
	}
}

// S1UIfindex returns the kernel interface index of the S1-U (Access) interface.
func (d *XDPDataplane) S1UIfindex() uint32 { return d.s1uIfindex }

// S5UIfindex returns the kernel interface index of the S5/S8-U (Core) interface.
func (d *XDPDataplane) S5UIfindex() uint32 { return d.s5uIfindex }

// SharedInterface reports whether S1-U and S5/S8-U share one Linux ifindex.
func (d *XDPDataplane) SharedInterface() bool { return d.sharedIface }

// ConfigureQoSOuterMarking writes the singleton XDP QoS outer marking map.
func (d *XDPDataplane) ConfigureQoSOuterMarking(cfg QoSOuterMarkingConfig) error {
	if cfg.GTPUDSCP > 63 {
		return fmt.Errorf("bpf: GTP-U DSCP must be in range 0-63, got %d", cfg.GTPUDSCP)
	}
	if cfg.QCIDefaultDSCP > 63 {
		return fmt.Errorf("bpf: QCI default DSCP must be in range 0-63, got %d", cfg.QCIDefaultDSCP)
	}
	if d.objs.QosOuterConfigMap == nil {
		return fmt.Errorf("bpf: qos_outer_config_map is not loaded")
	}
	val := qosOuterMarkingMapValue{
		Enabled:        boolToU8(cfg.Enabled),
		GTPUEnabled:    boolToU8(cfg.GTPUEnabled),
		GTPUDSCP:       cfg.GTPUDSCP,
		QCIEnabled:     boolToU8(cfg.QCIEnabled),
		QCIDefaultDSCP: cfg.QCIDefaultDSCP,
	}
	var key uint32
	if err := d.objs.QosOuterConfigMap.Update(key, val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("bpf: qos_outer_config_map update: %w", err)
	}
	return nil
}

func boolToU8(v bool) uint8 {
	if v {
		return 1
	}
	return 0
}

// InstallRule inserts or updates a forwarding rule in sgw_fwd_map.
func (d *XDPDataplane) InstallRule(key XdpSgwGtpuSgwRuleKey, val XdpSgwGtpuSgwRuleValue) error {
	if d.objs.SgwFwdMap == nil && d.testRules != nil {
		d.testRules[key] = val
		return nil
	}
	if err := d.objs.SgwFwdMap.Put(key, val); err != nil {
		return fmt.Errorf("bpf: sgw_fwd_map put TEID=%d ifindex=%d: %w", key.Teid, key.Ifindex, err)
	}
	return nil
}

// LookupRule returns one forwarding rule from sgw_fwd_map.
func (d *XDPDataplane) LookupRule(key XdpSgwGtpuSgwRuleKey) (XdpSgwGtpuSgwRuleValue, bool, error) {
	if d.objs.SgwFwdMap == nil && d.testRules != nil {
		val, ok := d.testRules[key]
		return val, ok, nil
	}
	var val XdpSgwGtpuSgwRuleValue
	if err := d.objs.SgwFwdMap.Lookup(key, &val); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return XdpSgwGtpuSgwRuleValue{}, false, nil
		}
		return XdpSgwGtpuSgwRuleValue{}, false, fmt.Errorf("bpf: sgw_fwd_map lookup TEID=%d ifindex=%d: %w", key.Teid, key.Ifindex, err)
	}
	return val, true, nil
}

// InitStats creates a zeroed per-CPU entry in sgw_rule_stats for counterID.
//
// sgw_rule_stats is BPF_MAP_TYPE_PERCPU_HASH; bpf_map_lookup_elem in
// ebpf/xdp_sgw_gtpu.c returns NULL for a key that was never inserted — a
// PERCPU_HASH lookup does not auto-create entries the way an array map
// would. Without calling this before traffic arrives, the kernel program's
// "if (stats) stats->packets++" guard is always false and counters never
// increment regardless of traffic volume. Callers must call InitStats for
// every counter_id used in a rule installed via InstallRule.
func (d *XDPDataplane) InitStats(counterID uint32) error {
	if d.objs.SgwRuleStats == nil && d.testRules != nil {
		return nil
	}
	n, err := ebpf.PossibleCPU()
	if err != nil {
		return fmt.Errorf("bpf: possible CPU count: %w", err)
	}
	zero := make([]XdpSgwGtpuSgwRuleStats, n)
	if err := d.objs.SgwRuleStats.Update(counterID, zero, ebpf.UpdateNoExist); err != nil && !errors.Is(err, ebpf.ErrKeyExist) {
		return fmt.Errorf("bpf: sgw_rule_stats init counter_id=%d: %w", counterID, err)
	}
	return nil
}

// RemoveRule deletes a forwarding rule from sgw_fwd_map.
// Returns nil if the key was not present.
func (d *XDPDataplane) RemoveRule(key XdpSgwGtpuSgwRuleKey) error {
	if d.objs.SgwFwdMap == nil && d.testRules != nil {
		delete(d.testRules, key)
		return nil
	}
	err := d.objs.SgwFwdMap.Delete(key)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("bpf: sgw_fwd_map delete TEID=%d ifindex=%d: %w", key.Teid, key.Ifindex, err)
	}
	return nil
}

// ReadStats reads the per-CPU packet/byte counters for counterID and returns
// aggregated totals. ok is false when no entry exists for that counter ID.
func (d *XDPDataplane) ReadStats(counterID uint32) (packets, bytes uint64, ok bool) {
	var perCPU []XdpSgwGtpuSgwRuleStats
	if err := d.objs.SgwRuleStats.Lookup(counterID, &perCPU); err != nil {
		return 0, 0, false
	}
	for _, s := range perCPU {
		packets += s.Packets
		bytes += s.Bytes
	}
	return packets, bytes, true
}

// RemoveStats deletes the stats entry for counterID. Returns nil if absent.
func (d *XDPDataplane) RemoveStats(counterID uint32) error {
	if d.objs.SgwRuleStats == nil && d.testRules != nil {
		return nil
	}
	err := d.objs.SgwRuleStats.Delete(counterID)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("bpf: sgw_rule_stats delete counter_id=%d: %w", counterID, err)
	}
	return nil
}

// RuleCount returns the number of entries currently in sgw_fwd_map.
func (d *XDPDataplane) RuleCount() (int, error) {
	var count int
	var key XdpSgwGtpuSgwRuleKey
	var val XdpSgwGtpuSgwRuleValue
	iter := d.objs.SgwFwdMap.Iterate()
	for iter.Next(&key, &val) {
		count++
	}
	return count, iter.Err()
}

// RuleEntry is one forwarding rule from sgw_fwd_map joined with its
// sgw_rule_stats counters, for debug/inspection APIs.
type RuleEntry struct {
	Key           XdpSgwGtpuSgwRuleKey
	Value         XdpSgwGtpuSgwRuleValue
	Packets       uint64
	Bytes         uint64
	StatsRecorded bool // false if no sgw_rule_stats entry exists for this rule's CounterId
}

// Rules returns a snapshot of every forwarding rule currently programmed in
// sgw_fwd_map, with packet/byte counters joined in from sgw_rule_stats where
// present (see InitStats — a rule with Action != ACTION_FORWARD, or one
// whose stats entry failed to initialize, will have StatsRecorded=false).
func (d *XDPDataplane) Rules() ([]RuleEntry, error) {
	var key XdpSgwGtpuSgwRuleKey
	var val XdpSgwGtpuSgwRuleValue
	var entries []RuleEntry
	iter := d.objs.SgwFwdMap.Iterate()
	for iter.Next(&key, &val) {
		entry := RuleEntry{Key: key, Value: val}
		entry.Packets, entry.Bytes, entry.StatsRecorded = d.ReadStats(val.CounterId)
		entries = append(entries, entry)
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("bpf: sgw_fwd_map iterate: %w", err)
	}
	return entries, nil
}

// Close detaches the XDP programs and releases all kernel BPF resources.
func (d *XDPDataplane) Close() error {
	var first error
	if d.coreLink != nil {
		if err := d.coreLink.Close(); err != nil && first == nil {
			first = err
		}
	}
	if d.accessLink != nil {
		if err := d.accessLink.Close(); err != nil && first == nil {
			first = err
		}
	}
	if err := d.objs.Close(); err != nil && first == nil {
		first = err
	}
	return first
}
