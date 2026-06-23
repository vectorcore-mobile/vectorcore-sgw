// Package bpf provides the TC-BPF GTP-U fast-path dataplane for SGW-U.
// The BPF program (ebpf/tc_sgw_gtpu.c) attaches to S1-U and S5/S8-U ingress
// and performs in-place outer IP/TEID rewrite for G-PDU packets.
package bpf

import (
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// TCDataplane manages the TC-BPF GTP-U forwarding program and its BPF maps.
// It attaches to both the S1-U (Access) and S5/S8-U (Core) interfaces.
// Zero value is not valid; use New.
type TCDataplane struct {
	objs        TcSgwGtpuObjects
	accessLink  link.Link // TC hook on S1-U ingress
	coreLink    link.Link // TC hook on S5/S8-U ingress
	s1uIfindex  uint32
	s5uIfindex  uint32
}

// New loads the TC-BPF GTP-U program and attaches it to the S1-U and S5/S8-U
// interface ingress. maxEntries controls the BPF map capacity.
func New(s1uIfname, s5uIfname string, maxEntries int) (*TCDataplane, error) {
	s1uIface, err := net.InterfaceByName(s1uIfname)
	if err != nil {
		return nil, fmt.Errorf("bpf: S1-U interface %q not found: %w", s1uIfname, err)
	}
	s5uIface, err := net.InterfaceByName(s5uIfname)
	if err != nil {
		return nil, fmt.Errorf("bpf: S5/S8-U interface %q not found: %w", s5uIfname, err)
	}

	spec, err := LoadTcSgwGtpu()
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

	d := &TCDataplane{
		s1uIfindex: uint32(s1uIface.Index),
		s5uIfindex: uint32(s5uIface.Index),
	}

	if err := spec.LoadAndAssign(&d.objs, nil); err != nil {
		return nil, fmt.Errorf("bpf: load BPF objects: %w", err)
	}

	d.accessLink, err = link.AttachTCX(link.TCXOptions{
		Interface: s1uIface.Index,
		Program:   d.objs.TcSgwGtpuFunc,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		d.objs.Close()
		return nil, fmt.Errorf("bpf: attach TC to S1-U interface %q: %w", s1uIfname, err)
	}

	d.coreLink, err = link.AttachTCX(link.TCXOptions{
		Interface: s5uIface.Index,
		Program:   d.objs.TcSgwGtpuFunc,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		d.accessLink.Close()
		d.objs.Close()
		return nil, fmt.Errorf("bpf: attach TC to S5/S8-U interface %q: %w", s5uIfname, err)
	}

	return d, nil
}

// S1UIfindex returns the kernel interface index of the S1-U (Access) interface.
func (d *TCDataplane) S1UIfindex() uint32 { return d.s1uIfindex }

// S5UIfindex returns the kernel interface index of the S5/S8-U (Core) interface.
func (d *TCDataplane) S5UIfindex() uint32 { return d.s5uIfindex }

// InstallRule inserts or updates a forwarding rule in sgw_fwd_map.
func (d *TCDataplane) InstallRule(key TcSgwGtpuSgwRuleKey, val TcSgwGtpuSgwRuleValue) error {
	if err := d.objs.SgwFwdMap.Put(key, val); err != nil {
		return fmt.Errorf("bpf: sgw_fwd_map put TEID=%d ifindex=%d: %w", key.Teid, key.Ifindex, err)
	}
	return nil
}

// RemoveRule deletes a forwarding rule from sgw_fwd_map.
// Returns nil if the key was not present.
func (d *TCDataplane) RemoveRule(key TcSgwGtpuSgwRuleKey) error {
	err := d.objs.SgwFwdMap.Delete(key)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("bpf: sgw_fwd_map delete TEID=%d ifindex=%d: %w", key.Teid, key.Ifindex, err)
	}
	return nil
}

// ReadStats reads the per-CPU packet/byte counters for counterID and returns
// aggregated totals. ok is false when no entry exists for that counter ID.
func (d *TCDataplane) ReadStats(counterID uint32) (packets, bytes uint64, ok bool) {
	var perCPU []TcSgwGtpuSgwRuleStats
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
func (d *TCDataplane) RemoveStats(counterID uint32) error {
	err := d.objs.SgwRuleStats.Delete(counterID)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("bpf: sgw_rule_stats delete counter_id=%d: %w", counterID, err)
	}
	return nil
}

// RuleCount returns the number of entries currently in sgw_fwd_map.
func (d *TCDataplane) RuleCount() (int, error) {
	var count int
	var key TcSgwGtpuSgwRuleKey
	var val TcSgwGtpuSgwRuleValue
	iter := d.objs.SgwFwdMap.Iterate()
	for iter.Next(&key, &val) {
		count++
	}
	return count, iter.Err()
}

// Close detaches the TC programs and releases all kernel BPF resources.
func (d *TCDataplane) Close() error {
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
