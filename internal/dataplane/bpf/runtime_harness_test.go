//go:build linux

package bpf

// Runtime test harness: creates an isolated network namespace with two veth
// pairs simulating the S1-U and S5/S8-U links, attaches the real compiled
// xdp_sgw_gtpu BPF object to the SGW-U-facing end of each, and provides raw
// AF_PACKET injection/capture helpers so tests can drive actual kernel BPF
// execution instead of only exercising the Go-side rule compiler.
//
// These tests require CAP_NET_ADMIN/CAP_BPF (root) to create netns/veth and
// attach XDP-BPF programs; they skip themselves when not available.

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	sgwugtpu "vectorcore-sgw/internal/sgwu/gtpu"
)

// requireRoot skips the calling test unless running as root. Creating
// network namespaces and attaching XDP-BPF programs requires CAP_NET_ADMIN
// and CAP_BPF, which non-root test environments (e.g. CI without privileges)
// will not have.
func requireRoot(t testing.TB) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("runtime BPF test requires root (CAP_NET_ADMIN/CAP_BPF) to create netns/veth and attach XDP-BPF")
	}
}

// linkPair is one veth link created inside the harness namespace.
type linkPair struct {
	name    string
	ip      net.IP
	ifindex int
	mac     net.HardwareAddr
}

// harness owns an isolated network namespace containing two veth pairs:
//
//	s1u <-> s1uPeer   (simulates the S1-U / Access link; BPF attaches to s1u)
//	s5u <-> s5uPeer   (simulates the S5/S8-U / Core link; BPF attaches to s5u)
//
// s1uPeer/s5uPeer simulate the eNodeB and PGW/peer SGW-U respectively — the
// test injects/captures raw frames on those ends.
type harness struct {
	origNS netns.NsHandle
	ns     netns.NsHandle

	s1u, s1uPeer linkPair
	s5u, s5uPeer linkPair
}

// newHarness creates the isolated namespace and both veth pairs, and
// registers cleanup. The calling goroutine's OS thread is locked for the
// duration of the test (network namespaces are per-thread, not per-process).
func newHarness(t testing.TB) *harness {
	t.Helper()
	requireRoot(t)

	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatalf("harness: netns.Get origin: %v", err)
	}

	ns, err := netns.New()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatalf("harness: netns.New: %v", err)
	}

	h := &harness{origNS: orig, ns: ns}
	t.Cleanup(func() {
		_ = h.ns.Close()
		_ = netns.Set(h.origNS)
		_ = h.origNS.Close()
		runtime.UnlockOSThread()
	})

	// A freshly created netns has "lo" administratively down. Even though
	// local delivery (RTN_LOCAL routes) is a routing decision rather than a
	// literal hop through lo, the kernel's local-delivery path for this
	// namespace does not work correctly until lo itself is brought up —
	// confirmed by reproducing with nsenter: local routes existed but a
	// plain UDP packet addressed to the receiving veth's own IP still never
	// reached a listening socket until "ip link set lo up" was run.
	loLink, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatalf("harness: LinkByName lo: %v", err)
	}
	if err := netlink.LinkSetUp(loLink); err != nil {
		t.Fatalf("harness: LinkSetUp lo: %v", err)
	}

	suffix := fmt.Sprintf("%d", os.Getpid()%10000)
	h.s1u, h.s1uPeer = mustVethPair(t, "s1u"+suffix, "s1up"+suffix,
		mustIPNet("10.81.1.1/24"), mustIPNet("10.81.1.2/24"))
	h.s5u, h.s5uPeer = mustVethPair(t, "s5u"+suffix, "s5up"+suffix,
		mustIPNet("10.81.2.1/24"), mustIPNet("10.81.2.2/24"))

	// In real deployments the eNodeB/PGW peer is never a locally-configured
	// address of the SGW-U host, so this does not apply in production. Here
	// both ends of each simulated link are local addresses of the SAME
	// namespace, and net.ipv4.conf.*.accept_local (default 0) silently
	// discards any packet whose *source* address is itself local when it
	// arrives on a different interface — confirmed by reproducing outside
	// Go entirely (raw AF_PACKET inject + tcpdump showed the frame accepted
	// at L2/IP, ip_rcv counted it, but it never reached the UDP socket and
	// no standard SNMP counter recorded a drop reason). Without this, every
	// capture/listener in this harness would silently see nothing.
	for _, dev := range []string{"all", h.s1u.name, h.s1uPeer.name, h.s5u.name, h.s5uPeer.name} {
		mustSysctl(t, fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/accept_local", dev), "1")
	}

	// Pre-populate static neighbor entries for the peer addresses on the
	// SGW-U-facing devices so bpf_redirect_neigh's automatic FIB+neighbor
	// resolution succeeds on the first packet instead of dropping it while
	// an asynchronous ARP resolution would otherwise be in flight.
	mustNeigh(t, h.s5u.ifindex, h.s5uPeer.ip, h.s5uPeer.mac)
	mustNeigh(t, h.s1u.ifindex, h.s1uPeer.ip, h.s1uPeer.mac)

	return h
}

func mustIPNet(s string) *net.IPNet {
	ip, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	ipnet.IP = ip
	return ipnet
}

func mustVethPair(t testing.TB, name, peerName string, ip, peerIP *net.IPNet) (linkPair, linkPair) {
	t.Helper()
	v := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: name},
		PeerName:  peerName,
	}
	if err := netlink.LinkAdd(v); err != nil {
		t.Fatalf("harness: LinkAdd %s/%s: %v", name, peerName, err)
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatalf("harness: LinkByName %s: %v", name, err)
	}
	peer, err := netlink.LinkByName(peerName)
	if err != nil {
		t.Fatalf("harness: LinkByName %s: %v", peerName, err)
	}

	if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: ip}); err != nil {
		t.Fatalf("harness: AddrAdd %s: %v", name, err)
	}
	if err := netlink.AddrAdd(peer, &netlink.Addr{IPNet: peerIP}); err != nil {
		t.Fatalf("harness: AddrAdd %s: %v", peerName, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatalf("harness: LinkSetUp %s: %v", name, err)
	}
	if err := netlink.LinkSetUp(peer); err != nil {
		t.Fatalf("harness: LinkSetUp %s: %v", peerName, err)
	}

	return linkPair{name: name, ip: ip.IP, ifindex: link.Attrs().Index, mac: link.Attrs().HardwareAddr},
		linkPair{name: peerName, ip: peerIP.IP, ifindex: peer.Attrs().Index, mac: peer.Attrs().HardwareAddr}
}

func mustSysctl(t testing.TB, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0644); err != nil {
		t.Fatalf("harness: write %s=%s: %v", path, value, err)
	}
}

func mustNeigh(t testing.TB, linkIndex int, ip net.IP, mac net.HardwareAddr) {
	t.Helper()
	n := &netlink.Neigh{
		LinkIndex:    linkIndex,
		Family:       netlink.FAMILY_V4,
		State:        netlink.NUD_PERMANENT,
		IP:           ip,
		HardwareAddr: mac,
	}
	if err := netlink.NeighAdd(n); err != nil {
		t.Fatalf("harness: NeighAdd %s on ifindex %d: %v", ip, linkIndex, err)
	}
}

// htons converts a uint16 from host to network byte order.
func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

// openRawSocket opens an AF_PACKET SOCK_RAW socket bound to ifindex.
// proto should be a host-order EtherType (e.g. unix.ETH_P_ALL, unix.ETH_P_IP).
// If timeout > 0, read calls return a timeout error after that duration.
func openRawSocket(t testing.TB, ifindex int, proto uint16, timeout time.Duration) int {
	t.Helper()
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(proto)))
	if err != nil {
		t.Fatalf("harness: socket(AF_PACKET): %v", err)
	}
	sa := &unix.SockaddrLinklayer{Protocol: htons(proto), Ifindex: ifindex}
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		t.Fatalf("harness: bind ifindex %d: %v", ifindex, err)
	}
	if timeout > 0 {
		tv := unix.NsecToTimeval(timeout.Nanoseconds())
		if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
			unix.Close(fd)
			t.Fatalf("harness: SO_RCVTIMEO: %v", err)
		}
	}
	t.Cleanup(func() { unix.Close(fd) })
	return fd
}

// ipv4Checksum computes the standard one's-complement-of-one's-complement-sum
// IPv4 header checksum (RFC 791 §3.1) over b, which must have its checksum
// field already zeroed.
func ipv4Checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// buildGPDUFrame constructs a full Ethernet/IPv4/UDP/GTP-U G-PDU frame.
// The GTP-U header is built with sgwugtpu.Marshal (the already-implemented,
// already-tested Phase 6 encoder) so this harness does not re-derive any
// GTP-U wire-format constant from memory.
func buildGPDUFrame(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort uint16, teid uint32, payload []byte) []byte {
	return buildGPDUFrameWithTOS(srcMAC, dstMAC, srcIP, dstIP, srcPort, teid, 0, payload)
}

func buildGPDUFrameWithTOS(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort uint16, teid uint32, tos uint8, payload []byte) []byte {
	gtpHdr := sgwugtpu.Marshal(sgwugtpu.Header{
		Version: 1,
		PT:      true,
		MsgType: sgwugtpu.MsgTypeGPDU,
		TEID:    teid,
	}, len(payload))

	udpPayload := append(append([]byte{}, gtpHdr...), payload...)
	udpLen := 8 + len(udpPayload)
	udp := make([]byte, 8, 8+len(udpPayload))
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], uint16(sgwugtpu.Port))
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	binary.BigEndian.PutUint16(udp[6:8], 0) // checksum: 0 = not used, valid for IPv4 per RFC 768
	udp = append(udp, udpPayload...)

	ipLen := 20 + len(udp)
	ip := make([]byte, 20)
	ip[0] = 0x45 // version=4, IHL=5 (no options)
	ip[1] = tos  // DSCP/ECN
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipLen))
	binary.BigEndian.PutUint16(ip[4:6], 0) // identification
	binary.BigEndian.PutUint16(ip[6:8], 0) // flags/fragment offset
	ip[8] = 64                             // TTL
	ip[9] = unix.IPPROTO_UDP
	binary.BigEndian.PutUint16(ip[10:12], 0) // checksum placeholder
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(ip[10:12], ipv4Checksum(ip))

	eth := make([]byte, 14)
	copy(eth[0:6], dstMAC)
	copy(eth[6:12], srcMAC)
	binary.BigEndian.PutUint16(eth[12:14], unix.ETH_P_IP)

	frame := make([]byte, 0, len(eth)+len(ip)+len(udp))
	frame = append(frame, eth...)
	frame = append(frame, ip...)
	frame = append(frame, udp...)
	return frame
}

// parsedFrame is the result of decoding a captured Ethernet/IPv4/UDP/GTP-U frame.
type parsedFrame struct {
	srcIP, dstIP net.IP
	teid         uint32
	tos          uint8
	payload      []byte
	raw          []byte
}

// captureGPDU reads frames from fd (an ETH_P_ALL raw socket) until one
// parses successfully as an IPv4/UDP/GTP-U frame or the read times out
// (fd must have been opened with a timeout via openRawSocket). This is
// necessary because ETH_P_ALL captures everything on the link — IPv6 NDP,
// ARP, etc. — not just the frame under test, so a single blocking Read is
// not reliable even when a real G-PDU is expected.
func captureGPDU(fd int) (parsedFrame, bool) {
	buf := make([]byte, 2048)
	for {
		n, err := unix.Read(fd, buf)
		if err != nil {
			return parsedFrame{}, false
		}
		if pf, perr := parseGPDUFrame(buf[:n]); perr == nil {
			pf.raw = append([]byte{}, buf[:n]...)
			return pf, true
		}
	}
}

// parseGPDUFrame decodes a captured frame back to its outer IP addresses and
// inner GTP-U TEID/payload, using sgwugtpu.Parse for the GTP-U portion.
func parseGPDUFrame(b []byte) (parsedFrame, error) {
	const ethLen = 14
	if len(b) < ethLen+20+8+sgwugtpu.MinLen {
		return parsedFrame{}, fmt.Errorf("frame too short: %d bytes", len(b))
	}
	ipStart := ethLen
	ihl := int(b[ipStart]&0x0F) * 4
	udpStart := ipStart + ihl
	gtpStart := udpStart + 8
	if gtpStart > len(b) {
		return parsedFrame{}, fmt.Errorf("frame too short for IHL=%d", ihl)
	}
	hdr, hdrLen, err := sgwugtpu.Parse(b[gtpStart:])
	if err != nil {
		return parsedFrame{}, fmt.Errorf("gtpu parse: %w", err)
	}
	return parsedFrame{
		srcIP:   net.IP(append([]byte{}, b[ipStart+12:ipStart+16]...)),
		dstIP:   net.IP(append([]byte{}, b[ipStart+16:ipStart+20]...)),
		tos:     b[ipStart+1],
		teid:    hdr.TEID,
		payload: append([]byte{}, b[gtpStart+hdrLen:]...),
	}, nil
}

func maybeWritePCAP(t testing.TB, name string, frames ...[]byte) {
	t.Helper()
	dir := os.Getenv("BPF_RUNTIME_PCAP_DIR")
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("pcap mkdir %s: %v", dir, err)
	}
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("pcap create %s: %v", path, err)
	}
	defer f.Close()

	// PCAP global header, little-endian, linktype Ethernet.
	global := make([]byte, 24)
	binary.LittleEndian.PutUint32(global[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(global[4:6], 2)
	binary.LittleEndian.PutUint16(global[6:8], 4)
	binary.LittleEndian.PutUint32(global[16:20], 65535)
	binary.LittleEndian.PutUint32(global[20:24], 1)
	if _, err := f.Write(global); err != nil {
		t.Fatalf("pcap write header %s: %v", path, err)
	}

	for _, frame := range frames {
		now := time.Now()
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[0:4], uint32(now.Unix()))
		binary.LittleEndian.PutUint32(rec[4:8], uint32(now.Nanosecond()/1000))
		binary.LittleEndian.PutUint32(rec[8:12], uint32(len(frame)))
		binary.LittleEndian.PutUint32(rec[12:16], uint32(len(frame)))
		if _, err := f.Write(rec); err != nil {
			t.Fatalf("pcap write record header %s: %v", path, err)
		}
		if _, err := f.Write(frame); err != nil {
			t.Fatalf("pcap write frame %s: %v", path, err)
		}
	}
}
