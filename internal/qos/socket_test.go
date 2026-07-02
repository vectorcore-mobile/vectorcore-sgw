package qos

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSetUDPConnIPv4DSCP(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	if err := SetUDPConnIPv4DSCP(conn, 40); err != nil {
		t.Fatalf("SetUDPConnIPv4DSCP: %v", err)
	}

	got := udpConnIPv4TOS(t, conn)
	if got != 0xa0 {
		t.Fatalf("IP_TOS = %#x, want 0xa0", got)
	}
}

func TestSetUDPConnIPv4DSCPRejectsInvalidValue(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	if err := SetUDPConnIPv4DSCP(conn, 64); err == nil {
		t.Fatal("SetUDPConnIPv4DSCP succeeded with DSCP 64")
	}
}

func udpConnIPv4TOS(t *testing.T, conn *net.UDPConn) int {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var got int
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		got, sockErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TOS)
	}); err != nil {
		t.Fatalf("Control: %v", err)
	}
	if sockErr != nil {
		t.Fatalf("GetsockoptInt(IP_TOS): %v", sockErr)
	}
	return got
}
