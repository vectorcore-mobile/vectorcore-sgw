package qos

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// SetUDPConnIPv4DSCP sets the DSCP bits on IPv4 packets sent by conn.
// ECN is left for the kernel to preserve; DSCP occupies the upper six TOS bits.
func SetUDPConnIPv4DSCP(conn *net.UDPConn, dscp uint8) error {
	if dscp > 63 {
		return fmt.Errorf("dscp must be in range 0-63, got %d", dscp)
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("udp syscall conn: %w", err)
	}
	tos := int(dscp) << 2
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TOS, tos)
	}); err != nil {
		return fmt.Errorf("udp control: %w", err)
	}
	if sockErr != nil {
		return fmt.Errorf("set IP_TOS: %w", sockErr)
	}
	return nil
}
