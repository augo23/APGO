//go:build !windows

package main

import (
	"net"
	"syscall"
)

// enableBroadcast sets SO_BROADCAST on a UDP socket so that writes to the
// limited broadcast address (255.255.255.255) are actually delivered. Go does
// not set this by default, and without it many kernels silently drop the
// packet — which breaks LAN peer discovery.
func enableBroadcast(c *net.UDPConn) {
	if raw, err := c.SyscallConn(); err == nil {
		_ = raw.Control(func(fd uintptr) {
			_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
		})
	}
}
