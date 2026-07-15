//go:build windows

package main

import (
	"net"
	"syscall"
)

// enableBroadcast sets SO_BROADCAST on a UDP socket (Windows variant).
func enableBroadcast(c *net.UDPConn) {
	if raw, err := c.SyscallConn(); err == nil {
		_ = raw.Control(func(fd uintptr) {
			_ = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
		})
	}
}
