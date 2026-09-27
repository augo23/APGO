//go:build windows

package main

import (
	"net"

	"golang.org/x/sys/windows"
)

// setProbeTTL caps how far a spray probe travels (see natspray_ttl_unix.go).
func setProbeTTL(c *net.UDPConn, ttl int) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := rc.Control(func(fd uintptr) {
		serr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_TTL, ttl)
	}); err != nil {
		return err
	}
	return serr
}
