//go:build !windows

package main

import (
	"net"

	"golang.org/x/sys/unix"
)

// setProbeTTL caps how far a spray probe travels. See natspray.go: the probe
// must clear our own NAT (so the mapping is created) and must NOT reach the
// peer's NAT, because an arriving probe creates an inbound conntrack entry
// there on exactly the port the peer is about to spray — and a NAT will not
// hand its own local socket a source port whose reverse tuple is already
// taken, so it silently renumbers the peer and every hit becomes impossible.
func setProbeTTL(c *net.UDPConn, ttl int) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := rc.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, ttl)
	}); err != nil {
		return err
	}
	return serr
}
