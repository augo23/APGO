//go:build darwin

package main

// Full-VPN (use_exit) plumbing for macOS. Two pieces (see vpnroutes.go):
//
//  1. enableFullTunnelRoutes adds 0.0.0.0/1 + 128.0.0.0/1 via the utun. Both
//     are more specific than the real default route, so every internet-bound
//     packet enters the overlay TUN — where the client forwards it to the
//     selected exit — while the original default route is left untouched.
//     LAN-subnet routes (DNS to the home router, printers, …) stay direct
//     because the connected /24 on the physical interface is more specific
//     still. utun-scoped routes vanish with the utun on exit; no cleanup.
//
//  2. pinTransportToPhysicalInterface binds the UDP transport socket to the
//     physical default interface (IP_BOUND_IF / IPV6_BOUND_IF), so the
//     client's own encrypted packets to peers and trackers bypass the /1
//     routes — otherwise they'd re-enter the TUN and loop.
//
// Note: the overlay is IPv4; if the local network has native IPv6, v6 traffic
// is not captured (it keeps using the normal v6 default route).

import (
	"fmt"
	"log"
	"net"
	"strings"

	"golang.org/x/sys/unix"
)

func enableFullTunnelRoutes() error {
	if tunName == "" {
		return fmt.Errorf("no TUN interface")
	}
	for _, half := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		// Idempotent: clear any stale claim on this half first (e.g. from a
		// previous run whose utun number changed), then add ours.
		_, _ = runCmd("route", "-n", "delete", "-inet", "-net", half)
		if out, err := runCmd("route", "-n", "add", "-inet", "-net", half, "-interface", tunName); err != nil {
			if !strings.Contains(out, "File exists") {
				return fmt.Errorf("route add %s via %s: %v (%s)", half, tunName, err, out)
			}
		}
	}
	log.Printf("[exit] full-tunnel routes installed (0.0.0.0/1 + 128.0.0.0/1 via %s)", tunName)
	return nil
}

func pinTransportToPhysicalInterface(conn *net.UDPConn) error {
	ifi, err := physicalDefaultInterface()
	if err != nil {
		return err
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var errV4, errV6 error
	if cerr := raw.Control(func(fd uintptr) {
		errV4 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, ifi.Index)
		// Dual-stack sockets need the v6 side bound too; on a v4-only socket
		// this fails harmlessly.
		errV6 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, ifi.Index)
	}); cerr != nil {
		return cerr
	}
	if errV4 != nil && errV6 != nil {
		return fmt.Errorf("IP_BOUND_IF: %v; IPV6_BOUND_IF: %v", errV4, errV6)
	}
	physIfIndex = ifi.Index
	log.Printf("[exit] transport socket pinned to %s (so peer traffic bypasses the VPN routes)", ifi.Name)
	return nil
}

// pinAuxUDPSocket binds a short-lived helper socket (tracker announce, LAN
// discovery) to the physical interface while full-tunnel routes are active,
// so discovery keeps working even before an exit has been selected. No-op
// when full-VPN mode isn't running.
func pinAuxUDPSocket(conn *net.UDPConn) {
	if physIfIndex == 0 || conn == nil {
		return
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, physIfIndex)
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, physIfIndex)
	})
}
