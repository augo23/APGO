//go:build windows

package main

// Full-VPN (use_exit) plumbing for Windows. Two pieces (see vpnroutes.go):
//
//  1. enableFullTunnelRoutes adds 0.0.0.0/1 + 128.0.0.0/1 on the Wintun
//     adapter with netsh. Both are more specific than the real default route,
//     so every internet-bound packet enters the overlay TUN — where the
//     client forwards it to the selected exit — while the original default
//     route is left untouched. LAN-subnet routes stay direct (the connected
//     /24 on the physical NIC is more specific still). The routes are bound
//     to the Wintun adapter, which is destroyed on exit; no cleanup needed.
//
//  2. pinTransportToPhysicalInterface binds the UDP transport socket to the
//     physical default interface (IP_UNICAST_IF / IPV6_UNICAST_IF), so the
//     client's own encrypted packets to peers and trackers bypass the /1
//     routes — otherwise they'd re-enter the TUN and loop.
//
// Note: the overlay is IPv4; if the local network has native IPv6, v6 traffic
// is not captured (it keeps using the normal v6 default route).

import (
	"fmt"
	"log"
	"net"

	"golang.org/x/sys/windows"
)

func enableFullTunnelRoutes() error {
	if tunName == "" {
		return fmt.Errorf("no TUN interface")
	}
	for _, half := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		// Idempotent: clear any stale claim on this half first, then add ours.
		_, _ = runCmd("netsh", "interface", "ipv4", "delete", "route",
			"prefix="+half, "interface="+tunName)
		if out, err := runCmd("netsh", "interface", "ipv4", "add", "route",
			"prefix="+half, "interface="+tunName, "metric=1", "store=active"); err != nil {
			return fmt.Errorf("netsh add route %s via %s: %v (%s)", half, tunName, err, out)
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
	idx := ifi.Index
	// IP_UNICAST_IF wants the interface index in NETWORK byte order;
	// IPV6_UNICAST_IF wants host byte order.
	be := ((idx & 0xff) << 24) | ((idx & 0xff00) << 8) | ((idx >> 8) & 0xff00) | ((idx >> 24) & 0xff)
	var errV4, errV6 error
	if cerr := raw.Control(func(fd uintptr) {
		errV4 = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_UNICAST_IF, be)
		// Dual-stack sockets need the v6 side bound too; on a v4-only socket
		// this fails harmlessly.
		errV6 = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, windows.IPV6_UNICAST_IF, idx)
	}); cerr != nil {
		return cerr
	}
	if errV4 != nil && errV6 != nil {
		return fmt.Errorf("IP_UNICAST_IF: %v; IPV6_UNICAST_IF: %v", errV4, errV6)
	}
	physIfIndex = idx
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
	idx := physIfIndex
	be := ((idx & 0xff) << 24) | ((idx & 0xff00) << 8) | ((idx >> 8) & 0xff00) | ((idx >> 24) & 0xff)
	_ = raw.Control(func(fd uintptr) {
		_ = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_UNICAST_IF, be)
		_ = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, windows.IPV6_UNICAST_IF, idx)
	})
}
