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
// The overlay is IPv4; IPv6 is captured and dropped (captureIPv6) so it
// cannot bypass the exit.

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
	captureIPv6(true)
	return nil
}

// fullTunnelV6Halves steer IPv6 into the utun as well. The overlay carries
// IPv4 only and the client drops every v6 packet it reads, so this is a
// blackhole on purpose: without it, on any network with native IPv6, apps
// keep reaching the internet over the home connection (and IP-check sites
// report the home address) while Full VPN claims to be on. Apps fall back to
// IPv4, which goes through the exit — the iOS app does the same.
var fullTunnelV6Halves = []string{"::/1", "8000::/1"}

func captureIPv6(on bool) {
	if tunName == "" {
		return
	}
	for _, half := range fullTunnelV6Halves {
		_, _ = runCmd("route", "-n", "delete", "-inet6", "-net", half, "-interface", tunName)
		if !on {
			continue
		}
		if out, err := runCmd("route", "-n", "add", "-inet6", "-net", half, "-interface", tunName); err != nil &&
			!strings.Contains(out, "File exists") {
			log.Printf("[exit] WARNING: could not capture IPv6 (%s via %s: %v %s) — on networks with IPv6, "+
				"some traffic may still leave through this Mac's own connection", half, tunName, err, strings.TrimSpace(out))
			return
		}
	}
}

func pinTransportToPhysicalInterface(conn *net.UDPConn) error {
	gw, ifname, err := physicalDefaultRoute("inet")
	var ifi *net.Interface
	if err == nil {
		ifi, err = net.InterfaceByName(ifname)
	}
	if err != nil {
		// Fall back to the route-lookup method (fine while no /1 routes exist).
		if ifi, err = physicalDefaultInterface(); err != nil {
			return err
		}
		gw = ""
	}
	// A socket bound to an interface only ever uses routes SCOPED to that
	// interface once the /1 routes point everything else at the utun. macOS
	// keeps no scoped copy of the PRIMARY interface's default route, so
	// without this every send to a peer beyond the local subnet failed with
	// "network is unreachable" — the exit could never be reached and Full VPN
	// cut this Mac off entirely.
	if gw != "" {
		ensureScopedDefault("inet", ifi.Name, gw)
	}
	if gw6, if6, err6 := physicalDefaultRoute("inet6"); err6 == nil && if6 == ifi.Name {
		ensureScopedDefault("inet6", ifi.Name, gw6)
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
	log.Printf("[exit] transport socket pinned to %s via %s (so peer traffic bypasses the VPN routes)", ifi.Name, gw)
	return nil
}

// physicalDefaultRoute returns the gateway and interface of the system's own
// (unscoped) default route for family "inet" or "inet6", ignoring tunnels.
// Read from the routing table rather than by a route lookup, which would
// resolve to our utun once the /1 routes exist.
func physicalDefaultRoute(family string) (gw, ifname string, err error) {
	out, err := runCmd("netstat", "-rn", "-f", family)
	if err != nil {
		return "", "", fmt.Errorf("netstat: %v", err)
	}
	gw, ifname = parseDefaultRoute(out)
	if gw == "" {
		return "", "", fmt.Errorf("no %s default route on a physical interface", family)
	}
	return gw, ifname, nil
}

// scopedDefaultsAdded remembers the scoped default routes this client added,
// so switching Full VPN off removes exactly those.
var scopedDefaultsAdded [][3]string // family, interface, gateway

func ensureScopedDefault(family, ifname, gw string) {
	out, _ := runCmd("netstat", "-rn", "-f", family)
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && f[0] == "default" && strings.Contains(f[2], "I") && f[3] == ifname {
			return // already there (macOS keeps one for non-primary interfaces)
		}
	}
	if out, err := runCmd("route", "-n", "add", "-"+family, "-ifscope", ifname, "default", gw); err != nil {
		if !strings.Contains(out, "File exists") {
			log.Printf("[exit] WARNING: could not add a %s default route scoped to %s via %s: %v (%s) — "+
				"peers beyond the local network may be unreachable while Full VPN is on", family, ifname, gw, err, strings.TrimSpace(out))
		}
		return
	}
	scopedDefaultsAdded = append(scopedDefaultsAdded, [3]string{family, ifname, gw})
}

func removeScopedDefaults() {
	for _, r := range scopedDefaultsAdded {
		_, _ = runCmd("route", "-n", "delete", "-"+r[0], "-ifscope", r[1], "default", r[2])
	}
	scopedDefaultsAdded = nil
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

// disableFullTunnelRoutes removes the two half-default routes (full VPN
// switched off while running). Missing routes are not an error.
func disableFullTunnelRoutes() error {
	var firstErr error
	for _, half := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		args := []string{"-n", "delete", "-inet", "-net", half}
		if tunName != "" {
			args = append(args, "-interface", tunName)
		}
		if out, err := runCmd("route", args...); err != nil && !strings.Contains(out, "not in table") && firstErr == nil {
			firstErr = fmt.Errorf("route delete %s: %v (%s)", half, err, out)
		}
	}
	captureIPv6(false)
	if firstErr == nil {
		log.Printf("[exit] full-tunnel routes removed")
	}
	return firstErr
}

// unpinTransport releases the physical-interface binding set by
// pinTransportToPhysicalInterface, so the socket follows the normal routing
// table again (and survives a switch between Wi-Fi and Ethernet).
func unpinTransport(conn *net.UDPConn) {
	physIfIndex = 0
	removeScopedDefaults()
	raw, err := conn.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, 0)
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, 0)
	})
}
