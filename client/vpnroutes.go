package main

// vpnroutes.go — shared helper for full-VPN (use_exit) mode on desktop OSes.
//
// When use_exit is on, the OS must steer ALL internet-bound traffic into the
// overlay TUN (where the client forwards it to the selected exit node). The
// per-OS half is in vpnroutes_darwin.go / vpnroutes_windows.go /
// vpnroutes_other.go:
//
//   enableFullTunnelRoutes           — install 0.0.0.0/1 + 128.0.0.0/1 via the
//                                      TUN (more specific than the real default
//                                      route, so it wins without touching it)
//   pinTransportToPhysicalInterface  — bind the UDP transport socket to the
//                                      physical default interface so the
//                                      client's own encrypted packets to peers
//                                      NEVER match those routes (no loop)
//
// The routes are interface-scoped, so they disappear automatically when the
// TUN goes away (client exit/crash) — no cleanup pass needed.

import (
	"errors"
	"net"
)

// physIfIndex caches the physical default interface's index, captured by
// pinTransportToPhysicalInterface BEFORE the full-tunnel routes go in (a
// route lookup done afterward would resolve to the TUN itself). Auxiliary
// short-lived sockets (tracker announces) reuse it via pinAuxUDPSocket.
var physIfIndex int

// physicalDefaultInterface returns the interface currently carrying the
// system's default route. Uses a connected-UDP route lookup (no packet is
// sent) and must therefore run BEFORE the full-tunnel routes are installed.
func physicalDefaultInterface() (*net.Interface, error) {
	c, err := net.Dial("udp4", "8.8.8.8:53")
	if err != nil {
		return nil, err
	}
	local := c.LocalAddr().(*net.UDPAddr).IP
	_ = c.Close()

	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for i := range ifs {
		addrs, err := ifs[i].Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.Equal(local) {
				return &ifs[i], nil
			}
		}
	}
	return nil, errors.New("could not match the default-route source address to an interface")
}
