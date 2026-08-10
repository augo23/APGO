package main

// lanconflict.go — detect an overlay CIDR that collides with a physical
// network this machine is attached to. When the overlay subnet and the LAN
// are the SAME range (e.g. overlay 10.22.22.0/24 on a home LAN that is also
// 10.22.22.0/24), the overlay route on the TUN and the connected LAN route
// fight over every address in the range: peers show "wrong" IPs (a LAN
// address and an overlay address are indistinguishable), and an exit node's
// return traffic to a client's overlay IP can be routed onto the LAN instead
// of into the tunnel — full VPN then fails even with NAT working perfectly.
// This is a configuration problem no code path can fix, so detect it and say
// it everywhere (log + dashboards).

import (
	"fmt"
	"net"
)

// overlayLANConflict is set at startup: a human-readable description of the
// physical interface whose IPv4 network overlaps the overlay CIDR, or "".
var overlayLANConflict string

// detectOverlayLANConflict scans physical interfaces (the overlay TUN itself
// is excluded) for an IPv4 network overlapping the overlay subnet.
func detectOverlayLANConflict() string {
	if overlayNet == nil {
		return ""
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for i := range ifs {
		ifi := &ifs[i]
		if ifi.Name == tunName || ifi.Flags&net.FlagLoopback != 0 || ifi.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil {
				continue
			}
			// Overlap in either direction: LAN inside overlay, or overlay
			// inside LAN (covers unequal prefix lengths).
			if overlayNet.Contains(ipn.IP) || ipn.Contains(overlayNet.IP) {
				return fmt.Sprintf("interface %s is on %s, which overlaps the overlay subnet %s",
					ifi.Name, ipn.String(), overlayNet.String())
			}
		}
	}
	return ""
}
