//go:build linux

package main

// multihome_linux.go lets TWO overlay clients share one network namespace.
//
// THE PROBLEM (and why a different interface name does not solve it)
//
// The TUN name is already allocated dynamically — ovl0, ovl1, … — so two
// clients never fight over the device itself. The collision is in the ROUTING
// TABLE. Each client normally assigns its address as a /24, which installs a
// CONNECTED route for the whole overlay subnet:
//
//	ovl7  10.22.22.7/24   -> connected route 10.22.22.0/24 dev ovl7
//	ovl8  10.22.22.22/24  -> connected route 10.22.22.0/24 dev ovl8   <-- same!
//
// Two identical routes, and the kernel picks between them by metric/order —
// effectively arbitrarily. Replies to an overlay peer then leave through the
// WRONG tunnel, under the wrong node identity, and the far end sees packets
// from an address it associates with a different key. Observed symptoms:
// heavy ping loss, "message authentication failed", "replayed or expired
// nonce", constant re-handshakes.
//
// THE FIX: /32 + SOURCE-BASED POLICY ROUTING
//
// The second (and later) client on a host:
//
//	1. assigns its overlay address as a /32, so it adds NO connected /24 and
//	   cannot compete with the existing one; and
//	2. installs its own routing table containing the overlay /24 via its own
//	   TUN, selected by an `ip rule` matching FROM its own address.
//
// Result: traffic sourced from THIS client's overlay address always leaves
// through THIS client's tunnel, while everything else on the host keeps using
// the first client exactly as before. This is the standard multi-homing
// pattern (`ip rule from <addr> lookup <table>`), and it is what makes
// hostNetwork viable on a node that already runs another overlay client.
//
// Everything here is best-effort and self-healing: if the rules cannot be
// installed we log precisely why and continue in the previous (single-client)
// behaviour rather than failing to start.

import (
	"fmt"
	"log"
	"net"

	"github.com/vishvananda/netlink"
)

// policyTableBase is where per-client routing tables start. Well above the
// reserved IDs (main=254, default=253, local=255) and clear of the ranges
// systemd-networkd and Kubernetes CNIs typically use.
const policyTableBase = 7100

// overlaySiblingOnHost reports an EXISTING interface (not ours) that already
// carries a connected route for the overlay subnet, or "" if none. That is the
// precise condition under which a second client must switch to policy routing.
func overlaySiblingOnHost(myLink string, overlay *net.IPNet) string {
	if overlay == nil {
		return ""
	}
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return ""
	}
	ones, _ := overlay.Mask.Size()
	for _, r := range routes {
		if r.Dst == nil || r.Gw != nil { // connected routes only
			continue
		}
		rOnes, _ := r.Dst.Mask.Size()
		if rOnes != ones || !r.Dst.IP.Equal(overlay.IP) {
			continue
		}
		link, err := netlink.LinkByIndex(r.LinkIndex)
		if err != nil || link.Attrs().Name == myLink {
			continue
		}
		return link.Attrs().Name
	}
	return ""
}

// enableOverlayPolicyRouting makes this client coexist with an existing
// overlay client in the same namespace. addrCIDR is our overlay address (e.g.
// "10.22.22.22/24"); it is re-applied as a /32. Returns the table id used.
func enableOverlayPolicyRouting(addrCIDR string, overlay *net.IPNet) (int, error) {
	ip, _, err := net.ParseCIDR(addrCIDR)
	if err != nil {
		return 0, fmt.Errorf("parse overlay address %q: %w", addrCIDR, err)
	}
	link, err := netlink.LinkByName(tunName)
	if err != nil {
		return 0, fmt.Errorf("find %s: %w", tunName, err)
	}

	// 1. Replace the /24 with a /32 so no connected subnet route is created.
	if addrs, err := netlink.AddrList(link, netlink.FAMILY_V4); err == nil {
		for i := range addrs {
			_ = netlink.AddrDel(link, &addrs[i])
		}
	}
	host32 := &netlink.Addr{IPNet: &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}}
	if err := netlink.AddrAdd(link, host32); err != nil && err.Error() != "file exists" {
		return 0, fmt.Errorf("add %s/32: %w", ip, err)
	}

	// 2. A private table holding the overlay subnet via our own TUN. The id is
	// derived from the interface index so two clients never pick the same one.
	table := policyTableBase + link.Attrs().Index
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       overlay,
		Table:     table,
		Scope:     netlink.SCOPE_LINK,
	}
	if err := netlink.RouteReplace(route); err != nil {
		return 0, fmt.Errorf("route %s dev %s table %d: %w", overlay, tunName, table, err)
	}

	// 3. Select that table for anything sourced from our own overlay address.
	rule := netlink.NewRule()
	rule.Src = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
	rule.Table = table
	rule.Priority = table
	_ = netlink.RuleDel(rule) // idempotent across restarts
	if err := netlink.RuleAdd(rule); err != nil {
		return 0, fmt.Errorf("ip rule from %s lookup %d: %w", ip, table, err)
	}
	return table, nil
}

// setupOverlayCoexistence is called after the TUN is up. It detects a sibling
// overlay client on this host and, if present, switches to /32 + policy
// routing. No-op (and no behaviour change) when this is the only client.
func setupOverlayCoexistence(addrCIDR string) {
	if addrCIDR == "" || overlayNet == nil || tunName == "" {
		return
	}
	sibling := overlaySiblingOnHost(tunName, overlayNet)
	if sibling == "" {
		return // sole overlay client on this host — nothing to do
	}
	log.Printf("[multihome] another overlay client is already on this host (%s carries %s). "+
		"Switching %s to /32 + source-based policy routing so both can coexist.",
		sibling, overlayNet, tunName)
	table, err := enableOverlayPolicyRouting(addrCIDR, overlayNet)
	if err != nil {
		log.Printf("[multihome] could NOT install policy routing (%v). This host now has two "+
			"connected routes for %s and the kernel will choose between them arbitrarily — expect "+
			"packet loss and repeated re-handshakes. Run this client in its own network namespace "+
			"(a non-hostNetwork pod/container) instead.", err, overlayNet)
		return
	}
	log.Printf("[multihome] ready: %s holds %s/32, table %d routes %s via %s, "+
		"rule 'from %s lookup %d'. Traffic from this node's overlay address now always uses %s.",
		tunName, stripMask(addrCIDR), table, overlayNet, tunName, stripMask(addrCIDR), table, tunName)
}
