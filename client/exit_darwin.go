//go:build darwin

package main

import (
	"fmt"
	"log"
	"os"
	"strings"
)

// setupExitNAT turns this Mac into an internet exit for overlay clients:
// enable IPv4 forwarding and NAT overlay-sourced traffic out the physical
// default interface with pf (macOS's built-in packet filter).
//
// The NAT rule is loaded into a sub-anchor under "com.apple/*". The stock
// /etc/pf.conf evaluates that wildcard via its nat-anchor/anchor lines, so the
// rule takes effect WITHOUT editing any system file, and disappears on reboot
// (we re-load it on every start — same idempotent spirit as the Linux
// delete-then-add iptables rules). Requires root, which the client already has
// for the utun.
func setupExitNAT() error {
	if overlayNet == nil {
		return fmt.Errorf("overlay subnet unknown")
	}
	cidr := overlayNet.String()

	// 1. IPv4 forwarding (per-boot; reset on reboot, re-applied on start).
	if out, err := runCmd("sysctl", "-w", "net.inet.ip.forwarding=1"); err != nil {
		return fmt.Errorf("enable net.inet.ip.forwarding: %v (%s)", err, out)
	}

	// 2. Egress interface = the one carrying the system default route. Must be
	// resolved BEFORE any full-tunnel routes could confuse the lookup (an exit
	// normally doesn't run use_exit, but be defensive and fail clearly).
	ifi, err := physicalDefaultInterface()
	if err != nil {
		return fmt.Errorf("find default-route interface: %v", err)
	}

	// 3. NAT overlay-sourced traffic out that interface. "(if)" tracks the
	// interface's address across DHCP changes. Rules go through a real file:
	// macOS's pfctl (an old OpenBSD fork) does not reliably read rules from
	// stdin, and a failed load here silently killed exit-node mode.
	rules := fmt.Sprintf("nat on %s inet from %s to any -> (%s)\n",
		ifi.Name, cidr, ifi.Name)
	tmp, err := os.CreateTemp("", "apgo-exit-*.conf")
	if err != nil {
		return fmt.Errorf("write pf rules: %v", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(rules); err != nil {
		tmp.Close()
		return fmt.Errorf("write pf rules: %v", err)
	}
	tmp.Close()
	const anchor = "com.apple/250.ApgoExit"
	if out, err := runCmd("pfctl", "-a", anchor, "-f", tmp.Name()); err != nil {
		return fmt.Errorf("pfctl load NAT rule: %v (%s)", err, out)
	}

	// 4. Make sure pf itself is running. -E enables with a reference count
	// (Internet Sharing and VPN apps use the same mechanism), so this never
	// fights other software and is safe when pf is already enabled. pfctl
	// prints its token chatter on stderr and can exit non-zero when pf is
	// already up — only treat it as fatal if pf is genuinely not enabled.
	if out, err := runCmd("pfctl", "-E"); err != nil &&
		!strings.Contains(out, "already enabled") && !strings.Contains(out, "Token") {
		if st, _ := runCmd("pfctl", "-s", "info"); !strings.Contains(st, "Status: Enabled") {
			return fmt.Errorf("pfctl -E: %v (%s)", err, out)
		}
	}

	// 5. Trust, but verify: read the anchor back. If the rule is not actually
	// installed, say so NOW instead of advertising an exit that black-holes.
	if out, _ := runCmd("pfctl", "-a", anchor, "-s", "nat"); !strings.Contains(out, cidr) {
		return fmt.Errorf("pf NAT rule did not take (anchor %s shows: %q)", anchor, out)
	}

	log.Printf("[exit] macOS NAT ready — masquerading %s out %s via pf", cidr, ifi.Name)
	return nil
}
