//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
)

// setupExitNAT turns this Linux node into an internet exit for overlay clients:
// enable IPv4 forwarding and masquerade overlay-sourced traffic out the default
// interface. Requires NET_ADMIN (the client already runs privileged for the TUN).
func setupExitNAT() error {
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644); err != nil {
		// In a non-privileged container /proc/sys is mounted READ-ONLY even
		// with NET_ADMIN + host networking, so this write always fails there.
		// That's fine as long as the host already forwards — check the live
		// value before giving up. (Enable it on the host with
		// `sysctl -w net.ipv4.ip_forward=1`, or run the container privileged.)
		if cur, rerr := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); rerr != nil ||
			len(cur) == 0 || cur[0] != '1' {
			return fmt.Errorf("enable ip_forward: %w (and it is not already on — "+
				"set net.ipv4.ip_forward=1 on the HOST, or run this container privileged)", err)
		}
	}
	cidr := ""
	if overlayNet != nil {
		cidr = overlayNet.String()
	}
	if cidr == "" {
		return fmt.Errorf("overlay subnet unknown")
	}
	dev := tunName
	if dev == "" {
		dev = "ovl0"
	}
	// Idempotent: delete-then-add so repeated starts don't stack rules.
	run := func(args ...string) {
		_ = exec.Command("iptables", args...).Run()
	}
	// MASQUERADE overlay-sourced traffic leaving via a non-overlay interface.
	run("-t", "nat", "-D", "POSTROUTING", "-s", cidr, "!", "-o", dev, "-j", "MASQUERADE")
	if out, err := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING",
		"-s", cidr, "!", "-o", dev, "-j", "MASQUERADE").CombinedOutput(); err != nil {
		return fmt.Errorf("iptables MASQUERADE: %v (%s)", err, out)
	}
	// Allow forwarding in both directions for the overlay subnet.
	run("-D", "FORWARD", "-s", cidr, "-j", "ACCEPT")
	run("-A", "FORWARD", "-s", cidr, "-j", "ACCEPT")
	run("-D", "FORWARD", "-d", cidr, "-j", "ACCEPT")
	run("-A", "FORWARD", "-d", cidr, "-j", "ACCEPT")
	return nil
}
