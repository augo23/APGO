//go:build linux

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
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
	// Pick an iptables binary that actually works on THIS kernel. "iptables"
	// in the container image is the LEGACY (xtables) variant; on a modern
	// nftables-only host kernel every legacy call fails with "can't
	// initialize iptables table `nat'" — which silently disabled exit-node
	// mode on exactly the hosts most people run Kubernetes on. Probe the
	// candidates with a harmless read and use the first one that can even
	// SEE the nat table.
	var ipt string
	var probeErrs []string
	for _, cand := range []string{"iptables", "iptables-nft", "iptables-legacy"} {
		if out, err := exec.Command(cand, "-t", "nat", "-L", "POSTROUTING", "-n").CombinedOutput(); err == nil {
			ipt = cand
			break
		} else {
			probeErrs = append(probeErrs, fmt.Sprintf("%s: %v (%s)", cand, err, strings.TrimSpace(string(out))))
		}
	}
	if ipt == "" {
		return fmt.Errorf("no working iptables variant on this kernel — %s", strings.Join(probeErrs, "; "))
	}
	// Idempotent: delete-then-add so repeated starts don't stack rules.
	run := func(args ...string) {
		_ = exec.Command(ipt, args...).Run()
	}
	// MASQUERADE overlay-sourced traffic leaving via a non-overlay interface.
	run("-t", "nat", "-D", "POSTROUTING", "-s", cidr, "!", "-o", dev, "-j", "MASQUERADE")
	if out, err := exec.Command(ipt, "-t", "nat", "-A", "POSTROUTING",
		"-s", cidr, "!", "-o", dev, "-j", "MASQUERADE").CombinedOutput(); err != nil {
		return fmt.Errorf("%s MASQUERADE: %v (%s)", ipt, err, out)
	}
	// Allow forwarding in both directions for the overlay subnet.
	run("-D", "FORWARD", "-s", cidr, "-j", "ACCEPT")
	run("-A", "FORWARD", "-s", cidr, "-j", "ACCEPT")
	run("-D", "FORWARD", "-d", cidr, "-j", "ACCEPT")
	run("-A", "FORWARD", "-d", cidr, "-j", "ACCEPT")
	log.Printf("[exit] Linux NAT ready — %s masquerading %s (dev %s)", ipt, cidr, dev)
	return nil
}
