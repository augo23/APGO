//go:build freebsd

package main

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
)

// setupPublicExitNAT on FreeBSD (pfSense). pfSense owns pf and rewrites the
// ruleset on every filter reload, so this process cannot install the NAT and
// the kernel-level block rules itself the way it does on Linux and macOS. The
// operator adds them once in the pfSense GUI (pfsense/README.md) and confirms
// that with public_exit_manual_nat: true. Until then the service refuses to
// start rather than run without the second layer.
//
// What this does automatically: checks IP forwarding and routes the client
// pool into the overlay tun, so replies from the internet reach the service.
// The userspace destination filter in pubexit_server.go applies either way.
func setupPublicExitNAT(pool *net.IPNet) error {
	if !pxManualNAT.Load() {
		return fmt.Errorf("on pfSense/FreeBSD the NAT and firewall rules for the public exit must be added by hand " +
			"(Outbound NAT for " + pool.String() + ", and block rules from it to private networks and to this firewall — " +
			"see pfsense/README.md), then set public_exit_manual_nat: true")
	}
	if tunName == "" {
		return fmt.Errorf("no TUN interface yet")
	}
	out, err := exec.Command("sysctl", "-n", "net.inet.ip.forwarding").CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "1" {
		return fmt.Errorf("IP forwarding is off (sysctl net.inet.ip.forwarding=%s)", strings.TrimSpace(string(out)))
	}
	cidr := pool.String()
	_ = exec.Command("route", "-q", "-n", "delete", "-inet", "-net", cidr).Run()
	if o, err := exec.Command("route", "-q", "-n", "add", "-inet", "-net", cidr, "-interface", tunName).CombinedOutput(); err != nil &&
		!strings.Contains(string(o), "File exists") {
		return fmt.Errorf("route %s via %s: %v (%s)", cidr, tunName, err, strings.TrimSpace(string(o)))
	}
	log.Printf("[public-exit] FreeBSD: %s routed via %s; NAT and firewall rules are the operator's (public_exit_manual_nat)", cidr, tunName)
	return nil
}
