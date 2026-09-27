//go:build darwin

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
)

// setupPublicExitNAT routes the public-exit client pool into the utun, NATs it
// out of the default interface with pf, and — behind the userspace filter in
// pubexit_server.go — has pf drop pool traffic that is not bound for the
// internet or that is addressed to this Mac.
func setupPublicExitNAT(pool *net.IPNet) error {
	if tunName == "" {
		return fmt.Errorf("no TUN interface yet")
	}
	if out, err := runCmd("sysctl", "-w", "net.inet.ip.forwarding=1"); err != nil {
		return fmt.Errorf("enable net.inet.ip.forwarding: %v (%s)", err, out)
	}
	_, ifname, err := physicalDefaultRoute("inet")
	if err != nil {
		ifi, ierr := physicalDefaultInterface()
		if ierr != nil {
			return fmt.Errorf("find default-route interface: %v", err)
		}
		ifname = ifi.Name
	}
	cidr := pool.String()
	_, _ = runCmd("route", "-n", "delete", "-inet", "-net", cidr)
	if out, err := runCmd("route", "-n", "add", "-inet", "-net", cidr, "-interface", tunName); err != nil &&
		!strings.Contains(out, "File exists") {
		return fmt.Errorf("route %s via %s: %v (%s)", cidr, tunName, err, out)
	}
	if err := ensurePFMainAnchors(); err != nil {
		return err
	}
	if out, _ := runCmd("pfctl", "-s", "rules"); !strings.Contains(out, `anchor "com.apple/*"`) {
		return fmt.Errorf(`pf's main ruleset does not evaluate the com.apple filter anchors (expected: anchor "com.apple/*"), so the public-exit firewall rules could not apply`)
	}
	var private []string
	for _, n := range pxNonPublic {
		private = append(private, n.String())
	}
	if overlayNet != nil {
		private = append(private, overlayNet.String())
	}
	rules := fmt.Sprintf("nat on %[1]s inet from %[2]s to any -> (%[1]s)\n"+
		"block drop quick inet from %[2]s to { %[3]s }\n"+
		"block drop in quick inet from %[2]s to self\n",
		ifname, cidr, strings.Join(private, ", "))
	tmp, err := os.CreateTemp("", "apgo-pubexit-*.conf")
	if err != nil {
		return fmt.Errorf("write pf rules: %v", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(rules); err != nil {
		tmp.Close()
		return fmt.Errorf("write pf rules: %v", err)
	}
	tmp.Close()
	const anchor = "com.apple/251.ApgoPublicExit"
	if out, err := runCmd("pfctl", "-a", anchor, "-f", tmp.Name()); err != nil {
		return fmt.Errorf("pfctl load public-exit rules: %v (%s)", err, out)
	}
	if out, err := runCmd("pfctl", "-E"); err != nil &&
		!strings.Contains(out, "already enabled") && !strings.Contains(out, "Token") {
		if st, _ := runCmd("pfctl", "-s", "info"); !strings.Contains(st, "Status: Enabled") {
			return fmt.Errorf("pfctl -E: %v (%s)", err, out)
		}
	}
	if out, _ := runCmd("pfctl", "-a", anchor, "-s", "nat"); !strings.Contains(out, cidr) {
		return fmt.Errorf("pf NAT rule for public-exit clients did not take (anchor %s shows: %q)", anchor, out)
	}
	if out, _ := runCmd("pfctl", "-a", anchor, "-s", "rules"); !strings.Contains(out, "block") {
		return fmt.Errorf("pf filter rules for public-exit clients did not take (anchor %s shows: %q)", anchor, out)
	}
	log.Printf("[public-exit] macOS NAT ready — public-exit clients %s out %s via pf", cidr, ifname)
	return nil
}
