//go:build linux

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
)

// setupPublicExitNAT routes the public-exit client pool into the overlay TUN,
// masquerades it to the internet, and — as a second line of defence behind the
// userspace filter in pubexit_server.go — tells the kernel to drop pool traffic
// to anything but the internet and to never deliver it to this host.
func setupPublicExitNAT(pool *net.IPNet) error {
	if tunName == "" {
		return fmt.Errorf("no TUN interface yet")
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644); err != nil {
		if cur, rerr := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); rerr != nil || len(cur) == 0 || cur[0] != '1' {
			return fmt.Errorf("enable ip_forward: %w (set net.ipv4.ip_forward=1 on the host, or run privileged)", err)
		}
	}
	cidr := pool.String()
	dev := tunName
	if out, err := exec.Command("ip", "route", "replace", cidr, "dev", dev).CombinedOutput(); err != nil {
		return fmt.Errorf("route %s via %s: %v (%s)", cidr, dev, err, strings.TrimSpace(string(out)))
	}
	ipt := ""
	for _, cand := range []string{"iptables", "iptables-nft", "iptables-legacy"} {
		if err := exec.Command(cand, "-t", "nat", "-L", "POSTROUTING", "-n").Run(); err == nil {
			ipt = cand
			break
		}
	}
	if ipt == "" {
		return fmt.Errorf("no working iptables on this host")
	}
	run := func(args ...string) error {
		out, err := exec.Command(ipt, args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s %s: %v (%s)", ipt, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	const chain = "APGO_PUBEXIT"
	_ = run("-N", chain) // exists already on a restart
	if err := run("-F", chain); err != nil {
		return err
	}
	drops := []string{}
	for _, n := range pxNonPublic {
		drops = append(drops, n.String())
	}
	if overlayNet != nil {
		drops = append(drops, overlayNet.String())
	}
	for _, d := range drops {
		if err := run("-A", chain, "-d", d, "-j", "DROP"); err != nil {
			return err
		}
	}
	if err := run("-A", chain, "-j", "ACCEPT"); err != nil {
		return err
	}
	// Forward: pool -> chain (internet only); replies back to the pool.
	_ = run("-D", "FORWARD", "-s", cidr, "-j", chain)
	if err := run("-I", "FORWARD", "1", "-s", cidr, "-j", chain); err != nil {
		return err
	}
	_ = run("-D", "FORWARD", "-d", cidr, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	if err := run("-I", "FORWARD", "1", "-d", cidr, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
		// No conntrack match in this kernel/container: only then fall back
		// to accepting replies by address.
		_ = run("-D", "FORWARD", "-d", cidr, "-j", "ACCEPT")
		if err := run("-I", "FORWARD", "1", "-d", cidr, "-j", "ACCEPT"); err != nil {
			return err
		}
	}
	// Never deliver pool traffic to this host.
	_ = run("-D", "INPUT", "-s", cidr, "-j", "DROP")
	if err := run("-I", "INPUT", "1", "-s", cidr, "-j", "DROP"); err != nil {
		return err
	}
	_ = run("-t", "nat", "-D", "POSTROUTING", "-s", cidr, "!", "-o", dev, "-j", "MASQUERADE")
	if err := run("-t", "nat", "-A", "POSTROUTING", "-s", cidr, "!", "-o", dev, "-j", "MASQUERADE"); err != nil {
		return err
	}
	log.Printf("[public-exit] Linux NAT ready — %s masquerading public-exit clients %s (via %s)", ipt, cidr, dev)
	return nil
}
