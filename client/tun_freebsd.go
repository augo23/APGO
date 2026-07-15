//go:build freebsd

package main

// FreeBSD data plane — used by the pfSense package (pfSense is FreeBSD).
//
// The TUN device comes from wireguard-go's tun package (the same dependency
// the Windows build uses for Wintun), which handles FreeBSD's tun cloning and
// the AF protocol header internally and hands us raw L3 packets. The rest of
// the client speaks a single-packet io.ReadWriteCloser, so fbsdTunRW adapts
// the batched Device API to that — mirroring tun_windows.go.
//
// Addressing/routes use ifconfig/route (FreeBSD tun is point-to-point: the
// address is assigned local→local with the overlay netmask, then a subnet
// route is pinned to the interface).

import (
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
	"strings"

	"golang.zx2c4.com/wireguard/tun"
)

var globalTunIF io.ReadWriteCloser

// tunName is the tun interface name, remembered so an admin-assigned overlay
// IP can be applied live in-process (see reAddressTUN) and so the operator
// can reference it in pf rules.
var tunName string

// tunNetmask remembers the overlay netmask (dotted quad) for ifconfig calls.
var tunNetmask string

func createAndConfigureTUN(cfg *ClientConfig) error {
	if cfg.Tun.Name == "" {
		cfg.Tun.Name = "ovl0"
	}
	if cfg.Tun.MTU == 0 {
		cfg.Tun.MTU = 1280
	}
	if cfg.Tun.AddressCIDR == "" {
		return fmt.Errorf("overlay address required (tun.address_cidr, or leave overlay_cidr set so one is derived)")
	}
	ip, ipnet, err := net.ParseCIDR(cfg.Tun.AddressCIDR)
	if err != nil {
		return fmt.Errorf("parse addr %q: %w", cfg.Tun.AddressCIDR, err)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("overlay address must be IPv4, got %q", cfg.Tun.AddressCIDR)
	}

	// If the requested name is taken (another client instance still running),
	// iterate upward: ovl0 → ovl1 → ovl2 … so a stale interface never blocks us.
	prefix, start := splitTunNameFBSD(cfg.Tun.Name)
	var dev tun.Device
	for n := 0; n < 8; n++ {
		name := fmt.Sprintf("%s%d", prefix, start+n)
		dev, err = tun.CreateTUN(name, cfg.Tun.MTU)
		if err == nil {
			if n > 0 {
				log.Printf("TUN %s was taken — using %s instead", cfg.Tun.Name, name)
			}
			break
		}
		s := strings.ToLower(err.Error())
		if !strings.Contains(s, "busy") && !strings.Contains(s, "exist") && !strings.Contains(s, "in use") {
			return fmt.Errorf("create TUN (running as root?): %w", err)
		}
	}
	if err != nil {
		return fmt.Errorf("create TUN: no free %s* name: %w", prefix, err)
	}
	name, _ := dev.Name()
	tunName = name
	globalTunIF = newFbsdTunRW(dev)
	log.Printf("TUN %s created (FreeBSD)", name)

	mask := net.IP(ipnet.Mask).To4()
	tunNetmask = fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])

	// FreeBSD tun is point-to-point: assign local→local with the overlay
	// netmask, then pin the subnet route to the interface.
	if out, err := runCmd("ifconfig", name, "inet",
		ip4.String(), ip4.String(), "netmask", tunNetmask,
		"mtu", fmt.Sprintf("%d", cfg.Tun.MTU), "up"); err != nil {
		return fmt.Errorf("ifconfig %s: %v (%s)", name, err, out)
	}
	// Replace any stale route quietly, then add ours.
	_, _ = runCmd("route", "-q", "delete", "-net", ipnet.String())
	if out, err := runCmd("route", "-q", "add", "-net", ipnet.String(), "-interface", name); err != nil {
		log.Printf("warning: route add %s via %s: %v (%s)", ipnet.String(), name, err, out)
	}
	log.Printf("Assigned %s (net %s) to %s", cfg.Tun.AddressCIDR, ipnet.String(), name)
	return nil
}

// splitTunNameFBSD splits "ovl0" into ("ovl", 0) for the create loop.
func splitTunNameFBSD(name string) (prefix string, start int) {
	i := len(name)
	for i > 0 && name[i-1] >= '0' && name[i-1] <= '9' {
		i--
	}
	prefix, start = name[:i], 0
	fmt.Sscanf(name[i:], "%d", &start)
	if prefix == "" {
		prefix = "ovl"
	}
	return prefix, start
}

// fbsdTunRW adapts wireguard/tun's batched Device to a single-packet
// io.ReadWriteCloser (same adapter shape as Windows' wintunRW).
type fbsdTunRW struct {
	dev   tun.Device
	bufs  [][]byte
	sizes []int
	queue [][]byte
}

func newFbsdTunRW(dev tun.Device) *fbsdTunRW {
	bs := dev.BatchSize()
	if bs < 1 {
		bs = 1
	}
	bufs := make([][]byte, bs)
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}
	return &fbsdTunRW{dev: dev, bufs: bufs, sizes: make([]int, bs)}
}

func (w *fbsdTunRW) Read(p []byte) (int, error) {
	for len(w.queue) == 0 {
		n, err := w.dev.Read(w.bufs, w.sizes, 0)
		if err != nil {
			return 0, err
		}
		for i := 0; i < n; i++ {
			pkt := make([]byte, w.sizes[i])
			copy(pkt, w.bufs[i][:w.sizes[i]])
			w.queue = append(w.queue, pkt)
		}
	}
	pkt := w.queue[0]
	w.queue = w.queue[1:]
	return copy(p, pkt), nil
}

func (w *fbsdTunRW) Write(p []byte) (int, error) {
	buf := make([]byte, len(p))
	copy(buf, p)
	if _, err := w.dev.Write([][]byte{buf}, 0); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *fbsdTunRW) Close() error { return w.dev.Close() }

// reAddressTUN changes the tun interface's IPv4 address live (no restart).
func reAddressTUN(oldIP, newCIDR string) error {
	if tunName == "" {
		return fmt.Errorf("no TUN interface")
	}
	ip, ipnet, err := net.ParseCIDR(newCIDR)
	if err != nil {
		return err
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("overlay address must be IPv4, got %q", newCIDR)
	}
	if oldIP != "" {
		_, _ = runCmd("ifconfig", tunName, "inet", oldIP, "delete")
	}
	mask := net.IP(ipnet.Mask).To4()
	maskStr := fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
	if out, err := runCmd("ifconfig", tunName, "inet",
		ip4.String(), ip4.String(), "netmask", maskStr, "up"); err != nil {
		return fmt.Errorf("ifconfig %s: %v (%s)", tunName, err, out)
	}
	_, _ = runCmd("route", "-q", "delete", "-net", ipnet.String())
	_, _ = runCmd("route", "-q", "add", "-net", ipnet.String(), "-interface", tunName)
	log.Printf("[provision] overlay address changed to %s on %s", newCIDR, tunName)
	return nil
}

func runCmd(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
