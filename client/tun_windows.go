//go:build windows

package main

// Windows data-plane via Wintun (WireGuard's layer-3 adapter). Wintun delivers
// raw IP packets (unlike the legacy TAP driver, which is layer-2 Ethernet), so
// it matches this L3 overlay. It ships as a single wintun.dll placed next to
// the client executable; no driver install is required, but creating the
// adapter needs Administrator rights.
//
// The rest of the client speaks a single-packet io.ReadWriteCloser, so wintunRW
// adapts wireguard/tun's batched Read/Write API to that.
//
// NOTE: wireguard/tun's Device API has changed across versions; the Windows
// build pins a known-good version in windows/install.cmd. If it fails to
// compile, that pin is the thing to bump.

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

// tunName is the Wintun adapter name, remembered so an admin-assigned overlay IP
// can be applied live in-process (see reAddressTUN).
var tunName string

func createAndConfigureTUN(cfg *ClientConfig) error {
	if cfg.Tun.MTU == 0 {
		cfg.Tun.MTU = 1280
	}
	if cfg.Tun.AddressCIDR == "" {
		return fmt.Errorf("overlay address required on Windows (set one in Settings)")
	}
	ip, ipnet, err := net.ParseCIDR(cfg.Tun.AddressCIDR)
	if err != nil {
		return fmt.Errorf("parse addr %q: %w", cfg.Tun.AddressCIDR, err)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("overlay address must be IPv4, got %q", cfg.Tun.AddressCIDR)
	}

	// If the adapter name is taken (another client instance still running),
	// iterate upward: APGO → APGO1 → APGO2 … so a stale adapter never blocks us.
	var dev tun.Device
	var err error
	for n := 0; n < 8; n++ {
		name := "APGO"
		if n > 0 {
			name = fmt.Sprintf("APGO%d", n)
		}
		dev, err = tun.CreateTUN(name, cfg.Tun.MTU)
		if err == nil {
			if n > 0 {
				log.Printf("Wintun adapter APGO was taken — using %s instead", name)
			}
			break
		}
		s := strings.ToLower(err.Error())
		if !strings.Contains(s, "busy") && !strings.Contains(s, "exist") && !strings.Contains(s, "in use") {
			return fmt.Errorf("create Wintun adapter (wintun.dll present? running as Administrator?): %w", err)
		}
	}
	if err != nil {
		return fmt.Errorf("create Wintun adapter: no free APGO* adapter name: %w", err)
	}
	name, _ := dev.Name()
	tunName = name
	globalTunIF = newWintunRW(dev)
	log.Printf("TUN %s created (Windows Wintun)", name)

	// Wintun is a raw L3 adapter, so assign the address, mask and MTU with netsh.
	mask := net.IP(ipnet.Mask).To4()
	maskStr := fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
	if out, err := runCmd("netsh", "interface", "ip", "set", "address",
		fmt.Sprintf("name=%s", name), "static", ip4.String(), maskStr); err != nil {
		log.Printf("warning: netsh set address on %s: %v (%s)", name, err, out)
	}
	if out, err := runCmd("netsh", "interface", "ipv4", "set", "subinterface",
		name, fmt.Sprintf("mtu=%d", cfg.Tun.MTU), "store=persistent"); err != nil {
		log.Printf("warning: netsh set mtu on %s: %v (%s)", name, err, out)
	}
	// The static address in the overlay subnet installs the on-link /24 route
	// automatically; ipnet is parsed above for validation/logging.
	log.Printf("Assigned %s (net %s) to %s", cfg.Tun.AddressCIDR, ipnet.String(), name)
	return nil
}

// wintunRW adapts wireguard/tun's batched Device to a single-packet
// io.ReadWriteCloser. Reads are buffered: one batched Read may return several
// packets, which we hand out one at a time.
type wintunRW struct {
	dev   tun.Device
	bufs  [][]byte
	sizes []int
	queue [][]byte
}

func newWintunRW(dev tun.Device) *wintunRW {
	bs := dev.BatchSize()
	if bs < 1 {
		bs = 1
	}
	bufs := make([][]byte, bs)
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}
	return &wintunRW{dev: dev, bufs: bufs, sizes: make([]int, bs)}
}

func (w *wintunRW) Read(p []byte) (int, error) {
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

func (w *wintunRW) Write(p []byte) (int, error) {
	buf := make([]byte, len(p))
	copy(buf, p)
	if _, err := w.dev.Write([][]byte{buf}, 0); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *wintunRW) Close() error { return w.dev.Close() }

// reAddressTUN changes the Wintun adapter's IPv4 address live (no restart).
// netsh's static set replaces the existing address, so oldIP is unused.
func reAddressTUN(oldIP, newCIDR string) error {
	ip, ipnet, err := net.ParseCIDR(newCIDR)
	if err != nil {
		return err
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("overlay address must be IPv4, got %q", newCIDR)
	}
	mask := net.IP(ipnet.Mask).To4()
	maskStr := fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
	if out, err := runCmd("netsh", "interface", "ip", "set", "address",
		fmt.Sprintf("name=%s", tunName), "static", ip4.String(), maskStr); err != nil {
		return fmt.Errorf("netsh set address: %v (%s)", err, out)
	}
	return nil
}

func runCmd(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
