//go:build linux

package main

import (
	"fmt"
	"log"
	"strings"

	water "github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

var globalTunIF *water.Interface

// tunName is the overlay interface name, remembered so an admin-assigned overlay
// IP can be applied live in-process (see reAddressTUN).
var tunName string

// tunNameTaken reports whether a TUN create error means the interface name is
// already owned by another process (e.g. an older client still running on this
// host), as opposed to a real failure like missing privileges.
func tunNameTaken(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "busy") || strings.Contains(s, "exists")
}

// splitTunName splits "ovl0" into ("ovl", 0) so the create loop can iterate
// ovl0 → ovl1 → ovl2 … A name with no trailing number starts at 0.
func splitTunName(name string) (prefix string, start int) {
	i := len(name)
	for i > 0 && name[i-1] >= '0' && name[i-1] <= '9' {
		i--
	}
	prefix, start = name[:i], 0
	fmt.Sscanf(name[i:], "%d", &start)
	return prefix, start
}

func createAndConfigureTUN(cfg *ClientConfig) error {
	if cfg.Tun.Name == "" {
		cfg.Tun.Name = "ovl0"
	}
	if cfg.Tun.MTU == 0 {
		cfg.Tun.MTU = 1420
	}

	// If the requested name is taken (another overlay client — or anything
	// else — owns it), iterate upward: ovl0 → ovl1 → ovl2 … so multiple
	// clients can coexist on one host and a stale interface never blocks us.
	prefix, start := splitTunName(cfg.Tun.Name)
	var ifce *water.Interface
	var err error
	for n := start; n < start+16; n++ {
		name := fmt.Sprintf("%s%d", prefix, n)
		ifce, err = water.New(water.Config{DeviceType: water.TUN, PlatformSpecificParams: water.PlatformSpecificParams{Name: name}})
		if err == nil {
			if name != cfg.Tun.Name {
				log.Printf("TUN %s was taken — using %s instead", cfg.Tun.Name, name)
			}
			cfg.Tun.Name = name
			break
		}
		if !tunNameTaken(err) {
			return fmt.Errorf("create TUN: %w", err)
		}
		log.Printf("TUN %s is in use, trying %s%d…", name, prefix, n+1)
	}
	if err != nil {
		return fmt.Errorf("create TUN: no free %s* interface after 16 attempts: %w", prefix, err)
	}
	tunName = cfg.Tun.Name
	log.Printf("TUN %s created", cfg.Tun.Name)
	globalTunIF = ifce

	link, err := netlink.LinkByName(cfg.Tun.Name)
	if err != nil {
		return fmt.Errorf("find link: %w", err)
	}
	if err := netlink.LinkSetMTU(link, cfg.Tun.MTU); err != nil {
		return fmt.Errorf("set MTU: %w", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("link up: %w", err)
	}

	if cfg.Tun.AddressCIDR != "" {
		addr, err := netlink.ParseAddr(cfg.Tun.AddressCIDR)
		if err != nil {
			return fmt.Errorf("parse addr: %w", err)
		}
		if err := netlink.AddrAdd(link, addr); err != nil {
			if err.Error() != "file exists" {
				return fmt.Errorf("addr add: %w", err)
			}
		}
		log.Printf("Assigned %s to %s", cfg.Tun.AddressCIDR, cfg.Tun.Name)
	}
	return nil
}

// reAddressTUN changes the overlay interface's IPv4 address live (no restart).
// oldIP is informational on Linux; all existing v4 addresses are replaced.
func reAddressTUN(oldIP, newCIDR string) error {
	link, err := netlink.LinkByName(tunName)
	if err != nil {
		return fmt.Errorf("find link: %w", err)
	}
	naddr, err := netlink.ParseAddr(newCIDR)
	if err != nil {
		return fmt.Errorf("parse addr: %w", err)
	}
	if addrs, err := netlink.AddrList(link, 2 /* FAMILY_V4 */); err == nil {
		for i := range addrs {
			_ = netlink.AddrDel(link, &addrs[i])
		}
	}
	if err := netlink.AddrAdd(link, naddr); err != nil && err.Error() != "file exists" {
		return fmt.Errorf("addr add: %w", err)
	}
	return nil
}
