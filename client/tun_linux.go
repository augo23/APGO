//go:build linux

package main

import (
	"fmt"
	"log"

	water "github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

var globalTunIF *water.Interface

func createAndConfigureTUN(cfg *ClientConfig) error {
	if cfg.Tun.Name == "" {
		cfg.Tun.Name = "ovl0"
	}
	if cfg.Tun.MTU == 0 {
		cfg.Tun.MTU = 1420
	}

	ifce, err := water.New(water.Config{DeviceType: water.TUN, PlatformSpecificParams: water.PlatformSpecificParams{Name: cfg.Tun.Name}})
	if err != nil {
		return fmt.Errorf("create TUN: %w", err)
	}
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
