//go:build windows

package main

import (
	"fmt"
	"log"
)

// setupExitNAT turns this Windows node into an internet exit for overlay
// clients: enable IPv4 forwarding on the interfaces and NAT overlay-sourced
// traffic with the built-in WinNAT engine (New-NetNat — the same machinery
// Windows itself uses for Mobile Hotspot and Hyper-V NAT switches).
// Requires elevation, which the client already has for Wintun.
func setupExitNAT() error {
	if overlayNet == nil {
		return fmt.Errorf("overlay subnet unknown")
	}
	cidr := overlayNet.String()
	if tunName == "" {
		return fmt.Errorf("no TUN interface yet")
	}

	// 1. IPv4 forwarding on the overlay adapter (live, no reboot — unlike the
	// IPEnableRouter registry switch)…
	if out, err := runCmd("netsh", "interface", "ipv4", "set", "interface",
		tunName, "forwarding=enable"); err != nil {
		return fmt.Errorf("enable forwarding on %q: %v (%s)", tunName, err, out)
	}
	// …and on every connected interface, so the default-route NIC forwards
	// too. Best-effort: the specific failure that matters (no NAT) is caught
	// below, and Set-NetIPInterface can whine about transient interfaces.
	_, _ = runCmd("powershell", "-NoProfile", "-Command",
		"Get-NetIPInterface -AddressFamily IPv4 | Where-Object {$_.ConnectionState -eq 'Connected'} | Set-NetIPInterface -Forwarding Enabled -ErrorAction SilentlyContinue")

	// 2. WinNAT for the overlay prefix. Idempotent: remove any previous APGO
	// NAT (by name, or a stale one claiming the same prefix) before creating
	// ours — New-NetNat errors on duplicates rather than replacing them.
	ps := fmt.Sprintf(
		"Get-NetNat | Where-Object {($_.Name -eq 'APGOExit') -or ($_.InternalIPInterfaceAddressPrefix -eq '%s')} | Remove-NetNat -Confirm:$false -ErrorAction SilentlyContinue; "+
			"New-NetNat -Name APGOExit -InternalIPInterfaceAddressPrefix '%s' | Out-Null", cidr, cidr)
	if out, err := runCmd("powershell", "-NoProfile", "-Command", ps); err != nil {
		return fmt.Errorf("New-NetNat %s: %v (%s) — note: WinNAT allows one NAT "+
			"per machine; Hyper-V/WSL NAT or Mobile Hotspot can conflict", cidr, err, out)
	}

	log.Printf("[exit] Windows NAT ready — WinNAT translating %s (forwarding on %q)", cidr, tunName)
	return nil
}
