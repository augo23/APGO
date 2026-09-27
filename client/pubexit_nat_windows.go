//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
)

// setupPublicExitNAT gives the Wintun adapter an address in the client pool
// (so Windows treats the pool as on-link and routes replies into the tunnel)
// and NATs the pool with WinNAT. The userspace filter in pubexit_server.go is
// what restricts clients to the internet.
func setupPublicExitNAT(pool *net.IPNet) error {
	if tunName == "" {
		return fmt.Errorf("no TUN interface yet")
	}
	ones, _ := pool.Mask.Size()
	gw := make(net.IP, 4)
	binary.BigEndian.PutUint32(gw, binary.BigEndian.Uint32(pool.IP.To4())+1)
	cidr := pool.String()
	if out, err := runCmd("netsh", "interface", "ipv4", "set", "interface", tunName, "forwarding=enable"); err != nil {
		return fmt.Errorf("enable forwarding on %q: %v (%s)", tunName, err, out)
	}
	ps := fmt.Sprintf(
		"if (-not (Get-NetIPAddress -InterfaceAlias '%[1]s' -IPAddress '%[2]s' -ErrorAction SilentlyContinue)) { "+
			"New-NetIPAddress -InterfaceAlias '%[1]s' -IPAddress '%[2]s' -PrefixLength %[3]d -SkipAsSource $true | Out-Null }; "+
			"Get-NetNat | Where-Object {($_.Name -eq 'APGOPublicExit') -or ($_.InternalIPInterfaceAddressPrefix -eq '%[4]s')} | Remove-NetNat -Confirm:$false -ErrorAction SilentlyContinue; "+
			"New-NetNat -Name APGOPublicExit -InternalIPInterfaceAddressPrefix '%[4]s' | Out-Null",
		tunName, gw.String(), ones, cidr)
	if out, err := runCmd("powershell", "-NoProfile", "-Command", ps); err != nil {
		return fmt.Errorf("WinNAT for %s: %v (%s) — some Windows versions allow only one NAT; "+
			"turning off the internal exit node (or Hyper-V/WSL NAT) may be required", cidr, err, out)
	}
	log.Printf("[public-exit] Windows NAT ready — WinNAT translating public-exit clients %s", cidr)
	return nil
}
