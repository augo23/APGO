//go:build windows

package main

// firewall_windows.go opens this client's UDP port in Windows Firewall.
//
// Windows is the only supported platform where a correctly configured node is
// still unreachable out of the box, and the failure is silent and total.
// The Windows Firewall's "allow?" popup only appears for INTERACTIVE desktop
// applications; the overlay client is launched elevated and hidden by the tray
// app, so it never gets a prompt — its inbound UDP is simply dropped, with no
// log line anywhere.
//
// What the operator sees is a node that starts cleanly, announces to trackers,
// finds peers, and then relays everything or connects to nothing, because no
// peer's hole-punch packet ever arrives. On Linux and macOS this does not
// happen (neither blocks inbound UDP by default), so the platform difference
// is invisible until someone runs Windows.
//
// The client is already running elevated (it needs Administrator for the
// Wintun adapter), so it is the right place to do this: the installer runs
// unelevated and cannot.

import (
	"fmt"
	"log"
	"os"
	"strings"
)

const firewallRuleName = "APGO Overlay (UDP)"

// ensureFirewallRules adds an inbound allow rule for the client's UDP port,
// replacing any rule left over from a previous run on a different port.
// Best-effort: a failure is logged with the manual command, never fatal — a
// node behind a relay still works, and refusing to start over a firewall rule
// would be worse than the problem.
func ensureFirewallRules(port int) {
	if port <= 0 {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		exe = ""
	}

	// Delete first: netsh has no "add or update", so re-adding after a port
	// change would otherwise leave a stale rule for the old port and
	// accumulate one rule per port the node has ever used.
	_, _ = runCmd("netsh", "advfirewall", "firewall", "delete", "rule",
		"name="+firewallRuleName)

	args := []string{"advfirewall", "firewall", "add", "rule",
		"name=" + firewallRuleName,
		"dir=in", "action=allow", "protocol=UDP",
		fmt.Sprintf("localport=%d", port),
		// All three profiles: a laptop moves between them, and a rule that
		// only covers "Private" stops working the moment Windows decides a
		// network is Public — which it does for most Wi-Fi by default.
		"profile=any",
		"description=Peer-to-peer overlay transport. Added by APGO.",
	}
	if exe != "" {
		args = append(args, "program="+exe)
	}
	if out, err := runCmd("netsh", args...); err != nil {
		log.Printf("[firewall] could not add the inbound rule for UDP %d: %v (%s)", port, err, strings.TrimSpace(out))
		log.Printf("[firewall] peers will not be able to reach this node directly (it will fall back to relays). " +
			"To fix it, run this in an Administrator PowerShell:")
		log.Printf(`[firewall]   netsh advfirewall firewall add rule name="%s" dir=in action=allow protocol=UDP localport=%d profile=any`,
			firewallRuleName, port)
		return
	}
	log.Printf("[firewall] inbound UDP %d allowed (rule %q)", port, firewallRuleName)
}
