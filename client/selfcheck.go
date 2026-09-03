package main

// selfcheck.go periodically writes everything needed to diagnose a dead data
// path into the client's own log.
//
// WHY THIS EXISTS. "The peer list is green and nothing is reachable" is the
// hardest state this client gets into, and diagnosing it has meant asking an
// operator to run a dozen ad-hoc commands across several machines and paste the
// output back — which is slow, error-prone, and asks them to be the instrument.
// Every fact below is already in this process's memory; there was simply no way
// to see it. Nothing here is new capability, only visibility.
//
// It runs on a slow ticker and prints one compact block, so a log tail is a
// complete diagnosis rather than a starting point.

import (
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"time"
)

const selfCheckEvery = 60 * time.Second

// startSelfCheck logs a diagnostic block immediately and then on a ticker.
func startSelfCheck() {
	go func() {
		// One early block, before the mesh settles, then the steady cadence.
		time.Sleep(20 * time.Second)
		for {
			logSelfCheck()
			time.Sleep(selfCheckEvery)
		}
	}()
}

func logSelfCheck() {
	defer func() {
		// Diagnostics must never be the thing that kills the client.
		if r := recover(); r != nil {
			log.Printf("[selfcheck] recovered: %v", r)
		}
	}()

	var b strings.Builder
	fmt.Fprintf(&b, "\n[selfcheck] ===== overlay_ip=%s tun=%s port=%d public=%s\n",
		myOverlayIP(), tunName, myUDPPort, currentPublicEndpoint())

	// --- interfaces carrying an overlay-range address ------------------------
	//
	// A STALE interface still holding a previous overlay address is invisible
	// from inside the process and changes which source address the OS picks for
	// overlay traffic. If packets leave with an address this node no longer
	// answers to, every reply comes back addressed to nobody and is discarded —
	// which looks exactly like total packet loss in both directions.
	fmt.Fprintf(&b, "[selfcheck] interfaces:\n")
	if ifs, err := net.Interfaces(); err == nil {
		for _, ifc := range ifs {
			addrs, err := ifc.Addrs()
			if err != nil || len(addrs) == 0 {
				continue
			}
			var v4 []string
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
					v4 = append(v4, ipn.String())
				}
			}
			if len(v4) == 0 {
				continue
			}
			mark := ""
			if ifc.Name == tunName {
				mark = "  <== OUR TUN"
			} else {
				for _, s := range v4 {
					if inSameOverlaySubnet(s) {
						mark = "  <== STALE? carries an overlay-range address on a NON-overlay interface"
					}
				}
			}
			fmt.Fprintf(&b, "[selfcheck]   %-10s %s%s\n", ifc.Name, strings.Join(v4, ","), mark)
		}
	}

	// --- learned routes ------------------------------------------------------
	// Empty here while sessions are established means data has nowhere to go and
	// every packet is being blind-flooded.
	ents := ipLearning.Entries()
	sort.Slice(ents, func(i, j int) bool { return ents[i].IP < ents[j].IP })
	fmt.Fprintf(&b, "[selfcheck] learned routes (%d):\n", len(ents))
	for _, e := range ents {
		live := "dead"
		if GlobalSessions != nil {
			if s := GlobalSessions.GetByAddr(e.Addr); s != nil && s.Established() {
				live = "established"
			}
		}
		fmt.Fprintf(&b, "[selfcheck]   %-15s -> %-24s session=%s age=%s\n",
			e.IP, e.Addr, live, time.Since(e.Seen).Truncate(time.Second))
	}

	// --- sessions ------------------------------------------------------------
	if GlobalSessions != nil {
		addrs := GlobalSessions.EstablishedAddrs()
		fmt.Fprintf(&b, "[selfcheck] established sessions (%d):\n", len(addrs))
		for _, a := range addrs {
			s := GlobalSessions.GetByAddr(a)
			if s == nil {
				continue
			}
			fmt.Fprintf(&b, "[selfcheck]   %-24s peer_overlay_ip=%-15s fp=%s\n",
				a, peerOverlayIPByPub(s.peerStatic), peerKeyFingerprint(s.peerStatic[:]))
		}
	}

	// --- where undelivered traffic was actually addressed --------------------
	// One dominant destination that is not this node is the answer outright.
	if top := notForUsTop(5); len(top) > 0 {
		fmt.Fprintf(&b, "[selfcheck] frames arriving for OTHER overlay IPs (top 5):\n")
		for _, e := range top {
			fmt.Fprintf(&b, "[selfcheck]   dst=%v count=%v\n", e["dst"], e["count"])
		}
	}

	fmt.Fprintf(&b, "[selfcheck] counters: %v\n", dataStats())
	fmt.Fprintf(&b, "[selfcheck] verdict: %s", dataPathVerdict())
	log.Print(b.String())
}

// inSameOverlaySubnet reports whether cidr (an interface address such as
// "10.22.22.115/24") falls inside this node's overlay subnet.
func inSameOverlaySubnet(cidr string) bool {
	mine := myOverlayIP()
	if mine == "" {
		return false
	}
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil || ip.To4() == nil {
		return false
	}
	m := net.ParseIP(mine).To4()
	v := ip.To4()
	if m == nil || v == nil {
		return false
	}
	// Same /24 is the right granularity: overlay subnets here are /24 and the
	// interesting case is a leftover address one octet away from ours.
	return m[0] == v[0] && m[1] == v[1] && m[2] == v[2]
}
