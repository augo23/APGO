package main

// refreshroutes.go — "Refresh routes", requested remotely from the admin panel
// (a RefreshRoutes timestamp in a signed node-config record, nodeconfig.go).
//
// A node's path choices are made of state that only ever accumulates: per-peer
// relay verdicts (relaypolicy.go), retry back-offs (sessions.go) and the NAT
// classification. After the network underneath changes — a router reboot, a
// new client build on a peer, a NAT that briefly misreported itself — that
// state can keep a perfectly reachable peer on a relay. Refreshing throws the
// verdicts away and rebuilds them from fresh evidence, WITHOUT dropping any
// established session: live traffic keeps flowing on the current path while
// the direct one is re-tried, and moves over the moment a punch lands.

import (
	"log"
	"sync"
	"time"
)

// refreshMaxAge: a request older than this is recorded but not acted on. It
// covers the case priming cannot — a node that rebooted, had no stored value,
// and then hears an old request re-gossiped by a peer.
const refreshMaxAge = 10 * time.Minute

var (
	// natReprobe wakes the NAT probe loop (startNATProbing) early.
	natReprobe = make(chan struct{}, 1)

	refreshMu        sync.Mutex
	refreshApplied   int64 // last RefreshRoutes value acted on
	refreshPrimed    bool  // first look only records the value
)

// maybeRefreshRoutes acts on a RefreshRoutes request once. The first record
// seen after start only PRIMES the value: a stored request from yesterday must
// not fire again on every reboot.
func maybeRefreshRoutes(c SignedNodeConfig) {
	if c.RefreshRoutes == nil {
		refreshMu.Lock()
		refreshPrimed = true
		refreshMu.Unlock()
		return
	}
	v := *c.RefreshRoutes
	refreshMu.Lock()
	if !refreshPrimed {
		refreshPrimed = true
		refreshApplied = v
		refreshMu.Unlock()
		return
	}
	if v <= refreshApplied {
		refreshMu.Unlock()
		return
	}
	refreshApplied = v
	refreshMu.Unlock()
	if age := time.Since(time.Unix(v, 0)); age > refreshMaxAge {
		log.Printf("[routes] ignoring refresh request from %s ago (older than %s)", age.Round(time.Second), refreshMaxAge)
		return
	}
	refreshRoutes("admin request")
}

func refreshRoutes(source string) {
	relayPolMu.Lock()
	n := len(relayPol)
	relayPol = map[string]*relayPeerPolicy{}
	relayPolMu.Unlock()

	if GlobalSessions != nil {
		GlobalSessions.ResetBackoff()
	}
	select {
	case natReprobe <- struct{}{}:
	default:
	}

	peers := knownPeerList()
	for _, p := range peers {
		go connectToPeer(p, gKP, gPSK)
	}
	log.Printf("[routes] refresh (%s): cleared %d relay verdict(s) and all back-offs, re-probing NAT, re-dialing %d known peer(s); established sessions kept",
		source, n, len(peers))
}

// ipv6SnapshotFor reports the IPv6 setting for the admin panel.
func ipv6SnapshotFor(pubB64 string, rec *bool) any {
	if rec != nil {
		return *rec
	}
	if pubB64 == selfPubB64() {
		return ipv6Enabled
	}
	return nil
}
