package main

// relaypolicy.go — deciding WHEN a direct path is impossible, instead of
// discovering it by failing for an hour.
//
// THE FAILURE THIS EXISTS TO END
//
// A phone on a cellular carrier and a desktop behind a home router is the one
// NAT pairing hole punching cannot solve, and the client used to attack it
// forever anyway. From a real log, a laptop trying to reach a phone:
//
//	09:37:03  handshake to 107.122.246.1:28929 failed: no handshake reply
//	09:37:30  handshake to 107.122.246.1:50088 failed: no handshake reply
//	10:08:13  handshake to 107.122.246.1:10744 failed: no handshake reply
//	…
//	13:38:24  handshake to 107.122.246.1:26912 established
//
// Four hours, thirteen different external ports, one accidental success. The
// carrier NAT is SYMMETRIC: it allocates a fresh external port per
// destination, so the port a peer learns from STUN (the mapping toward the
// STUN server) is never the port that would reach it from here. The home
// router is PORT-RESTRICTED: it drops inbound datagrams from an address it
// has not sent to first. Neither side can open the other's pinhole, because
// neither can address the other's current mapping. No amount of retrying
// changes that — the pairing is unsolvable by construction, and the only
// path that can ever carry traffic is a relay.
//
// Two things were missing. The client could not TELL this pairing apart from
// an ordinary slow punch, and on mobile it had no relay to escalate to
// (see ios/core/relayclient.go). This file is the first half.
//
// HOW THE PAIRING IS RECOGNISED
//
// probeNAT (overlay.go) already classifies our own NAT by asking several STUN
// servers on one socket and comparing the external ports they report. That
// answer was used only for port prediction and a log line; it was never told
// to the peer, so each side knew half of a fact that is only useful whole.
//
// So the class now rides along in the connect candidate exchange as a
// "nat=" token (natTokenFor / parseNATClass). The wire format is a
// comma-separated candidate list, and a token is not a host:port — every
// existing build runs candidates through isPunchableAddr, whose SplitHostPort
// rejects it, so old peers skip it silently. The exchange is therefore
// backward compatible in both directions with no version negotiation: an old
// peer simply reports natUnknown and gets the previous behaviour.
//
// WHAT IS DONE WITH IT
//
// directPunchViable answers "could a direct path exist between these two NAT
// classes". Only one pairing is refused outright — symmetric on one side,
// symmetric-or-restricted on the other, which is the case above. Everything
// else keeps punching exactly as before, because everything else works: a
// symmetric peer CAN reach a port-stable one that has an open or forwarded
// port, and two port-stable peers punch in a single round trip.
//
// Being wrong in the conservative direction costs a relayed session where a
// direct one was possible — recoverable, because relayUpgradeProbe keeps
// trying direct in the background and the session moves back the moment a
// punch lands. Being wrong the other way costs what the log above shows.
//
// THE SECOND TRIGGER: TIME
//
// NAT classification needs two STUN servers to answer, and in the field one
// frequently does not ("NAT type unknown: only 1 STUN server(s) answered").
// A classification-only rule would therefore go dark exactly when the network
// is degraded enough to need it most. So elapsed time is an independent
// trigger: once a peer has been punched at for relayEscalateAfter with
// nothing established, it is treated as relay-preferred regardless of what
// either side believes about its NAT. The timer catches everything the
// classifier misses — a CGNAT that looks port-stable to STUN, a firewall
// dropping UDP to new destinations, a peer whose battery saver froze its
// radio — without needing to name any of them.

import (
	"log"
	"strings"
	"sync"
	"time"
)

// NAT classes carried in the candidate exchange. Untyped constants, not
// byte/int types: gomobile's gobind rejects typed scalar constants in the
// mobile cores that share this file's design, and keeping the two spellings
// identical is what makes the desktop and mobile logic diffable.
const (
	natUnknown    = "unknown"
	natStable     = "stable" // endpoint-independent mapping (full-cone, port-restricted)
	natSymmetric  = "sym"    // fresh external port per destination
	natTokenPfx   = "nat="
	natTokenMaxLn = 16 // bound what we parse out of a peer's candidate string
)

const (
	// relayEscalateAfter is how long a peer may stay unestablished while we
	// punch before it is treated as relay-preferred.
	//
	// The value is a judgement about impatience, not about the network. A
	// successful punch between two ordinary home routers completes in one or
	// two round trips — under a second. Anything still failing after fifteen
	// seconds has already had ten-plus attempts across the retry ladder and
	// is not about to succeed on the eleventh. Fifteen seconds is also about
	// the longest a person will wait staring at an app before deciding it is
	// broken, which is the number that actually matters here.
	relayEscalateAfter = 15 * time.Second

	// relayUpgradeProbeEvery is how often a relayed peer is re-punched to see
	// whether a direct path has appeared (the phone joined Wi-Fi, the carrier
	// moved it off CGNAT, the router rebooted into a friendlier mapping).
	//
	// Deliberately slow. A relayed session is already carrying traffic, so
	// this is an optimisation, not a repair, and each probe is a real Noise
	// handshake — an X25519 keygen and DH — plus a radio wake on a phone.
	// Once a minute converts "stuck on relay until restart" into "direct
	// within a minute of it becoming possible" for a cost too small to see.
	relayUpgradeProbeEvery = 60 * time.Second

	// relayPolicyForget drops bookkeeping for peers we have stopped hearing
	// from, so this never becomes an unbounded map keyed by peer churn.
	relayPolicyForget = 30 * time.Minute
)

// natTokenFor renders our own NAT class for the candidate list. Returns ""
// when we genuinely do not know, so an unclassified node adds nothing to the
// wire rather than asserting "unknown" as though it were information.
func natTokenFor(m natMapping) string {
	// samples < 2 is UNKNOWN, not port-stable: with a single STUN answer
	// "all reported ports agree" is vacuously true (see natMapping.samples).
	if m.ip == "" || m.samples < 2 {
		return ""
	}
	if m.symmetric {
		return natTokenPfx + natSymmetric
	}
	return natTokenPfx + natStable
}

// parseNATClass extracts a peer's advertised NAT class from its candidate
// list. Unknown, absent or malformed all yield natUnknown — an old peer that
// never sends the token is indistinguishable from one that cannot classify
// itself, and both should keep the previous punching behaviour.
func parseNATClass(candidateList string) string {
	for _, c := range strings.Split(candidateList, ",") {
		c = strings.TrimSpace(c)
		if len(c) > natTokenMaxLn || !strings.HasPrefix(c, natTokenPfx) {
			continue
		}
		switch strings.TrimPrefix(c, natTokenPfx) {
		case natSymmetric:
			return natSymmetric
		case natStable:
			return natStable
		}
	}
	return natUnknown
}

// directPunchViable reports whether a direct path could exist between our NAT
// class and the peer's.
//
// The refused case is narrow on purpose: a symmetric NAT on one side and a
// symmetric or port-restricted NAT on the other. Neither end can address the
// other's current mapping, so every punch is a guess at a port that has
// already moved.
//
// We treat our own natStable as "restricted" rather than "open", because that
// is the conservative reading and the common one: a home router preserves the
// external port (so STUN calls it stable) while still dropping inbound from
// addresses it has not sent to. A node that really is open — a forwarded
// port, a DMZ host, a Kubernetes hostPort — advertises that endpoint
// explicitly via advertise_port, and myConnectCandidates ranks it ahead of
// everything STUN-derived, so the peer reaches it without needing punching at
// all and never consults this function.
func directPunchViable(mine, theirs string) bool {
	if mine == natUnknown || theirs == natUnknown {
		// Not enough information to rule anything out. Punch, and let the
		// escalation timer be the backstop.
		return true
	}
	if mine == natSymmetric && theirs == natSymmetric {
		return false
	}
	// Symmetric on one side, port-restricted on the other: the restricted
	// side cannot open a pinhole toward a port that changes per destination.
	if mine == natSymmetric && theirs == natStable {
		return false
	}
	if mine == natStable && theirs == natSymmetric {
		return false
	}
	return true
}

// ---------------------------------------------------------------- per-peer

// relayPeerPolicy is what we have learned about reaching ONE peer.
type relayPeerPolicy struct {
	firstPunch time.Time // when we started trying to punch this peer
	lastSeen   time.Time // last time anything referenced this peer
	lastProbe  time.Time // last background direct-path probe while relayed
	natClass   string
	relayFirst bool   // classification says direct cannot work
	escalated  bool   // timer expired without an established session
	reason     string // for the log line, emitted once
}

var (
	relayPolMu sync.Mutex
	relayPol   = map[string]*relayPeerPolicy{}
)

// relayPolicyFor returns (creating if needed) the policy record for a peer,
// keyed by its overlay IP.
func relayPolicyFor(overlayIP string) *relayPeerPolicy {
	now := time.Now()
	p := relayPol[overlayIP]
	if p == nil {
		p = &relayPeerPolicy{firstPunch: now, natClass: natUnknown}
		relayPol[overlayIP] = p
	}
	p.lastSeen = now
	// Opportunistic sweep: bounded work, no separate goroutine or ticker.
	for k, v := range relayPol {
		if now.Sub(v.lastSeen) > relayPolicyForget {
			delete(relayPol, k)
		}
	}
	return p
}

// noteConnectCandidates records what a peer's candidate list tells us about
// its NAT, and returns whether we should bother punching it directly.
//
// Called from the connect-signalling handler, which is the only place a
// peer's candidate list (and therefore its NAT token) arrives.
func noteConnectCandidates(overlayIP, candidateList string) bool {
	theirs := parseNATClass(candidateList)
	mine := ourNATClass()

	relayPolMu.Lock()
	defer relayPolMu.Unlock()
	p := relayPolicyFor(overlayIP)
	p.natClass = theirs

	if !directPunchViable(mine, theirs) && !p.relayFirst {
		p.relayFirst = true
		p.reason = "nat pairing " + mine + "/" + theirs + " cannot be punched"
		log.Printf("[relay-policy] %s: %s — going relay-first (direct probes continue in the background)",
			overlayIP, p.reason)
	}
	return !p.relayFirst
}

// ourNATClass is our own classification, in the same vocabulary.
func ourNATClass() string {
	natMu.Lock()
	m := natInfo
	natMu.Unlock()
	if m.ip == "" || m.samples < 2 {
		return natUnknown
	}
	if m.symmetric {
		return natSymmetric
	}
	return natStable
}

// relayPreferred reports whether traffic for this peer should go over a relay
// rather than waiting on a direct path. True once either trigger has fired:
// the NAT pairing is known-unpunchable, or we have been punching for
// relayEscalateAfter with nothing to show.
//
// established tells us whether a direct session exists right now; when one
// does, the timer is reset, because a peer that connects, roams and
// reconnects should get a fresh budget rather than inheriting a stale verdict
// from an hour ago.
func relayPreferred(overlayIP string, established bool) bool {
	relayPolMu.Lock()
	defer relayPolMu.Unlock()
	p := relayPolicyFor(overlayIP)

	if established {
		p.firstPunch = time.Now()
		if p.escalated {
			p.escalated = false
			log.Printf("[relay-policy] %s: direct session established — back off relay", overlayIP)
		}
		return false
	}
	if p.relayFirst {
		return true
	}
	if !p.escalated && time.Since(p.firstPunch) >= relayEscalateAfter {
		p.escalated = true
		log.Printf("[relay-policy] %s: no direct session after %s of punching — preferring relay",
			overlayIP, relayEscalateAfter)
	}
	return p.escalated
}

// shouldProbeDirect rate-limits the background direct-path retry for a peer
// we are currently reaching over a relay. Returns true at most once per
// relayUpgradeProbeEvery.
//
// This is what keeps relay-first from being a one-way door: a phone that
// walks into Wi-Fi, or a carrier that moves a subscriber off CGNAT, becomes
// directly reachable within a minute instead of at the next app restart.
func shouldProbeDirect(overlayIP string) bool {
	now := time.Now()
	relayPolMu.Lock()
	defer relayPolMu.Unlock()
	p := relayPolicyFor(overlayIP)
	if now.Sub(p.lastProbe) < relayUpgradeProbeEvery {
		return false
	}
	p.lastProbe = now
	return true
}

// relayPolicySnapshot exposes the per-peer verdicts to the dashboard/status
// API, so "why is this peer relayed" is answerable without reading a log.
func relayPolicySnapshot() map[string]map[string]any {
	relayPolMu.Lock()
	defer relayPolMu.Unlock()
	out := make(map[string]map[string]any, len(relayPol))
	for ip, p := range relayPol {
		out[ip] = map[string]any{
			"nat_class":   p.natClass,
			"relay_first": p.relayFirst,
			"escalated":   p.escalated,
			"reason":      p.reason,
		}
	}
	return out
}
