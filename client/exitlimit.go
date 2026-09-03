package main

// exitlimit.go meters traffic this node forwards AS A VPN EXIT NODE.
//
// Being an exit is the most expensive thing a node can volunteer for: unlike a
// relay circuit, which carries overlay traffic between two members of the mesh,
// an exit pays for somebody else's entire internet connection out of its own
// link and its own IP address. Before this, the public relay could be metered
// and the exit could not -- so the cheap donation was capped and the expensive
// one was unlimited, which is exactly backwards.
//
// It reuses bandwidthLimiter (token buckets + a persisted rolling quota) rather
// than inventing a second mechanism, so the semantics an operator has already
// learned from the relay limits carry over unchanged, and one ledger format
// covers both.

import (
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
)

var (
	exitLimiterOnce sync.Mutex
	gExitLimiter    *bandwidthLimiter

	// Dropped byte/packet counters, so a throttled exit is visible as a
	// throttle rather than as "the internet is slow through the VPN".
	statExitDropped atomic.Uint64
	statExitBytes   atomic.Uint64
)

// exitStatePath keeps the exit ledger beside the relay one, in the writable
// state dir. A separate file: the two budgets are independent, and sharing a
// ledger would let exit traffic silently consume the relay's quota.
func exitStatePath() string {
	if p := os.Getenv("EXIT_STATE_FILE"); p != "" {
		return p
	}
	if rp := relayStatePath(); rp != "" {
		return filepath.Join(filepath.Dir(rp), "exit-bandwidth.json")
	}
	return ""
}

// ensureExitLimiter returns the exit meter, creating it unlimited on first use.
// Unlimited is the correct default here and NOT a footgun, because unlike the
// public relay an exit node only ever serves peers that are already admitted to
// this network -- there is no open-to-strangers state to protect against. The
// limit exists so an operator can budget their own link, not to fend off
// unknown callers.
func ensureExitLimiter() *bandwidthLimiter {
	exitLimiterOnce.Lock()
	defer exitLimiterOnce.Unlock()
	if gExitLimiter == nil {
		gExitLimiter = newBandwidthLimiter(0, 0, 0, 30, exitStatePath())
	}
	return gExitLimiter
}

// exitAllowOut reports whether n bytes may be forwarded OUT to the internet on
// a client's behalf, charging the budget when they may.
//
// Fail-OPEN when no limiter exists: a node that has never been given an exit
// budget must behave exactly as it did before this file existed. Fail-closed
// would silently break every existing exit node on upgrade.
func exitAllowOut(n int) bool {
	l := gExitLimiter
	if l == nil {
		return true
	}
	if l.QuotaExceeded() {
		statExitDropped.Add(1)
		return false
	}
	if !l.AllowUp(n) {
		statExitDropped.Add(1)
		return false
	}
	statExitBytes.Add(uint64(n))
	return true
}

// exitAllowIn is the return direction: internet -> overlay client.
func exitAllowIn(n int) bool {
	l := gExitLimiter
	if l == nil {
		return true
	}
	if l.QuotaExceeded() {
		statExitDropped.Add(1)
		return false
	}
	if !l.AllowDown(n) {
		statExitDropped.Add(1)
		return false
	}
	statExitBytes.Add(uint64(n))
	return true
}

// exitLimitStatus is the dashboard view.
func exitLimitStatus() map[string]any {
	out := map[string]any{
		"enabled":       amExit,
		"limited":       gExitLimiter != nil,
		"dropped":       statExitDropped.Load(),
		"bytes_metered": statExitBytes.Load(),
	}
	if gExitLimiter != nil {
		out["bandwidth"] = gExitLimiter.Status()
	}
	return out
}

// setExitNodeEnabled turns exit-node mode on or off LIVE, doing the NAT work
// that initExit does at startup.
//
// Turning it ON can fail (iptables/pf unavailable, no permission), and that
// failure must not leave the node advertising 'E' while black-holing every
// client that selects it -- the same trap initExit guards against. So amExit is
// only set once the NAT is actually in place.
func setExitNodeEnabled(on bool) error {
	if on == amExit {
		return nil
	}
	if !on {
		// Stop advertising and stop forwarding. The platform NAT rules are
		// deliberately LEFT IN PLACE: there is no teardownExitNAT on any
		// platform today, and inventing four of them (iptables, pf, WinNAT,
		// no-op) inside this change would put untested privileged teardown on
		// the path that was just stabilised. Leaving the rules is inert --
		// amExit gates every forwarding decision, so nothing is forwarded
		// regardless -- and re-enabling is then instant. Removing them cleanly
		// is worth doing, as its own change.
		amExit = false
		// Tell peers now rather than letting the candidate age out: without
		// this, every other node shows this one as an exit for minutes after
		// the setting reads "off".
		withdrawExitAnnounce()
		log.Printf("[exit] exit-node mode OFF (admin) — no longer advertising or forwarding " +
			"(platform NAT rules left in place; they forward nothing while exit mode is off)")
		return nil
	}
	if err := setupExitNAT(); err != nil {
		amExit = false
		exitNATErr = err.Error()
		return err
	}
	amExit = true
	exitNATErr = ""
	log.Printf("[exit] exit-node mode ON (admin) — forwarding internet traffic for overlay clients")
	return nil
}
