package main

// relayshare.go gives a public relay a SENSIBLE DEFAULT budget instead of
// demanding that the operator invent one.
//
// The relay used to refuse to start without an explicit limit. The reasoning
// was sound -- an uncapped relay is an open-ended commitment that strangers
// find and keep -- but the remedy was wrong: it made the safe choice the one
// that takes work, so the realistic outcomes were "no relay" or "some number
// typed to get past the dialog". A default that is automatically reasonable
// protects the link better than a mandatory field that invites a guess.
//
// The default is 80% of this node's own observed throughput, leaving a fifth of
// the link for the node itself. Capacity is ESTIMATED, because nothing here can
// ask the NIC what the line rate is: the estimate is a decaying peak of the
// total bytes/sec this node has actually moved. It is deliberately conservative
// while the node is idle and grows as real traffic proves the link can carry
// more, so a relay on a fresh node starts small and opens up rather than
// promising bandwidth that was never measured.

import (
	"sync"
	"sync/atomic"
	"time"
)

// relayDefaultSharePct is the fraction of estimated capacity a public relay may
// use when no explicit limit is configured.
const relayDefaultSharePct = 80

// relayShareFloorBps keeps the automatic budget usable on a node that has
// barely transferred anything yet. Without a floor, a freshly started relay
// would advertise itself and then throttle to near zero -- which looks exactly
// like a broken relay, and is the failure people report as "relaying doesn't
// work" rather than as a rate limit.
const relayShareFloorBps = 128 * 1024 // 1 Mbit/s

var (
	// nodeBytesTotal is every byte this node has sent or received on the
	// overlay transport, sampled to derive a throughput estimate.
	nodeBytesTotal atomic.Uint64

	shareMu       sync.Mutex
	observedPeak  float64 // bytes/sec, decaying peak
	lastShareSamp time.Time
	lastShareByte uint64

	// relayAutoShare is true while the relay budget is automatic. An explicit
	// limit from an admin turns it off: a number somebody typed is a decision,
	// and must not be quietly overwritten by the governor on its next tick.
	relayAutoShare atomic.Bool
)

// noteNodeBytes records transport bytes for the capacity estimate.
func noteNodeBytes(n int) {
	if n > 0 {
		nodeBytesTotal.Add(uint64(n))
	}
}

// relayCapacityEstimateBps returns the current decaying-peak throughput
// estimate in bytes per second.
func relayCapacityEstimateBps() int64 {
	shareMu.Lock()
	defer shareMu.Unlock()
	if observedPeak < relayShareFloorBps {
		return relayShareFloorBps
	}
	return int64(observedPeak)
}

// relayAutoBudgetBps is the automatic budget: 80% of estimated capacity.
func relayAutoBudgetBps() int64 {
	return relayCapacityEstimateBps() * relayDefaultSharePct / 100
}

// sampleShare updates the decaying peak from the byte counter.
//
// Decay matters as much as the peak. A pure high-water mark would let one burst
// -- a file copy, a backup -- permanently authorise a relay budget the link
// cannot sustain, and the relay would then be the thing saturating it. Decaying
// slowly (about 2% per sample) means a sustained rate holds the estimate up
// while a one-off spike bleeds away over a few minutes.
func sampleShare() {
	now := time.Now()
	cur := nodeBytesTotal.Load()
	shareMu.Lock()
	defer shareMu.Unlock()
	if lastShareSamp.IsZero() {
		lastShareSamp, lastShareByte = now, cur
		return
	}
	dt := now.Sub(lastShareSamp).Seconds()
	if dt <= 0 {
		return
	}
	rate := float64(cur-lastShareByte) / dt
	lastShareSamp, lastShareByte = now, cur
	if rate > observedPeak {
		observedPeak = rate
	} else {
		observedPeak *= 0.98
	}
}

// startRelayShareGovernor keeps the relay's automatic budget in step with the
// capacity estimate. It only ever writes the limiter while relayAutoShare is
// set, so an explicit admin limit is never overwritten.
func startRelayShareGovernor() {
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for range t.C {
			sampleShare()
			if !relayAutoShare.Load() || gBandwidth == nil {
				continue
			}
			b := relayAutoBudgetBps()
			cur := gBandwidth.Status()
			// Only write on a meaningful change, so the ledger is not marked
			// dirty (and rewritten to disk) every five seconds forever.
			if abs64(cur.UpLimitBps-b) > b/10 || abs64(cur.DownLimitBps-b) > b/10 {
				gBandwidth.Configure(b, b, cur.QuotaBytes, cur.PeriodDays)
			}
		}
	}()
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

// relayShareStatus is the dashboard view of the automatic budget.
func relayShareStatus() map[string]any {
	return map[string]any{
		"automatic":         relayAutoShare.Load(),
		"share_pct":         relayDefaultSharePct,
		"capacity_est_bps":  relayCapacityEstimateBps(),
		"auto_budget_bps":   relayAutoBudgetBps(),
		"auto_budget_human": formatRate(relayAutoBudgetBps()),
	}
}
