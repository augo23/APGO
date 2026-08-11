package main

import (
	"testing"
	"time"
)

// The relay fallback for an established-but-unproven route must be a PROBE,
// not a duplicate of every packet. Firing it per-packet multiplies a transfer
// by the peer count and is self-sustaining: the flood delays the keepalives
// that would mark the route live again. See shouldProbeUnprovenRoute.
func TestUnprovenRouteFallbackIsProbeNotFlood(t *testing.T) {
	unprovenProbeMu.Lock()
	unprovenProbeAt = map[string]time.Time{}
	unprovenProbeMu.Unlock()

	const dst = "10.22.22.7"
	probes := 0
	for i := 0; i < 5000; i++ {
		if shouldProbeUnprovenRoute(dst) {
			probes++
		}
	}
	if probes != 1 {
		t.Errorf("5000 packets to one destination produced %d relay probes, want 1", probes)
	}

	unprovenProbeMu.Lock()
	unprovenProbeAt[dst] = time.Now().Add(-unprovenProbeInterval - time.Millisecond)
	unprovenProbeMu.Unlock()
	if !shouldProbeUnprovenRoute(dst) {
		t.Error("no probe after the interval — a dead route would never be repaired")
	}
	if !shouldProbeUnprovenRoute("10.22.22.9") {
		t.Error("a different destination was throttled by an unrelated one")
	}
}
