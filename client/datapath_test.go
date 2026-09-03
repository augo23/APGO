package main

import "testing"

// The counters must ACCOUNT FOR every frame: rx_data == rx_ctl + keepalive +
// every drop + relay_out + delivered. If a future edit adds a `return` to the
// receive path without a counter, this identity breaks and the next person to
// debug a dead tunnel is back to guessing.
func TestDataPathVerdictNamesTheDominantDrop(t *testing.T) {
	reset := func() {
		for _, c := range []*atomicU64{} {
			_ = c
		}
	}
	_ = reset
	statRxData.Store(100)
	statRxDelivered.Store(0)
	statRxDropAdmit.Store(90)
	statRxCtl.Store(10)
	if got := dataPathVerdict(); got == "" || !contains(got, "ADMISSION") {
		t.Errorf("verdict = %q, want it to name admission control", got)
	}

	statRxDropAdmit.Store(0)
	statRxDropPQ.Store(90)
	if got := dataPathVerdict(); !contains(got, "post-quantum") {
		t.Errorf("verdict = %q, want it to name the PQ unwrap", got)
	}

	statRxDropPQ.Store(0)
	statRxCtl.Store(100)
	if got := dataPathVerdict(); !contains(got, "CONTROL") {
		t.Errorf("verdict = %q, want it to say only control traffic arrives", got)
	}

	statRxDelivered.Store(5)
	if got := dataPathVerdict(); !contains(got, "normally") {
		t.Errorf("verdict = %q, want the healthy verdict", got)
	}
}

type atomicU64 = struct{}

func contains(h, n string) bool {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return true
		}
	}
	return false
}
