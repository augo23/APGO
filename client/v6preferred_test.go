package main

import (
	"testing"
	"time"
)

// Small helpers so the cache-pinning in these tests reads clearly.
func timeNowForTest() time.Time  { return time.Now() }
func timeZeroForTest() time.Time { return time.Time{} }

// The exact candidate list from the field report: four addresses out of ONE
// /64 on a Wi-Fi interface the phone had already left, ahead of the only
// address that could work. maxV6Candidates is 4, so the stale ones consumed
// the entire v6 budget and every peer punched all four.
func TestRankPutsPreferredSourceFirst(t *testing.T) {
	stale := []string{
		"[2600:381:9681:bbb7:cc6:7408:f774:aac]:58186",
		"[2600:381:9681:bbb7:8c9b:2893:f23:ccda]:58186",
		"[2600:381:9681:bbb7:5d8b:1b3:3a3a:d198]:58186",
	}
	live := "[2600:1007:113c:a7eb:42e:a7b7:fe6a:be53]:58186"
	eps := append(append([]string{}, stale...), live)

	ifOf := map[string]string{
		stale[0]: "en0", stale[1]: "en0", stale[2]: "en0",
		live: "pdp_ip0",
	}

	// Pin the probe result rather than depending on the test host's network.
	v6PrefMu.Lock()
	v6PrefAt = timeNowForTest()
	v6PrefAddr = "2600:1007:113c:a7eb:42e:a7b7:fe6a:be53"
	v6PrefIf = "pdp_ip0"
	v6PrefMu.Unlock()
	defer func() {
		v6PrefMu.Lock()
		v6PrefAt, v6PrefAddr, v6PrefIf = timeZeroForTest(), "", ""
		v6PrefMu.Unlock()
	}()

	got := rankV6Endpoints(eps, ifOf)
	if got[0] != live {
		t.Fatalf("preferred source must rank first; got %q (full: %v)", got[0], got)
	}
	if len(got) != len(eps) {
		t.Fatalf("ranking must not drop candidates: got %d, want %d", len(got), len(eps))
	}
}

// With no usable v6 route the probe has no opinion, and having no opinion is
// not a reason to reorder or discard anything.
func TestRankIsIdentityWithoutPreferredSource(t *testing.T) {
	eps := []string{"[2001:db8::1]:1", "[2001:db8::2]:1"}
	v6PrefMu.Lock()
	v6PrefAt = timeNowForTest()
	v6PrefAddr, v6PrefIf = "", ""
	v6PrefMu.Unlock()
	defer func() {
		v6PrefMu.Lock()
		v6PrefAt = timeZeroForTest()
		v6PrefMu.Unlock()
	}()

	got := rankV6Endpoints(eps, map[string]string{})
	for i := range eps {
		if got[i] != eps[i] {
			t.Fatalf("order must be preserved when there is no preference: %v", got)
		}
	}
}

// Addresses sharing the live interface must outrank addresses on other
// interfaces, so a dual-stack host with two NICs still advertises both of the
// working interface's addresses before any ghost.
func TestRankGroupsByPreferredInterface(t *testing.T) {
	a := "[2001:db8:1::1]:1" // preferred
	b := "[2001:db8:1::2]:1" // same interface (privacy address)
	c := "[2001:db8:2::9]:1" // other, stale interface
	ifOf := map[string]string{a: "en1", b: "en1", c: "en0"}

	v6PrefMu.Lock()
	v6PrefAt = timeNowForTest()
	v6PrefAddr, v6PrefIf = "2001:db8:1::1", "en1"
	v6PrefMu.Unlock()
	defer func() {
		v6PrefMu.Lock()
		v6PrefAt, v6PrefAddr, v6PrefIf = timeZeroForTest(), "", ""
		v6PrefMu.Unlock()
	}()

	got := rankV6Endpoints([]string{c, b, a}, ifOf)
	want := []string{a, b, c}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}
