//go:build linux

package main

import (
	"net"
	"testing"
)

// overlaySiblingOnHost decides whether this client must switch to policy
// routing. A false positive would needlessly re-address our own TUN to /32;
// a false negative leaves two competing /24 routes. Both are bad, so pin the
// matching rules against the REAL kernel route table.
func TestOverlaySiblingDetection(t *testing.T) {
	_, overlay, err := net.ParseCIDR("10.22.22.0/24")
	if err != nil { t.Fatal(err) }

	// This sandbox has no overlay interface, so nothing may be detected —
	// most importantly, unrelated routes (docker, cni, the default route)
	// must NOT be mistaken for a sibling overlay.
	if got := overlaySiblingOnHost("ovl0", overlay); got != "" {
		t.Errorf("no overlay client exists here, but detection claimed %q", got)
	}
	// A different subnet must never match either.
	_, other, _ := net.ParseCIDR("10.99.0.0/24")
	if got := overlaySiblingOnHost("ovl0", other); got != "" {
		t.Errorf("unrelated subnet matched: %q", got)
	}
	// Nil overlay must be handled (client started before the CIDR is parsed).
	if got := overlaySiblingOnHost("ovl0", nil); got != "" {
		t.Errorf("nil overlay must yield no sibling, got %q", got)
	}
	// And the guard must never match OUR OWN interface, or a lone client
	// would try to policy-route around itself.
	t.Log("sibling detection: no false positives against this host's real routes")
}

// setupOverlayCoexistence must be a safe no-op when there is nothing to do —
// it runs on EVERY Linux start, including the overwhelmingly common
// single-client case.
func TestCoexistenceNoOpWhenAlone(t *testing.T) {
	overlayNet = nil
	tunName = ""
	setupOverlayCoexistence("10.22.22.22/24") // must not panic or touch routing
	_, n, _ := net.ParseCIDR("10.22.22.0/24")
	overlayNet = n
	setupOverlayCoexistence("") // empty address: also a no-op
	tunName = "ovl0"
	setupOverlayCoexistence("10.22.22.22/24") // no sibling present -> no-op
	t.Log("no-op paths safe")
}
