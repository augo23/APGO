package main

import (
	"fmt"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCheckEndpoint(t *testing.T) {
	cases := []struct {
		ep, src      string
		ok, verified bool
	}{
		{"8.8.8.8:5000", "8.8.8.8", true, true},       // own address, NAT'd port
		{"1.1.1.1:5000", "8.8.8.8", false, false},     // someone else's IPv4
		{"8.8.8.8:5000", "2001:4860::1", true, false}, // cross-family: unverifiable
		{"[2001:4860::1]:5000", "2001:4860::1", true, true},
		{"[2001:4860::2]:5000", "2001:4860::1", false, false},
		{"192.168.1.5:5000", "192.168.1.5", false, false}, // private endpoints never recorded
		{"8.8.8.8:5000", "192.168.1.20", true, false},     // LAN client, can't verify
	}
	for _, c := range cases {
		ok, v := checkEndpoint(c.ep, c.src)
		if ok != c.ok || (ok && v != c.verified) {
			t.Errorf("checkEndpoint(%q, %q) = %v,%v want %v,%v", c.ep, c.src, ok, v, c.ok, c.verified)
		}
	}
}

func TestPerSourceCaps(t *testing.T) {
	r := newRegistry(time.Minute)
	for i := 0; i < 50; i++ {
		r.announce("net", fmt.Sprintf("9.9.9.%d:1", i), "2001:db8::1", false)
	}
	if got := len(r.announce("net", "", "x", false)); got != r.maxPerSourceUnverified {
		t.Fatalf("unverified source recorded %d endpoints, want %d", got, r.maxPerSourceUnverified)
	}
	// A site behind one NAT (verified) may register many ports of its own IP.
	for i := 0; i < 20; i++ {
		r.announce("site", fmt.Sprintf("8.8.8.8:%d", 1000+i), "8.8.8.8", true)
	}
	if got := len(r.announce("site", "", "x", false)); got != 20 {
		t.Fatalf("verified site recorded %d endpoints, want 20", got)
	}
	// Refreshing an existing endpoint never counts against the cap.
	r.announce("net", "9.9.9.0:1", "2001:db8::1", false)
	if got := len(r.announce("net", "", "x", false)); got != r.maxPerSourceUnverified {
		t.Fatalf("refresh changed count to %d", got)
	}
	// Query-only requests never create networks.
	r.announce("ghost", "", "x", false)
	if _, ok := r.nets["ghost"]; ok {
		t.Fatal("query-only announce created a network")
	}
}

func TestSourceIP(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/rendezvous", nil)
	req.RemoteAddr = "127.0.0.1:5555"
	req.Header.Set("CF-Connecting-IP", "8.8.4.4")
	if got := sourceIP(req, ""); got != "8.8.4.4" {
		t.Fatalf("behind local proxy: got %q", got)
	}
	req.RemoteAddr = "8.8.8.8:5555" // direct internet client can't spoof the header
	if got := sourceIP(req, ""); got != "8.8.8.8" {
		t.Fatalf("direct client spoofed header: got %q", got)
	}
	req.RemoteAddr = "127.0.0.1:5555"
	req.Header.Del("CF-Connecting-IP")
	req.Header.Set("X-Forwarded-For", "6.6.6.6, 9.9.9.9")
	if got := sourceIP(req, ""); got != "9.9.9.9" {
		t.Fatalf("XFF should use the proxy-appended last hop: got %q", got)
	}
	if got := sourceIP(req, "0"); got != "127.0.0.1" {
		t.Fatalf("TRUST_PROXY_HEADERS=0 ignored: got %q", got)
	}
}

func TestRateLimiter(t *testing.T) {
	l := newRateLimiter(1, 3)
	n := 0
	for i := 0; i < 10; i++ {
		if l.allow("a") {
			n++
		}
	}
	if n != 3 || !l.allow("b") {
		t.Fatalf("burst allowed %d, want 3 (and other keys unaffected)", n)
	}
}
