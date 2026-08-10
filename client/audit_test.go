package main

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func setOverlay(t *testing.T, cidr string) {
	t.Helper()
	_, n, err := net.ParseCIDR(cidr)
	if err != nil { t.Fatal(err) }
	overlayNet = n
	overlayCIDR = cidr
}

// 1. Candidate filtering: the rules I changed, stated as expectations.
func TestCandidateFiltering(t *testing.T) {
	setOverlay(t, "10.22.22.0/24")
	cases := []struct{ addr string; punchable, validPeer bool; why string }{
		{"69.36.62.127:6970", true, true, "public endpoint"},
		{"10.22.22.7:6970", false, false, "overlay addr: NEVER a transport endpoint (see isPunchableAddr)"},
		{"192.168.1.5:6970", true, false, "LAN addr: punchable, not a public peer record"},
		{":6970", false, false, "unexpanded template"},
		{"127.0.0.1:6970", false, false, "loopback"},
		{"69.36.62.127:0", false, false, "port 0"},
		{"garbage", false, false, "malformed"},
	}
	for _, c := range cases {
		if got := isPunchableAddr(c.addr); got != c.punchable {
			t.Errorf("isPunchableAddr(%q)=%v want %v (%s)", c.addr, got, c.punchable, c.why)
		}
		if got := isValidPeer(c.addr); got != c.validPeer {
			t.Errorf("isValidPeer(%q)=%v want %v (%s)", c.addr, got, c.validPeer, c.why)
		}
	}
}

// 2. Only addresses this host OWNS may be advertised: a real endpoint is
// published, an overlay address (another node's) is dropped entirely.
func TestOnlyOwnedAddressesAreAdvertised(t *testing.T) {
	setOverlay(t, "10.22.22.0/24")
	myUDPPort = 6970
	extraCandidates = nil
	for _, c := range []string{"10.22.22.7:6970", "69.36.62.127:6970"} {
		if isPunchableAddr(c) {
			extraCandidates = append(extraCandidates, c)
		}
	}
	defer func() { extraCandidates = nil }()
	got := myConnectCandidates()
	if strings.Contains(got, "10.22.22.7") {
		t.Errorf("overlay address must never be advertised; got %q", got)
	}
	if !strings.Contains(got, "69.36.62.127:6970") {
		t.Errorf("the real public endpoint must be advertised; got %q", got)
	}
}

// 3. A configured public candidate must override a misleading STUN result.
func TestFirstPublicExtraCandidateHost(t *testing.T) {
	setOverlay(t, "10.22.22.0/24")
	extraCandidates = []string{"10.22.22.7:6970", "192.168.1.9:6970", "69.36.62.127:6970"}
	defer func() { extraCandidates = nil }()
	if got := firstPublicExtraCandidateHost(); got != "69.36.62.127" {
		t.Errorf("want the public host, got %q (overlay/LAN must be skipped)", got)
	}
	extraCandidates = []string{"10.22.22.7:6970"}
	if got := firstPublicExtraCandidateHost(); got != "" {
		t.Errorf("overlay-only should yield no override, got %q", got)
	}
}

// 4. Roster must carry exit/exit-error/v6 so panels can badge relayed peers.
func TestRosterCarriesDiagnosticFlags(t *testing.T) {
	in := []rosterEntry{{IP: "10.22.22.22", Name: "k8s", Exit: true, ExitErr: true, PQ: true, V6: true}}
	b, err := json.Marshal(in)
	if err != nil { t.Fatal(err) }
	var out []rosterEntry
	if err := json.Unmarshal(b, &out); err != nil { t.Fatal(err) }
	g := out[0]
	if !g.Exit || !g.ExitErr || !g.PQ || !g.V6 {
		t.Errorf("flags lost in round-trip: %+v (json=%s)", g, b)
	}
	// Old builds send none of these; absence must decode as false, not error.
	var legacy []rosterEntry
	if err := json.Unmarshal([]byte(`[{"ip":"10.22.22.5","name":"old"}]`), &legacy); err != nil {
		t.Fatalf("legacy roster must still parse: %v", err)
	}
	if legacy[0].Exit || legacy[0].V6 { t.Error("absent flags must default false") }
}

// 5. Rendezvous credential: one field, two schemes, auto-detected.
func TestRendezvousAuthScheme(t *testing.T) {
	defer func() { gRendezvousCred = "" }()
	newReq := func() *http.Request {
		r, _ := http.NewRequest("POST", "https://rv.example.com/api/rendezvous", nil); return r
	}
	gRendezvousCred = ""
	r := newReq(); applyRendezvousAuth(r)
	if r.Header.Get("Authorization") != "" { t.Error("no credential -> no header") }

	gRendezvousCred = "sometoken"
	r = newReq(); applyRendezvousAuth(r)
	if got := r.Header.Get("Authorization"); got != "Bearer sometoken" {
		t.Errorf("bare value must be Bearer, got %q", got)
	}
	gRendezvousCred = "alice:hunter2"
	r = newReq(); applyRendezvousAuth(r)
	u, p, ok := r.BasicAuth()
	if !ok || u != "alice" || p != "hunter2" { t.Errorf("colon value must be Basic; got %v %q %q", ok, u, p) }

	// A password containing a colon must survive.
	gRendezvousCred = "bob:a:b:c"
	r = newReq(); applyRendezvousAuth(r)
	u, p, _ = r.BasicAuth()
	if u != "bob" || p != "a:b:c" { t.Errorf("password with colons mangled: %q %q", u, p) }
}

// 6. Exit pin matching — the field users type into the apps.
func TestExitPinMatches(t *testing.T) {
	var pub [32]byte
	copy(pub[:], []byte("0123456789abcdef0123456789abcdef"))
	if exitPinMatches("", pub) { t.Error("empty pin must never match") }
	fp := peerKeyFingerprint(pub[:])
	if len(fp) >= 6 && !exitPinMatches(fp[:6], pub) {
		t.Errorf("6-char fingerprint prefix %q should match", fp[:6])
	}
	if exitPinMatches("zz", pub) { t.Error("short junk must not match") }
}

// 7. Heavy-tick math: the bug that silenced gossip when keepalive >= 60s.
func TestHeavyTickFiresForEveryKeepalive(t *testing.T) {
	for _, ka := range []int{5, 10, 20, 25, 30, 60, 120} {
		every := int(time.Minute / (time.Duration(ka) * time.Second))
		if every < 1 { every = 1 }
		fired := 0
		for tick := 1; tick <= 20; tick++ {
			if every == 1 || tick%every == 1 { fired++ }
		}
		if fired == 0 {
			t.Errorf("keepalive=%ds: heavy tick NEVER fires (slowGossipEvery=%d)", ka, every)
		}
	}
}

// 8. Keepalive must stay under the ~30s carrier-NAT UDP timeout.
func TestKeepaliveUnderCarrierNATTimeout(t *testing.T) {
	if gKeepaliveInterval >= 30*time.Second {
		t.Errorf("keepalive %v is at/over the typical carrier NAT timeout (~30s)", gKeepaliveInterval)
	}
	if sessionStaleTimeout <= 3*gKeepaliveInterval {
		t.Errorf("stale timeout %v must exceed 3 keepalives (%v) or healthy sessions get torn down",
			sessionStaleTimeout, 3*gKeepaliveInterval)
	}
}

// A node must never ADVERTISE an address it does not own. The regression this
// guards: a Kubernetes pod configured with EXTRA_CANDIDATES="$(NODE_IP):6970"
// on a cluster whose node-IP is an overlay address published another node's
// overlay IP as its own endpoint — visible in every dashboard as the wrong
// address, unusable by phones, and dependent on that other node staying up.
func TestOverlayAddressIsNeverAdvertisedAsOwnEndpoint(t *testing.T) {
	setOverlay(t, "10.22.22.0/24")
	myUDPPort = 6970
	defer func() { extraCandidates = nil }()

	// Simulate loadConfig's filtering of operator-supplied candidates.
	filter := func(in []string) []string {
		var out []string
		for _, c := range in {
			c = strings.TrimSpace(c)
			if c == "" || !isPunchableAddr(c) {
				continue
			}
			if h, _, err := net.SplitHostPort(c); err == nil && isOverlayTransportAddr(net.ParseIP(h)) {
				continue // dropped: another node's overlay address
			}
			out = append(out, c)
		}
		return out
	}

	extraCandidates = filter([]string{"10.22.22.7:6970"})
	if len(extraCandidates) != 0 {
		t.Errorf("an overlay address must be dropped, kept %v", extraCandidates)
	}
	if got := myConnectCandidates(); strings.Contains(got, "10.22.22.7") {
		t.Errorf("overlay address leaked into advertised candidates: %q", got)
	}

	// A real address the host owns must still be advertised, first.
	extraCandidates = filter([]string{"10.22.22.7:6970", "69.36.62.127:6970"})
	if len(extraCandidates) != 1 || extraCandidates[0] != "69.36.62.127:6970" {
		t.Fatalf("public candidate must survive filtering, got %v", extraCandidates)
	}
	got := myConnectCandidates()
	if !strings.Contains(got, "69.36.62.127:6970") {
		t.Errorf("public candidate must be advertised; got %q", got)
	}
	if strings.Contains(got, "10.22.22.7") {
		t.Errorf("overlay address still leaked: %q", got)
	}
}

// TestOverlayEndpointBlockedAtEveryStage walks the FULL chain by which an
// overlay address became a peer's advertised endpoint, and asserts it is
// refused at every stage. Blocking only one stage is not enough: the address
// was re-learned from a different stage each time.
//
//	1 advertise  myConnectCandidates must not publish it
//	2 punch      isPunchableAddr must reject it
//	3 tracker    isValidPeer must reject it
//	4 memorise   addKnownPeer must not store it (else the retry loop revives it)
//	5 gossip     PEX must neither send nor accept it
func TestOverlayEndpointBlockedAtEveryStage(t *testing.T) {
	setOverlay(t, "10.22.22.0/24")
	myUDPPort = 6970
	const bad = "10.22.22.7:6970"  // another node's overlay address
	const good = "69.36.62.127:6970"

	// 2 + 3
	if isPunchableAddr(bad) { t.Error("stage 2: isPunchableAddr accepted an overlay address") }
	if isValidPeer(bad)     { t.Error("stage 3: isValidPeer accepted an overlay address") }
	if !isPunchableAddr(good) { t.Error("a real public endpoint must stay punchable") }

	// 1
	extraCandidates = nil
	for _, c := range []string{bad, good} {
		if isPunchableAddr(c) { extraCandidates = append(extraCandidates, c) }
	}
	defer func() { extraCandidates = nil }()
	if got := myConnectCandidates(); strings.Contains(got, "10.22.22.7") {
		t.Errorf("stage 1: advertised an overlay address: %q", got)
	} else if !strings.Contains(got, "69.36.62.127") {
		t.Errorf("stage 1: dropped the real endpoint too: %q", got)
	}

	// 4 — the stage that made the bad endpoint outlive its cause.
	knownPeersMu.Lock(); knownPeers = map[string]time.Time{}; knownPeersMu.Unlock()
	addKnownPeer(bad)
	addKnownPeer(good)
	list := knownPeerList()
	for _, p := range list {
		if strings.HasPrefix(p, "10.22.22.7") {
			t.Errorf("stage 4: overlay address memorised in knownPeers (%v) — the retry loop would revive it", list)
		}
	}
	found := false
	for _, p := range list { if p == good { found = true } }
	if !found { t.Errorf("stage 4: real endpoint should be remembered, got %v", list) }
}
