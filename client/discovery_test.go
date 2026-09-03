package main

import (
	"net"
	"testing"
	"time"
)

func TestParseRateUnits(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"", 0},
		{"unlimited", 0},
		{"0", 0},
		{"1000", 1000},
		{"5MB", 5_000_000},
		{"5 MB/s", 5_000_000},
		{"500kb", 500_000},
		{"1.5GB", 1_500_000_000},
		// Bit units divided by 8 — an ISP's "100 mbit" plan is 12.5 MB/s, and
		// treating it as 100 MB/s would use eight times the intended share.
		{"100mbit", 12_500_000},
		{"8bit", 1},
		{"1MiB", 1024 * 1024},
	}
	for _, c := range cases {
		if got := parseRate(c.in); got != c.want {
			t.Errorf("parseRate(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestTokenBucketEnforcesCeiling(t *testing.T) {
	b := newTokenBucket(1000) // 1000 B/s, burst floored at 64 KiB
	// Burst is spendable immediately...
	if !b.Allow(65536) {
		t.Fatal("full burst should be allowed")
	}
	// ...and then the bucket is empty.
	if b.Allow(65536) {
		t.Fatal("second full burst must be refused")
	}
	// An unlimited bucket never refuses.
	u := newTokenBucket(0)
	for i := 0; i < 100; i++ {
		if !u.Allow(1 << 20) {
			t.Fatal("unlimited bucket refused")
		}
	}
}

func TestQuotaStopsRelaying(t *testing.T) {
	l := newBandwidthLimiter(0, 0, 1000, 30, "")
	if l.QuotaExceeded() {
		t.Fatal("fresh quota must not be exceeded")
	}
	if !l.AllowUp(600) || !l.AllowDown(500) {
		t.Fatal("spending inside the quota must be allowed")
	}
	if !l.QuotaExceeded() {
		t.Fatal("1100 bytes against a 1000-byte quota must exceed it")
	}
	if l.AllowUp(1) {
		t.Fatal("relaying must stop once the quota is spent")
	}
}

// The blinded key is the whole privacy argument for putting a private overlay
// on a public DHT: without the PSK you cannot compute what to look up.
func TestDHTKeyIsBlindedByPSK(t *testing.T) {
	name := "home-lab-overlay"
	plain := deriveInfoHash(name)
	k1 := dhtKey(name, []byte("psk-one"))
	k2 := dhtKey(name, []byte("psk-two"))
	if len(k1) != 20 {
		t.Fatalf("key length = %d, want 20", len(k1))
	}
	if string(k1) == string(plain) {
		t.Error("blinded key must differ from the guessable tracker infohash")
	}
	if string(k1) == string(k2) {
		t.Error("a different PSK must produce a different key (PSK rotation evicts old members)")
	}
	if string(dhtKey(name, []byte("psk-one"))) != string(k1) {
		t.Error("key derivation must be deterministic")
	}
	// No PSK: documented fallback to the plain infohash.
	if string(dhtKey(name, nil)) != string(plain) {
		t.Error("with no PSK the key should fall back to the tracker infohash")
	}
}

func TestBencodeRoundTrip(t *testing.T) {
	in := map[string]interface{}{
		"t": "aa",
		"y": "q",
		"q": "get_peers",
		"a": map[string]interface{}{"id": "01234567890123456789", "port": 6969},
	}
	enc, err := bencode(in)
	if err != nil {
		t.Fatalf("bencode: %v", err)
	}
	// Dict keys must be sorted — some implementations drop unsorted dicts.
	if enc[0] != 'd' || string(enc[1:4]) != "1:a" {
		t.Errorf("expected sorted dict starting with key \"a\", got %q", enc[:8])
	}
	out, err := bdecode(enc)
	if err != nil {
		t.Fatalf("bdecode: %v", err)
	}
	m, ok := out.(map[string]interface{})
	if !ok {
		t.Fatal("decoded value is not a dict")
	}
	if q, _ := bdictStr(m, "q"); q != "get_peers" {
		t.Errorf("q = %q, want get_peers", q)
	}
	a, _ := bdictDict(m, "a")
	if p, _ := bdictInt(a, "port"); p != 6969 {
		t.Errorf("port = %d, want 6969", p)
	}
}

func TestRoutingTableRejectsUnroutableAddrs(t *testing.T) {
	// A hostile node that can seed LAN addresses into our table turns our own
	// lookups into a scan of the operator's network.
	bad := []string{"127.0.0.1:6881", "192.168.1.5:6881", "10.0.0.1:6881",
		"169.254.1.1:6881", "100.64.0.1:6881", "0.0.0.0:6881"}
	for _, s := range bad {
		a, _ := net.ResolveUDPAddr("udp", s)
		if dhtRoutableAddr(a) {
			t.Errorf("%s must not be routable for the DHT", s)
		}
	}
	good, _ := net.ResolveUDPAddr("udp", "203.0.113.7:6881")
	if !dhtRoutableAddr(good) {
		t.Error("a public address must be routable")
	}

	var tbl dhtRoutingTable
	var lan, pub [20]byte
	lan[0], pub[0] = 0x01, 0x02
	badAddr, _ := net.ResolveUDPAddr("udp", "192.168.1.5:6881")
	tbl.Add(lan, badAddr)
	tbl.Add(pub, good)
	if tbl.Count() != 1 {
		t.Fatalf("table holds %d nodes, want 1 (the LAN one must be refused)", tbl.Count())
	}
}

func TestRoutingTableClosestOrdersByXOR(t *testing.T) {
	var tbl dhtRoutingTable
	addr, _ := net.ResolveUDPAddr("udp", "203.0.113.7:6881")
	mk := func(b byte) [20]byte {
		var id [20]byte
		id[0] = b
		return id
	}
	for _, b := range []byte{0xF0, 0x0F, 0x01, 0x80} {
		a := *addr
		a.Port = int(b) + 1000
		tbl.Add(mk(b), &a)
	}
	got := tbl.Closest(mk(0x00), 4)
	if len(got) != 4 {
		t.Fatalf("got %d nodes, want 4", len(got))
	}
	// Closest to 0x00 is 0x01, then 0x0F, 0x80, 0xF0.
	want := []byte{0x01, 0x0F, 0x80, 0xF0}
	for i, w := range want {
		if got[i].id[0] != w {
			t.Errorf("position %d = %#x, want %#x", i, got[i].id[0], w)
		}
	}
}

// Circuit ids must survive the round-trip through the synthetic address that
// carries them through the session layer — this is the load-bearing trick in
// relayclient.go, and an off-by-one here silently misroutes relayed traffic.
func TestSyntheticAddrRoundTrip(t *testing.T) {
	for _, cid := range []uint32{1, 0xFF, 0x1234, 0xFFFFFF} {
		a := synthAddrFor(cid)
		if !isSyntheticRelayAddr(a) {
			t.Fatalf("cid %d: address %s not recognised as synthetic", cid, a)
		}
		v4 := a.IP.To4()
		back := uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
		if back != cid {
			t.Errorf("cid %d round-tripped as %d", cid, back)
		}
	}
	real4, _ := net.ResolveUDPAddr("udp", "203.0.113.7:6969")
	if isSyntheticRelayAddr(real4) {
		t.Error("a real endpoint must not be mistaken for a circuit address")
	}
}

func TestRelayTokenBindsToSourceIP(t *testing.T) {
	d := &dhtState{}
	d.tokRotate = time.Now()
	a, _ := net.ResolveUDPAddr("udp", "203.0.113.7:6881")
	b, _ := net.ResolveUDPAddr("udp", "198.51.100.9:6881")
	tok := d.issueToken(a)
	if !d.validToken(a, tok) {
		t.Error("a token must validate for the address it was issued to")
	}
	// This is BEP 5's anti-spoofing property: without it anyone can list any
	// address as a peer for any key.
	if d.validToken(b, tok) {
		t.Error("a token must NOT validate for a different source address")
	}
	if d.validToken(a, "") {
		t.Error("an empty token must never validate")
	}
}

func TestPublicRelayRefusesWhenDisabled(t *testing.T) {
	l := newBandwidthLimiter(0, 0, 0, 30, "")
	r := startPublicRelay(nil, l, 0, 0, 0)
	defer func() { gPublicRelay = nil }()
	if r.enabled.Load() {
		t.Fatal("a public relay must start DISABLED — donating bandwidth is opt-in")
	}
	var g [20]byte
	addr, _ := net.ResolveUDPAddr("udp", "203.0.113.7:6969")
	r.handleServer(relayReserve, g[:], addr)
	r.mu.Lock()
	n := len(r.reservations)
	r.mu.Unlock()
	if n != 0 {
		t.Error("a disabled relay must not hold reservations")
	}
}

func TestPublicRelayEnforcesPerIPCircuitCap(t *testing.T) {
	l := newBandwidthLimiter(0, 0, 0, 30, "")
	r := startPublicRelay(nil, l, 100, 2, 0)
	defer func() { gPublicRelay = nil }()
	r.enabled.Store(true)
	var g [20]byte
	g[0] = 0xAB
	// Three members waiting in the group...
	for i := 1; i <= 3; i++ {
		a, _ := net.ResolveUDPAddr("udp", net.JoinHostPort("203.0.113."+itoaPort(i), "6969"))
		r.reserve(g, a)
	}
	caller, _ := net.ResolveUDPAddr("udp", "198.51.100.9:6969")
	r.connect(g, caller)
	r.mu.Lock()
	n := len(r.circuits)
	r.mu.Unlock()
	// ...but one caller IP is capped at maxPerIP circuits.
	if n > 2 {
		t.Errorf("opened %d circuits for one IP, cap is 2", n)
	}
	if n == 0 {
		t.Error("expected at least one circuit to open")
	}
}
