package main

import (
	"encoding/base64"
	"net"
	"testing"
)

func udp(t *testing.T, s string) *net.UDPAddr {
	t.Helper()
	a, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		t.Fatalf("resolve %s: %v", s, err)
	}
	return a
}

// A global IPv6 endpoint needs no NAT on either side, so it must outrank a
// public IPv4 endpoint — which always depends on a translation entry that some
// router owns and can drop at any moment.
//
// Both used to be class 0. That single fact is why a node with a perfectly
// good IPv6 address still spent its life hole-punching: whichever address
// completed a handshake first won the route, that was always the v4 one (it is
// the only address trackers and the DHT can carry), and rule 4's "sticky while
// live" then kept it there.
func TestRouteClassPrefersGlobalIPv6OverPublicIPv4(t *testing.T) {
	v6 := udp(t, "[2600:1007:1131:ebb9::1]:6969")
	v4 := udp(t, "203.0.113.9:6969")
	priv := udp(t, "192.168.7.9:6969")

	if routeClass(v6) <= routeClass(v4) {
		t.Errorf("global IPv6 (%d) must outrank public IPv4 (%d)", routeClass(v6), routeClass(v4))
	}
	if routeClass(priv) <= routeClass(v6) {
		t.Errorf("a private/LAN path (%d) must still outrank IPv6 (%d): same wire beats the internet",
			routeClass(priv), routeClass(v6))
	}
}

// A v4-mapped v6 address is how an IPv4 peer arrives on our dual-stack socket.
// Counting it as "IPv6" would promote every NAT'd v4 peer to the NAT-free
// class and make the preference meaningless.
func TestV4MappedAddressIsNotTreatedAsIPv6(t *testing.T) {
	mapped := &net.UDPAddr{IP: net.ParseIP("::ffff:203.0.113.9"), Port: 6969}
	if isGlobalIPv6(mapped.IP) {
		t.Errorf("::ffff:203.0.113.9 is IPv4 and must not count as global IPv6")
	}
	if routeClass(mapped) != routeClassPublicV4 {
		t.Errorf("a v4-mapped address must be class public-v4, got %d", routeClass(mapped))
	}
	for _, s := range []string{"fe80::1", "fd00::1"} {
		if isGlobalIPv6(net.ParseIP(s)) {
			t.Errorf("%s is not globally routable and must not count", s)
		}
	}
}

// Rule 4 of ip_learning: when a peer is reachable at two addresses, an upgrade
// to a better route class is taken immediately. This is what actually moves
// traffic off the fragile NAT'd path once the peer's v6 address is heard from.
func TestLearnUpgradesFromPublicV4ToIPv6(t *testing.T) {
	tbl := NewIPLearningTable()
	v4 := udp(t, "203.0.113.9:6969")
	v6 := udp(t, "[2600:1007:1131:ebb9::1]:6969")

	tbl.Learn("10.22.22.3", v4)
	if got := tbl.Lookup("10.22.22.3"); got == nil || got.String() != v4.String() {
		t.Fatalf("first route should be the v4 one, got %v", got)
	}

	// With no session table the rules fall through to last-writer-wins, so
	// assert the class comparison itself is the thing that decides.
	tbl.Learn("10.22.22.3", v6)
	if got := tbl.Lookup("10.22.22.3"); got == nil || got.String() != v6.String() {
		t.Errorf("hearing from the peer's IPv6 address must take over the route, got %v", got)
	}
}

// The default listen port must be stable for a node (so its NAT mapping and
// tracker records stay valid across restarts) and different between nodes (so
// several machines behind one router never contend for one external port).
func TestDerivedListenPortIsStableAndPerNode(t *testing.T) {
	var a, b [32]byte
	a[0], b[0] = 1, 2

	p1 := derivedListenPort(a, 0)
	if p1 != derivedListenPort(a, 0) {
		t.Errorf("the derived port must not change between calls for one key")
	}
	if p1 < listenPortBase || p1 >= listenPortBase+listenPortSpan {
		t.Errorf("derived port %d outside [%d,%d)", p1, listenPortBase, listenPortBase+listenPortSpan)
	}
	if p1 == derivedListenPort(b, 0) {
		t.Errorf("two different node keys must not derive the same port")
	}
	if p1 == derivedListenPort(a, 1) {
		t.Errorf("a retry must land on a different port, or the retry is pointless")
	}
	if derivedListenPort(a, 1) != derivedListenPort(a, 1) {
		t.Errorf("retry ports must be deterministic too, or the port moves every start")
	}
	if p1 == legacyDefaultPort {
		t.Errorf("derived ports must never collide with the old shared default")
	}
}

func TestExternalPortOf(t *testing.T) {
	for in, want := range map[string]int{
		"203.0.113.9:6969":              6969,
		"[2600:1007:1131:ebb9::1]:1071": 1071,
		"garbage":                       0,
		"":                              0,
	} {
		if got := externalPortOf(in); got != want {
			t.Errorf("externalPortOf(%q) = %d, want %d", in, got, want)
		}
	}
}

// Stale provisions from earlier installs of the same machine kept claiming its
// overlay address, so peers resolved that address to a key that no longer
// exists and the node received nothing while looking perfectly connected.
// put() already retired superseded claims as they arrived; nothing applied the
// rule to the records loaded from disk, which is where they actually lived.
func TestPruneSupersededAddressClaims(t *testing.T) {
	s := &provStore{recs: map[[32]byte]SignedProvision{}}

	key := func(b byte) ([32]byte, string) {
		var k [32]byte
		k[0] = b
		return k, base64.StdEncoding.EncodeToString(k[:])
	}
	oldest, oldestB64 := key(1)
	older, olderB64 := key(2)
	current, currentB64 := key(3)
	other, otherB64 := key(4)

	s.recs[oldest] = SignedProvision{PubKey: oldestB64, Address: "10.22.22.115/24", Name: "mac", Seq: 100}
	s.recs[older] = SignedProvision{PubKey: olderB64, Address: "10.22.22.115", Name: "mac", Seq: 200}
	s.recs[current] = SignedProvision{PubKey: currentB64, Address: "10.22.22.115/24", Name: "mac", Seq: 300}
	s.recs[other] = SignedProvision{PubKey: otherB64, Address: "10.22.22.7", Name: "zx7", Seq: 50}

	s.pruneSupersededAddresses()

	if len(s.recs) != 2 {
		t.Fatalf("expected 2 records to survive, got %d", len(s.recs))
	}
	if _, ok := s.recs[current]; !ok {
		t.Errorf("the newest claim on the address must survive")
	}
	if _, ok := s.recs[other]; !ok {
		t.Errorf("an unrelated address must be untouched")
	}
	for _, dead := range [][32]byte{oldest, older} {
		if _, ok := s.recs[dead]; ok {
			t.Errorf("a superseded claim on the same address must be dropped")
		}
	}

	// And it must be idempotent — this runs on every start.
	s.pruneSupersededAddresses()
	if len(s.recs) != 2 {
		t.Errorf("prune must be idempotent, got %d records on the second pass", len(s.recs))
	}
}

// A record with no address cannot conflict with anything and must be left
// alone (the store legitimately holds name-only provisions).
func TestPruneIgnoresAddresslessProvisions(t *testing.T) {
	s := &provStore{recs: map[[32]byte]SignedProvision{}}
	var a, b [32]byte
	a[0], b[0] = 9, 10
	s.recs[a] = SignedProvision{PubKey: "a", Address: "", Name: "ios", Seq: 1}
	s.recs[b] = SignedProvision{PubKey: "b", Address: "", Name: "k8s-node", Seq: 2}
	s.pruneSupersededAddresses()
	if len(s.recs) != 2 {
		t.Errorf("address-less provisions must not be pruned, got %d", len(s.recs))
	}
}

// The same device must never occupy two rows. Four sources feed the peer list
// and each dedupes only against the ones before it, which fails the moment a
// device's identity resolves differently in two of them — a re-provisioned
// address, or a relay row whose key could not be resolved at all. That is the
// "listed twice, once direct and once relayed" report.
func TestCollapseByDeviceKeepsTheRealPath(t *testing.T) {
	rows := []SessionInfo{
		{Remote: "203.0.113.9:6969", PubKey: "KEYA", KeyFP: "aaaa", OverlayIP: "10.22.22.53",
			Name: "", Established: true, Relayed: false, LastSeenUnix: 100},
		// Same device, reached through a relay under its OLD overlay address,
		// and carrying the name the direct row has not learned yet.
		{Remote: "relay/10.22.22.30", PubKey: "KEYA", KeyFP: "aaaa", OverlayIP: "10.22.22.30",
			Name: "phone", Established: false, Relayed: true, LastSeenUnix: 140},
		{Remote: "198.51.100.4:6969", PubKey: "KEYB", KeyFP: "bbbb", OverlayIP: "10.22.22.7",
			Established: true, Relayed: false, LastSeenUnix: 90},
	}
	got := collapseByDevice(rows)
	if len(got) != 2 {
		t.Fatalf("one row per device: want 2, got %d (%+v)", len(got), got)
	}
	if got[0].Relayed || got[0].Remote != "203.0.113.9:6969" {
		t.Errorf("the direct row must be the one kept, got %+v", got[0])
	}
	if got[0].Name != "phone" {
		t.Errorf("identity known only to the dropped row must be carried over, got name %q", got[0].Name)
	}
	if got[0].LastSeenUnix != 140 {
		t.Errorf("last-seen must be the newer of the two, got %d", got[0].LastSeenUnix)
	}
}

// Rows that share no key must not be merged just because both are keyless.
func TestCollapseByDeviceKeepsDistinctDevices(t *testing.T) {
	rows := []SessionInfo{
		{Remote: "relay/10.22.22.11", OverlayIP: "10.22.22.11", Relayed: true, LastSeenUnix: 10},
		{Remote: "relay/10.22.22.22", OverlayIP: "10.22.22.22", Relayed: true, LastSeenUnix: 11},
	}
	if got := collapseByDevice(rows); len(got) != 2 {
		t.Errorf("two different devices must stay two rows, got %d", len(got))
	}
}
