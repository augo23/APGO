package main

import (
	"net"
	"testing"
)

// A probe is only answered by a member of the network: the MAC is keyed by the
// PSK, and probe and reply are domain-separated so one cannot be replayed as
// the other.
func TestSprayFrameAuthentication(t *testing.T) {
	psk := []byte("network-psk-0123456789")
	f := buildSprayFrame(psk, sprayProbe, []byte("12345678"))
	body := f[len(ctlMagic):]

	kind, nonce, ok := parseSprayFrame(body, psk)
	if !ok || kind != sprayProbe || string(nonce) != "12345678" {
		t.Fatalf("valid probe rejected: ok=%v kind=%d", ok, kind)
	}
	if len(f) != len(ctlMagic)+sprayFrameLen {
		t.Fatalf("frame is %d bytes; probe and reply must be the same fixed size", len(f))
	}
	if _, _, ok := parseSprayFrame(body, []byte("a different network")); ok {
		t.Fatal("a probe from outside the network was accepted")
	}
	// Same nonce, relabelled as a reply: the MAC covers the kind, so this is
	// not a valid reply and cannot be used to fake "your spray landed".
	forged := append([]byte(nil), body...)
	forged[1] = sprayReply
	if _, _, ok := parseSprayFrame(forged, psk); ok {
		t.Fatal("a probe relabelled as a reply was accepted")
	}
	// Truncated, over-long and wrong-letter frames are all rejected.
	for _, bad := range [][]byte{body[:len(body)-1], append(append([]byte(nil), body...), 0),
		append([]byte{'x'}, body[1:]...)} {
		if _, _, ok := parseSprayFrame(bad, psk); ok {
			t.Fatalf("malformed frame accepted: % x", bad)
		}
	}
	// The reply to a probe is exactly as long as the probe: no amplification.
	if len(buildSprayFrame(psk, sprayReply, nonce)) != len(f) {
		t.Fatal("reply length differs from probe length")
	}
}

func TestSprayPortsAreDistinctAndInRange(t *testing.T) {
	ports := sprayPorts(natSprayPorts)
	if len(ports) != natSprayPorts {
		t.Fatalf("got %d ports, want %d", len(ports), natSprayPorts)
	}
	seen := map[int]bool{}
	for _, p := range ports {
		if p < natSprayPortLo || p > natSprayPortHi {
			t.Fatalf("port %d outside the sprayed range", p)
		}
		if seen[p] {
			t.Fatalf("port %d drawn twice in one round", p)
		}
		seen[p] = true
	}
	// Two rounds must not cover the same ground, or extra rounds buy nothing.
	second := sprayPorts(natSprayPorts)
	overlap := 0
	for _, p := range second {
		if seen[p] {
			overlap++
		}
	}
	if overlap > natSprayPorts/2 {
		t.Fatalf("%d of %d ports repeated between rounds — rounds must explore new ports", overlap, natSprayPorts)
	}
}

// Only the pairing that is otherwise relayed forever, and only when we know
// both classes. Two symmetric NATs are left alone: neither side knows an
// address on the other that its mappings could be aimed at.
func TestSprayRoleSelection(t *testing.T) {
	cands := "192.168.1.5:6969,203.0.113.7:41234,nat=sym"
	for _, tc := range []struct {
		mine, theirs string
		want         bool
	}{
		{natSymmetric, natStable, true},
		{natStable, natSymmetric, true},
		{natSymmetric, natSymmetric, false},
		{natStable, natStable, false},
		{natUnknown, natSymmetric, false},
		{natSymmetric, natUnknown, false},
	} {
		started := false
		if ep := peerPublicEndpoint(cands); ep != nil {
			switch {
			case tc.mine == natSymmetric && tc.theirs == natStable,
				tc.mine == natStable && tc.theirs == natSymmetric:
				started = true
			}
		}
		if started != tc.want {
			t.Errorf("mine=%s theirs=%s: spray started=%v, want %v", tc.mine, tc.theirs, started, tc.want)
		}
	}
}

// The peer's public candidate is the only one either half can aim at: a LAN
// address behind its NAT is not reachable from here and has no mapping.
func TestPeerPublicEndpoint(t *testing.T) {
	ep := peerPublicEndpoint("10.0.0.5:6969,192.168.1.9:6969,198.51.100.4:33445,nat=sym")
	if ep == nil || ep.String() != "198.51.100.4:33445" {
		t.Fatalf("picked %v, want the public candidate", ep)
	}
	if ep := peerPublicEndpoint("10.0.0.5:6969,nat=sym"); ep != nil {
		t.Fatalf("picked %v from private-only candidates", ep)
	}
}

// A promoted socket must carry everything for that peer: a frame sent from the
// main socket leaves through a different external port, which the peer's
// restricted NAT drops.
func TestPunchPathRoutesThatPeerOnly(t *testing.T) {
	aux, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer aux.Close()
	peer := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 4), Port: 33445}
	other := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 9), Port: 6969}

	if c := punchPathFor(peer); c != nil {
		t.Fatal("a peer with no punched path must use the main socket")
	}
	registerPunchPath(peer, aux)
	defer dropPunchPath(peer.String())

	if c := punchPathFor(peer); c != aux {
		t.Fatal("the punched peer must be routed through its own socket")
	}
	if c := punchPathFor(other); c != nil {
		t.Fatal("another peer must not be routed through it")
	}
	if c := punchPathFor(nil); c != nil {
		t.Fatal("a nil address must not select a socket")
	}
	dropPunchPath(peer.String())
	if c := punchPathFor(peer); c != nil {
		t.Fatal("a dropped path must fall back to the main socket")
	}
}

// OFF unless a node opts in. It shipped on-by-default, a fleet had a bad
// night, and the relay it replaces works — so the default is the safe one.
func TestSprayIsOptIn(t *testing.T) {
	if natSprayEnabled.Load() {
		t.Fatal("nat spray must default to off")
	}
	natSprayEnabled.Store(true)
	defer natSprayEnabled.Store(false)
	// With it off, nothing starts even for the pairing it exists for.
	natSprayEnabled.Store(false)
	before := len(gNATSpray.active)
	maybeStartNATSpray("10.0.0.2", "203.0.113.7:41234,nat=sym", natStable, natSymmetric)
	if len(gNATSpray.active) != before {
		t.Fatal("an attempt started while the feature is off")
	}
}

// A peer behind OUR OWN NAT must never be sprayed: that address is our router's
// WAN side, the probes hairpin back into the house, and the ordinary punch
// already reaches such a peer over the LAN.
func TestSprayRefusesSameSite(t *testing.T) {
	mu.Lock()
	saved := lastPublicIP
	lastPublicIP = "203.0.113.7:6969"
	mu.Unlock()
	defer func() { mu.Lock(); lastPublicIP = saved; mu.Unlock() }()

	if !sameSiteCandidates("192.168.1.9:6969,203.0.113.7:41234,nat=sym") {
		t.Fatal("a peer sharing our public address was not recognised as same-site")
	}
	if sameSiteCandidates("198.51.100.4:33445,nat=sym") {
		t.Fatal("a peer at another site was treated as same-site")
	}

	natSprayEnabled.Store(true)
	defer natSprayEnabled.Store(false)
	before := len(gNATSpray.active)
	maybeStartNATSpray("10.0.0.9", "203.0.113.7:41234,nat=sym", natStable, natSymmetric)
	if len(gNATSpray.active) != before {
		t.Fatal("an attempt started toward a peer behind our own NAT")
	}
}

// Spray frames are plaintext datagrams, not session payloads: they must be
// recognised straight off the wire, from a peer with no session. Routing them
// through the control-frame path (which only sees decrypted payloads) left
// every probe that landed on a main socket unanswered.
func TestSprayFramesAreRecognisedOnTheWire(t *testing.T) {
	f := buildSprayFrame([]byte("psk"), sprayProbe, []byte("abcdefgh"))
	if !isNATSprayDatagram(f) {
		t.Fatal("a spray datagram was not recognised on the wire")
	}
	for _, bad := range [][]byte{
		f[:len(f)-1],                         // truncated
		append(append([]byte(nil), f...), 0), // padded
		append([]byte("OVLYCTL1"), 'C'),      // a different control letter
		{0x01, 0x02, 0x03},                   // an overlay frame
	} {
		if isNATSprayDatagram(bad) {
			t.Fatalf("non-spray datagram recognised: % x", bad)
		}
	}
}

// The TTL cap is what makes the technique work at all (see natspray.go): the
// ladder must start low enough to be safe and never exceed the cap.
func TestProbeTTLLadderStaysShort(t *testing.T) {
	if natSprayTTLBase < 1 || natSprayTTLBase > 2 {
		t.Fatalf("ttl ladder starts at %d: it must approach from the safe side", natSprayTTLBase)
	}
	if natSprayTTLMax > 5 {
		t.Fatalf("ttl cap %d is high enough to reach a peer's NAT and poison its source port", natSprayTTLMax)
	}
	if natSprayPathTTL <= natSprayTTLMax {
		t.Fatal("a promoted socket must get an ordinary TTL, or its session dies in transit")
	}
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := setProbeTTL(c, natSprayTTLBase); err != nil {
		t.Fatalf("setting the probe TTL failed: %v", err)
	}
	if err := setProbeTTL(c, natSprayPathTTL); err != nil {
		t.Fatalf("restoring the path TTL failed: %v", err)
	}
}
