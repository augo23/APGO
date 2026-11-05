package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// --- helpers ----------------------------------------------------------------

const (
	tcpSYN = 0x02
	tcpACK = 0x10

	svcIP  = "10.22.22.22"
	selfIP = "10.22.22.115"
	homeIP = "10.22.22.11" // a copy on the client's own site
	farIP  = "10.22.22.7"  // a copy across the WAN
)

// testPkt builds an IPv4 TCP/UDP packet with valid checksums and a payload.
func testPkt(proto byte, src, dst string, sport, dport uint16, tcpFlags byte) []byte {
	hdr := 20
	if proto == protoUDP {
		hdr = 8
	}
	payload := []byte("hello, replica")
	p := make([]byte, 20+hdr+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8] = 64
	p[9] = proto
	copy(p[12:16], net.ParseIP(src).To4())
	copy(p[16:20], net.ParseIP(dst).To4())
	binary.BigEndian.PutUint16(p[20:22], sport)
	binary.BigEndian.PutUint16(p[22:24], dport)
	switch proto {
	case protoTCP:
		p[20+12] = 5 << 4
		p[20+13] = tcpFlags
	case protoUDP:
		binary.BigEndian.PutUint16(p[24:26], uint16(8+len(payload)))
	}
	copy(p[20+hdr:], payload)
	binary.BigEndian.PutUint16(p[10:12], fullCsum(p[:20], 0))
	if proto == protoTCP || proto == protoUDP {
		binary.BigEndian.PutUint16(p[20+l4CsumOff(proto):], l4Csum(p))
	}
	return p
}

func l4CsumOff(proto byte) int {
	if proto == protoUDP {
		return 6
	}
	return 16
}

func fullCsum(b []byte, acc uint32) uint16 {
	for i := 0; i+1 < len(b); i += 2 {
		acc += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		acc += uint32(b[len(b)-1]) << 8
	}
	for acc>>16 != 0 {
		acc = acc&0xffff + acc>>16
	}
	return ^uint16(acc)
}

// l4Csum computes the TCP/UDP checksum from scratch, with the checksum field
// treated as zero.
func l4Csum(p []byte) uint16 {
	seg := append([]byte(nil), p[20:]...)
	seg[l4CsumOff(p[9])], seg[l4CsumOff(p[9])+1] = 0, 0
	var acc uint32
	for i := 12; i < 20; i += 2 {
		acc += uint32(binary.BigEndian.Uint16(p[i:]))
	}
	acc += uint32(p[9]) + uint32(len(seg))
	return fullCsum(seg, acc)
}

func checksumsValid(t *testing.T, p []byte) {
	t.Helper()
	if fullCsum(p[:20], 0) != 0 {
		t.Errorf("IPv4 header checksum invalid")
	}
	if got, want := binary.BigEndian.Uint16(p[20+l4CsumOff(p[9]):]), l4Csum(p); got != want {
		t.Errorf("L4 checksum = %#04x, want %#04x", got, want)
	}
}

func pubFor(ip string) (k [32]byte) {
	copy(k[:], ip)
	return k
}

// resetReplicas installs test hooks: every address in reachable has a usable
// direct session whose key is pubFor(address).
func resetReplicas(t *testing.T, reachable ...string) {
	t.Helper()
	oldCIDR, oldSelf := overlayCIDR, myOverlayIP()
	oldPath, oldOwner, oldDial := replicaPath, replicaOwnerOK, replicaDial
	overlayCIDR = "10.22.22.0/24"
	setMyOverlayIP(selfIP)
	setReachable(reachable...)
	replicaOwnerOK = func(pub [32]byte, ip string) bool { return pub == pubFor(ip) }
	clear := func() {
		repMu.Lock()
		repServices = map[string]*replicaSet{}
		repPreferred = map[string]string{}
		repRTT = map[[32]byte]*rttSample{}
		repFlows = map[flowKey]*replicaFlow{}
		repReplies = map[replyKey]*replicaFlow{}
		rebuildRepKnownLocked()
		repMu.Unlock()
		repRedirecting.Store(false)
		ownerMu.Lock()
		ownerPorts, ownerNodes, ownerHealthy = nil, nil, map[string]bool{}
		ownerMu.Unlock()
	}
	clear()
	t.Cleanup(func() {
		clear()
		overlayCIDR = oldCIDR
		setMyOverlayIP(oldSelf)
		replicaPath, replicaOwnerOK, replicaDial = oldPath, oldOwner, oldDial
	})
}

func setReachable(ips ...string) {
	ok := map[string]bool{}
	for _, ip := range ips {
		ok[ip] = true
	}
	replicaPath = func(ip string) ([32]byte, *net.UDPAddr, *session, bool) {
		if !ok[ip] {
			return [32]byte{}, nil, nil, false
		}
		return pubFor(ip), &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 6970}, &session{}, true
	}
}

func announceFrom(sender, payload string) {
	handleReplicaAnnounce(pubFor(sender), append([]byte{replicaAnnounceVersion}, payload...))
}

// setRTT registers a candidate's measured RTT, as the probe loop + pongs do.
func setRTT(ip string, ms float64) {
	repMu.Lock()
	repRTT[pubFor(ip)] = &rttSample{ms: ms}
	repMu.Unlock()
}

func send(t *testing.T, sport uint16, flags byte) ([]byte, string, bool) {
	t.Helper()
	p := testPkt(protoTCP, selfIP, svcIP, sport, 443, flags)
	node, ok := replicaRewriteOut(p, svcIP)
	return p, node, ok
}

// --- parsing ----------------------------------------------------------------

func TestReplicaPortsParseAndCanonical(t *testing.T) {
	m, err := parseReplicaPorts(" udp/53, TCP/443 = 6943 ,tcp/80=6980")
	if err != nil {
		t.Fatal(err)
	}
	if got := m.String(); got != "tcp/80=6980,tcp/443=6943,udp/53=53" {
		t.Errorf("canonical = %q", got)
	}
	for _, bad := range []string{"", ",", "80", "tcp/0", "tcp/70000", "icmp/1", "tcp/x", "tcp/443=0", "tcp/443=x"} {
		if _, err := parseReplicaPorts(bad); err == nil {
			t.Errorf("parseReplicaPorts(%q) accepted", bad)
		}
	}
}

func TestParseNodeList(t *testing.T) {
	resetReplicas(t)
	got := parseNodeList([]string{"10.22.22.7, 10.22.22.11 10.22.22.7", "8.8.8.8,junk,10.22.22.22"}, svcIP)
	if fmt.Sprint(got) != "[10.22.22.7 10.22.22.11]" {
		t.Errorf("got %v: want overlay addresses only, deduped, without the service address", got)
	}
}

func TestParseFlow(t *testing.T) {
	k, ok, syn := parseFlow(testPkt(protoTCP, selfIP, svcIP, 50000, 443, tcpSYN))
	if !ok || !syn || k.dport != 443 || k.sport != 50000 || k.proto != protoTCP {
		t.Fatalf("tcp syn: %+v ok=%v syn=%v", k, ok, syn)
	}
	if _, ok, syn := parseFlow(testPkt(protoTCP, selfIP, svcIP, 50000, 443, tcpSYN|tcpACK)); !ok || syn {
		t.Error("SYN-ACK must not count as a new connection")
	}
	if _, ok, _ := parseFlow(testPkt(1, selfIP, svcIP, 0, 0, 0)); ok {
		t.Error("icmp has no ports")
	}
	for name, bits := range map[string]uint16{"non-first fragment": 185, "first fragment (MF)": 0x2000} {
		p := testPkt(protoTCP, selfIP, svcIP, 1, 443, 0)
		binary.BigEndian.PutUint16(p[6:8], bits)
		if _, ok, _ := parseFlow(p); ok {
			t.Errorf("%s must not be treated as a flow", name)
		}
	}
	dfOnly := testPkt(protoTCP, selfIP, svcIP, 1, 443, 0)
	binary.BigEndian.PutUint16(dfOnly[6:8], 0x4000)
	if _, ok, _ := parseFlow(dfOnly); !ok {
		t.Error("DF alone is not fragmentation")
	}
}

// --- rewriting --------------------------------------------------------------

func TestRewriteKeepsChecksumsValid(t *testing.T) {
	node, _ := ipv4To4(farIP)
	svc, _ := ipv4To4(svcIP)
	for _, proto := range []byte{protoTCP, protoUDP} {
		p := testPkt(proto, selfIP, svcIP, 50123, 443, tcpSYN)
		checksumsValid(t, p)
		rewriteAddrPort(p, true, node, 6943)
		if extractIPv4Dst(p) != farIP || binary.BigEndian.Uint16(p[22:24]) != 6943 {
			t.Fatalf("proto %d: destination not rewritten", proto)
		}
		checksumsValid(t, p)

		r := testPkt(proto, farIP, selfIP, 6943, 50123, tcpSYN|tcpACK)
		rewriteAddrPort(r, false, svc, 443)
		if extractIPv4Src(r) != svcIP || binary.BigEndian.Uint16(r[20:22]) != 443 {
			t.Fatalf("proto %d: source not rewritten", proto)
		}
		checksumsValid(t, r)
	}
	// UDP without a checksum stays without one.
	u := testPkt(protoUDP, selfIP, svcIP, 5000, 53, 0)
	u[26], u[27] = 0, 0
	rewriteAddrPort(u, true, node, 5353)
	if u[26] != 0 || u[27] != 0 {
		t.Error("zero UDP checksum must stay zero")
	}
}

// --- announces --------------------------------------------------------------

func TestAnnounceOnlyFromTheOwner(t *testing.T) {
	resetReplicas(t, svcIP, homeIP)
	announceFrom(homeIP, svcIP+"|tcp/443=6943|"+farIP) // a node that is not 10.22.22.22
	if isReplicatedService(svcIP) {
		t.Fatal("copies announced by a key that is not the node at the address were accepted")
	}
	handleReplicaAnnounce(pubFor(svcIP), append([]byte{1}, svcIP+"=tcp/443"...))
	if isReplicatedService(svcIP) {
		t.Fatal("a version-1 (retired anycast) announce was accepted")
	}
	announceFrom(svcIP, svcIP+"|tcp/443=6943|"+homeIP+","+farIP+",8.8.8.8,"+svcIP)
	if !isReplicatedService(svcIP) {
		t.Fatal("owner's announce not accepted")
	}
	repMu.Lock()
	nodes := fmt.Sprint(repServices[svcIP].nodes)
	repMu.Unlock()
	if nodes != "["+homeIP+" "+farIP+"]" {
		t.Errorf("nodes = %s: non-overlay addresses and the service address itself must be dropped", nodes)
	}
	announceFrom(svcIP, svcIP+"|tcp/443=6943|")
	if isReplicatedService(svcIP) {
		t.Error("an announce with no healthy copies must stop the redirect at once")
	}
}

// --- routing ----------------------------------------------------------------

func TestPicksFastestKeepsConnectionsAndRewritesReplies(t *testing.T) {
	resetReplicas(t, svcIP, homeIP, farIP)
	announceFrom(svcIP, svcIP+"|tcp/80=6980,tcp/443=6943|"+homeIP+","+farIP)
	setRTT(svcIP, 80)
	setRTT(homeIP, 2)
	setRTT(farIP, 40)

	p, node, ok := send(t, 1000, tcpSYN)
	if !ok || node != homeIP {
		t.Fatalf("SYN went to %q (ok=%v), want the fastest copy %s", node, ok, homeIP)
	}
	if extractIPv4Dst(p) != homeIP || binary.BigEndian.Uint16(p[22:24]) != 6943 {
		t.Fatal("packet not rewritten to the copy's address and port")
	}
	checksumsValid(t, p)

	// The reply from the copy comes back as a reply from 10.22.22.22:443.
	r := testPkt(protoTCP, homeIP, selfIP, 6943, 1000, tcpSYN|tcpACK)
	if !replicaRewriteIn(r) || extractIPv4Src(r) != svcIP || binary.BigEndian.Uint16(r[20:22]) != 443 {
		t.Fatal("reply from the copy not rewritten back to the service address")
	}
	checksumsValid(t, r)

	// The connection stays on its node even after another becomes faster.
	setRTT(farIP, 1)
	if _, node, _ := send(t, 1000, tcpACK); node != homeIP {
		t.Errorf("established connection moved to %q", node)
	}
	// A new connection still respects hysteresis: 1 ms vs 2 ms is not
	// "clearly faster".
	if _, node, _ := send(t, 1001, tcpSYN); node != homeIP {
		t.Errorf("new connection went to %q despite hysteresis", node)
	}
}

func TestReplyRewriteOnlyForOwnConnections(t *testing.T) {
	resetReplicas(t, svcIP, homeIP)
	announceFrom(svcIP, svcIP+"|tcp/443=6943|"+homeIP)
	setRTT(svcIP, 80)
	setRTT(homeIP, 2)
	if _, node, _ := send(t, 2000, tcpSYN); node != homeIP {
		t.Fatalf("setup: SYN went to %q", node)
	}
	for name, p := range map[string][]byte{
		"other local port":  testPkt(protoTCP, homeIP, selfIP, 6943, 2001, tcpACK),
		"other node port":   testPkt(protoTCP, homeIP, selfIP, 22, 2000, tcpACK),
		"other node":        testPkt(protoTCP, farIP, selfIP, 6943, 2000, tcpACK),
		"other protocol":    testPkt(protoUDP, homeIP, selfIP, 6943, 2000, 0),
		"to someone else":   testPkt(protoTCP, homeIP, "10.22.22.9", 6943, 2000, tcpACK),
		"plain node packet": testPkt(protoTCP, homeIP, selfIP, 6980, 2000, tcpACK),
	} {
		before := string(p)
		if replicaRewriteIn(p) || string(p) != before {
			t.Errorf("%s: rewritten, but it is not a reply to a connection we redirected", name)
		}
	}
}

func TestOwnerStaysWhenFastestOrOnlyChoice(t *testing.T) {
	resetReplicas(t, svcIP, homeIP, farIP)
	announceFrom(svcIP, svcIP+"|tcp/443=6943|"+homeIP+","+farIP)
	setRTT(svcIP, 1)
	setRTT(homeIP, 30)
	setRTT(farIP, 60)
	p, _, ok := send(t, 3000, tcpSYN)
	if ok || extractIPv4Dst(p) != svcIP {
		t.Fatal("owner is fastest: packet must go to it untouched")
	}
	// The connection stays on the owner too.
	setRTT(homeIP, 0)
	if _, _, ok := send(t, 3000, tcpACK); ok {
		t.Error("connection on the owner was moved mid-stream")
	}
}

func TestFallsBackToOwner(t *testing.T) {
	resetReplicas(t, svcIP, homeIP)
	announceFrom(svcIP, svcIP+"|tcp/443=6943|"+homeIP)
	setRTT(svcIP, 80)
	setRTT(homeIP, 2)
	for name, p := range map[string][]byte{
		"admin port 81": testPkt(protoTCP, selfIP, svcIP, 1, 81, tcpSYN),
		"udp/443":       testPkt(protoUDP, selfIP, svcIP, 1, 443, 0),
		"icmp":          testPkt(1, selfIP, svcIP, 0, 0, 0),
		"other address": testPkt(protoTCP, selfIP, "10.22.22.23", 1, 443, tcpSYN),
	} {
		dst := extractIPv4Dst(p)
		if _, ok := replicaRewriteOut(p, dst); ok {
			t.Errorf("%s: redirected, want the ordinary owner path", name)
		}
	}
	// Copy unreachable (no direct live session): owner.
	setReachable(svcIP)
	if _, _, ok := send(t, 4000, tcpSYN); ok {
		t.Error("redirected to a copy with no usable session")
	}
	// An established connection whose copy became unreachable is re-placed.
	setReachable(svcIP, homeIP)
	if _, node, _ := send(t, 4001, tcpSYN); node != homeIP {
		t.Fatalf("setup: got %q", node)
	}
	setReachable(svcIP)
	if _, _, ok := send(t, 4001, tcpACK); ok {
		t.Error("kept sending to a copy that became unreachable")
	}
}

func TestWithdrawnCopyKeepsOpenConnections(t *testing.T) {
	resetReplicas(t, svcIP, homeIP)
	announceFrom(svcIP, svcIP+"|tcp/443=6943|"+homeIP)
	setRTT(svcIP, 80)
	setRTT(homeIP, 2)
	if _, node, _ := send(t, 7000, tcpSYN); node != homeIP {
		t.Fatalf("setup: SYN went to %q", node)
	}
	announceFrom(svcIP, svcIP+"|tcp/443=6943|") // owner's health check blipped
	if _, node, ok := send(t, 7000, tcpACK); !ok || node != homeIP {
		t.Errorf("open connection moved off its copy (%q, ok=%v): withdrawal must only steer new connections", node, ok)
	}
	r := testPkt(protoTCP, homeIP, selfIP, 6943, 7000, tcpACK)
	if !replicaRewriteIn(r) || extractIPv4Src(r) != svcIP {
		t.Error("replies on the open connection must still be rewritten")
	}
	if _, _, ok := send(t, 7001, tcpSYN); ok {
		t.Error("new connection used a withdrawn copy")
	}
	// Once the open connection's flow expires, the address stops costing
	// anything on the hot path.
	repMu.Lock()
	for _, f := range repFlows {
		f.last = time.Now().Add(-2 * replicaFlowIdleTCP)
	}
	pruneReplicaFlowsLocked(time.Now(), false)
	rebuildRepKnownLocked()
	repMu.Unlock()
	if isReplicatedService(svcIP) {
		t.Error("address still on the hot path with no copies and no open connections")
	}
}

func TestNeverRedirectsToSelf(t *testing.T) {
	resetReplicas(t, svcIP, selfIP)
	announceFrom(svcIP, svcIP+"|tcp/443=6943|"+selfIP)
	setRTT(svcIP, 80)
	setRTT(selfIP, 0)
	if _, _, ok := send(t, 5000, tcpSYN); ok {
		t.Error("redirected to this node's own address")
	}
}

func TestStaleAnnounceExpires(t *testing.T) {
	resetReplicas(t, svcIP, homeIP)
	announceFrom(svcIP, svcIP+"|tcp/443=6943|"+homeIP)
	setRTT(homeIP, 1)
	repMu.Lock()
	repServices[svcIP].lastSeen = time.Now().Add(-2 * replicaAnnounceTTL())
	repMu.Unlock()
	if _, _, ok := send(t, 6000, tcpSYN); ok {
		t.Error("stale announce still used")
	}
}

// --- owner side -------------------------------------------------------------

func TestOwnerAnnouncesOnlyHealthyCopies(t *testing.T) {
	resetReplicas(t)
	setMyOverlayIP(svcIP)
	var mu sync.Mutex
	dialed := map[string]bool{}
	replicaDial = func(addr string, _ time.Duration) error {
		mu.Lock()
		dialed[addr] = true
		mu.Unlock()
		if addr == net.JoinHostPort(farIP, "6943") {
			return errors.New("refused")
		}
		return nil
	}
	ownerMu.Lock()
	ownerPorts, _ = parseReplicaPorts("tcp/443=6943, tcp/80=6980")
	ownerNodes = parseNodeList([]string{homeIP + " " + farIP}, svcIP)
	ownerMu.Unlock()
	runReplicaHealthChecks()
	if !dialed[net.JoinHostPort(homeIP, "6980")] || !dialed[net.JoinHostPort(homeIP, "6943")] {
		t.Errorf("health check must dial every mapped TCP port; dialed %v", dialed)
	}
	f := buildReplicaAnnounce()
	want := string(ctlMagic) + "I\x02" + svcIP + "|tcp/80=6980,tcp/443=6943|" + homeIP
	if string(f) != want {
		t.Errorf("announce = %q, want %q", f, want)
	}
	// The receiving side round-trips it.
	setReachable(svcIP, homeIP)
	handleReplicaAnnounce(pubFor(svcIP), f[len(ctlMagic)+1:])
	if !isReplicatedService(svcIP) {
		t.Error("client did not accept the owner's own announce")
	}
}

func TestNoAnnounceWithoutConfig(t *testing.T) {
	resetReplicas(t)
	if buildReplicaAnnounce() != nil {
		t.Error("a node with no replica settings must announce nothing")
	}
}

// --- concurrency ------------------------------------------------------------

func TestReplicasConcurrentUse(t *testing.T) {
	resetReplicas(t, svcIP, homeIP, farIP)
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 300; i++ {
				announceFrom(svcIP, svcIP+"|tcp/443=6943|"+homeIP+","+farIP)
				noteReplicaRTT(pubFor(homeIP), int64(i%7))
				p := testPkt(protoTCP, selfIP, svcIP, uint16(g*1000+i), 443, tcpSYN)
				if node, ok := replicaRewriteOut(p, svcIP); ok {
					r := testPkt(protoTCP, node, selfIP, 6943, uint16(g*1000+i), tcpACK)
					replicaRewriteIn(r)
				}
				_ = replicaStatus()
				_ = replicaSelfCheckLines()
			}
		}(g)
	}
	wg.Wait()
}
