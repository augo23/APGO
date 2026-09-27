package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// --- packet helpers -----------------------------------------------------------

func pxTestPacket(proto byte, src, dst string, dport uint16, payload []byte) []byte {
	var l4 []byte
	switch proto {
	case 6:
		l4 = make([]byte, 20+len(payload))
		binary.BigEndian.PutUint16(l4[0:2], 40000)
		binary.BigEndian.PutUint16(l4[2:4], dport)
		l4[12] = 5 << 4
		l4[13] = 0x02 // SYN
		copy(l4[20:], payload)
	case 17:
		l4 = make([]byte, 8+len(payload))
		binary.BigEndian.PutUint16(l4[0:2], 40000)
		binary.BigEndian.PutUint16(l4[2:4], dport)
		binary.BigEndian.PutUint16(l4[4:6], uint16(len(l4)))
		copy(l4[8:], payload)
	case 1:
		l4 = make([]byte, 8+len(payload))
		l4[0] = 8 // echo request
		copy(l4[8:], payload)
	}
	p := make([]byte, 20+len(l4))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8], p[9] = 64, proto
	copy(p[12:16], net.ParseIP(src).To4())
	copy(p[16:20], net.ParseIP(dst).To4())
	copy(p[20:], l4)
	binary.BigEndian.PutUint16(p[10:12], pxChecksum(p[:20]))
	pxFixL4(p)
	return p
}

// pxFixL4 computes the transport checksum from scratch.
func pxFixL4(p []byte) {
	l4 := p[20:]
	switch p[9] {
	case 6, 17:
		off := 16
		if p[9] == 17 {
			off = 6
		}
		l4[off], l4[off+1] = 0, 0
		binary.BigEndian.PutUint16(l4[off:], pxL4Sum(p))
	case 1:
		l4[2], l4[3] = 0, 0
		binary.BigEndian.PutUint16(l4[2:4], pxChecksum(l4))
	}
}

func pxL4Sum(p []byte) uint16 {
	l4 := p[20:]
	pseudo := make([]byte, 0, 12+len(l4))
	pseudo = append(pseudo, p[12:20]...)
	pseudo = append(pseudo, 0, p[9])
	pseudo = binary.BigEndian.AppendUint16(pseudo, uint16(len(l4)))
	pseudo = append(pseudo, l4...)
	return pxChecksum(pseudo)
}

func pxChecksumsValid(t *testing.T, p []byte) {
	t.Helper()
	if pxChecksum(p[:20]) != 0 {
		t.Fatal("IP header checksum invalid")
	}
	switch p[9] {
	case 6, 17:
		if pxL4Sum(p) != 0 {
			t.Fatalf("transport checksum invalid (proto %d)", p[9])
		}
	case 1:
		if pxChecksum(p[20:]) != 0 {
			t.Fatal("ICMP checksum invalid")
		}
	}
}

func TestPxRewriteKeepsChecksumsValid(t *testing.T) {
	for _, proto := range []byte{6, 17, 1} {
		p := pxTestPacket(proto, "10.22.22.53", "93.184.216.34", 443, []byte("hello world, odd!"))
		pxChecksumsValid(t, p)
		if !pxRewrite(p, true, [4]byte{198, 18, 7, 9}) {
			t.Fatal("rewrite failed")
		}
		if !bytes.Equal(p[12:16], []byte{198, 18, 7, 9}) {
			t.Fatal("source not rewritten")
		}
		pxChecksumsValid(t, p)
		if !pxRewrite(p, false, [4]byte{10, 22, 22, 53}) {
			t.Fatal("rewrite failed")
		}
		pxChecksumsValid(t, p)
	}
}

func TestPxRewriteICMPErrorInnerHeader(t *testing.T) {
	// "fragmentation needed" from a router, quoting the client's packet (as
	// seen after NAT: source = the client's pool address).
	orig := pxTestPacket(6, "198.18.7.9", "93.184.216.34", 443, nil)
	icmp := make([]byte, 8+28)
	icmp[0], icmp[1] = 3, 4
	copy(icmp[8:], orig[:28])
	p := make([]byte, 20+len(icmp))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8], p[9] = 64, 1
	copy(p[12:16], net.ParseIP("93.184.216.1").To4())
	copy(p[16:20], net.ParseIP("198.18.7.9").To4())
	copy(p[20:], icmp)
	binary.BigEndian.PutUint16(p[10:12], pxChecksum(p[:20]))
	pxFixL4(p)
	if !pxRewrite(p, false, [4]byte{10, 22, 22, 53}) {
		t.Fatal("rewrite failed")
	}
	pxChecksumsValid(t, p)
	inner := p[28:]
	if !bytes.Equal(inner[12:16], []byte{10, 22, 22, 53}) {
		t.Fatal("quoted header not rewritten — path-MTU discovery would break")
	}
	if pxChecksum(inner[:20]) != 0 {
		t.Fatal("quoted header checksum invalid")
	}
}

func TestPxParseRejectsMalformed(t *testing.T) {
	good := pxTestPacket(17, "1.2.3.4", "5.6.7.8", 53, []byte("x"))
	bad := [][]byte{
		nil,
		good[:19],
		append(append([]byte(nil), good...), 0), // length mismatch
		func() []byte { b := append([]byte(nil), good...); b[0] = 0x44; return b }(), // IHL 16
		func() []byte { b := append([]byte(nil), good...); b[0] = 0x65; return b }(), // version 6
		pxTestPacket(6, "1.2.3.4", "5.6.7.8", 80, nil)[:30],                          // truncated TCP
	}
	for i, b := range bad {
		if len(b) >= 4 && i == len(bad)-1 {
			binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
		}
		if _, ok := pxParse(b); ok {
			t.Fatalf("malformed packet %d accepted", i)
		}
	}
}

func TestPxPublicAddressClassification(t *testing.T) {
	public := []string{"1.1.1.1", "8.8.8.8", "93.184.216.34", "100.128.0.1", "172.32.0.1", "198.20.0.1", "223.255.255.254"}
	private := []string{"0.1.2.3", "10.22.22.1", "100.64.0.1", "100.127.3.3", "127.0.0.1", "169.254.1.1",
		"172.16.0.1", "172.31.255.255", "192.0.0.8", "192.0.2.1", "192.168.1.1", "198.18.0.1", "198.19.255.1",
		"198.51.100.2", "203.0.113.9", "224.0.0.1", "239.1.2.3", "240.0.0.1", "255.255.255.255"}
	for _, s := range public {
		var a [4]byte
		copy(a[:], net.ParseIP(s).To4())
		if !pxIsPublicIPv4(a) {
			t.Errorf("%s should be public", s)
		}
	}
	for _, s := range private {
		var a [4]byte
		copy(a[:], net.ParseIP(s).To4())
		if pxIsPublicIPv4(a) {
			t.Errorf("%s must not be reachable through a public exit", s)
		}
	}
	for _, c := range pxPoolCandidates {
		ip, _, _ := net.ParseCIDR(c)
		var a [4]byte
		copy(a[:], ip.To4())
		if pxIsPublicIPv4(a) {
			t.Errorf("pool %s must not be a public destination", c)
		}
	}
}

// --- end to end, in process ----------------------------------------------------

type pxTestRig struct {
	t      *testing.T
	tun    *captureTUN
	srv    *pxServer
	cli    *pxClient
	sConn  *net.UDPConn
	cConn  *net.UDPConn
	sAddr  *net.UDPAddr
	selfIP string
}

func newPxTestRig(t *testing.T) *pxTestRig {
	t.Helper()
	self := testKeypair(t)
	tun := testNode(t, self, []byte("my-network-psk"))
	sConn, cConn := udpListen(t), udpListen(t)
	GlobalConn = cConn
	static, err := pxNewStatic()
	if err != nil {
		t.Fatal(err)
	}
	_, pool, _ := net.ParseCIDR("198.18.0.0/16")
	srv := &pxServer{
		conn: sConn, static: static,
		limits:     newBandwidthLimiter(0, 0, 0, 30, ""),
		pending:    map[uint32]*pxPending{},
		sessions:   map[uint32]*pxSrvSession{},
		byPool:     map[[4]byte]*pxSrvSession{},
		perSource:  map[string]int{},
		pool:       pool,
		poolBase:   binary.BigEndian.Uint32(pool.IP.To4()),
		poolSize:   65534,
		natReady:   true,
		maxClients: 4, maxPerSrc: 2, clientBps: 0,
		hellos: newPxRate(100, 100),
	}
	srv.setBlockedPorts(nil)
	srv.enabled.Store(true)
	cli := &pxClient{cands: map[string]*pxCand{}, attempts: map[string]*pxAttempt{}, bySID: map[uint32]*pxAttempt{}}
	oldSrv, oldCli, oldUse, oldPin, oldHook := gPubExit, gPxClient, pxUsePublic.Load(), currentExitPin(), pxOnActive
	gPubExit, gPxClient = srv, cli
	pxOnActive = func() {}
	pxUsePublic.Store(true)
	useExitFlag.Store(true)
	setExitPin("public")
	t.Cleanup(func() {
		gPubExit, gPxClient = oldSrv, oldCli
		pxOnActive = oldHook
		pxUsePublic.Store(oldUse)
		setExitPin(oldPin)
	})
	return &pxTestRig{t: t, tun: tun, srv: srv, cli: cli, sConn: sConn, cConn: cConn,
		sAddr: sConn.LocalAddr().(*net.UDPAddr), selfIP: myOverlayIP()}
}

// pump delivers every datagram waiting on conn to the demux; it returns the
// raw datagrams too.
func (r *pxTestRig) pump(conn *net.UDPConn) [][]byte {
	var out [][]byte
	buf := make([]byte, 65535)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return out
		}
		d := append([]byte(nil), buf[:n]...)
		out = append(out, d)
		handlePubExitPacket(d, from)
	}
}

func (r *pxTestRig) connect() *pxActive {
	r.t.Helper()
	r.cli.AddCandidate(r.sAddr.String())
	r.cli.startAttempt(r.sAddr.String())
	for i := 0; i < 4; i++ {
		r.pump(r.sConn)
		r.pump(r.cConn)
		r.cli.mu.Lock()
		act := r.cli.active
		r.cli.mu.Unlock()
		if act != nil {
			return act
		}
	}
	r.t.Fatal("public exit session did not come up")
	return nil
}

func TestPublicExitEndToEnd(t *testing.T) {
	r := newPxTestRig(t)
	act := r.connect()
	if pxIsPublicIPv4(act.poolIP) || !r.srv.pool.Contains(net.IP(act.poolIP[:])) {
		t.Fatalf("bad pool address %v", act.poolIP)
	}
	if !pxActiveReady() {
		t.Fatal("client not ready")
	}

	// Outbound: internet destination, forged source -> leaves as pool address.
	out := pxTestPacket(6, "10.9.9.9", "93.184.216.34", 443, []byte("GET /"))
	if !pxClientSend(out) {
		t.Fatal("not sent")
	}
	r.pump(r.sConn)
	got := r.tun.got()
	if len(got) != 1 {
		t.Fatalf("exit wrote %d packets, want 1", len(got))
	}
	if !bytes.Equal(got[0][12:16], act.poolIP[:]) {
		t.Fatal("source was not replaced with the client's pool address (spoofing possible)")
	}
	pxChecksumsValid(t, got[0])

	// A private destination never even leaves the client.
	if !pxClientSend(pxTestPacket(17, r.selfIP, "192.168.1.1", 53, nil)) {
		t.Fatal("expected the packet to be consumed")
	}
	if d := r.pump(r.sConn); len(d) != 0 {
		t.Fatal("client sent private-range traffic to a stranger")
	}

	// Return path: internet -> pool address -> client, delivered to its own IP.
	back := pxTestPacket(6, "93.184.216.34", "0.0.0.0", 40000, []byte("200 OK"))
	copy(back[16:20], act.poolIP[:])
	binary.BigEndian.PutUint16(back[10:12], 0)
	binary.BigEndian.PutUint16(back[10:12], pxChecksum(back[:20]))
	pxFixL4(back)
	if !pubExitFromTUN(back) {
		t.Fatal("pool traffic not taken by the public exit")
	}
	r.pump(r.cConn)
	got = r.tun.got()
	if len(got) != 2 {
		t.Fatalf("client delivered %d packets, want 1 more", len(got)-1)
	}
	if net.IP(got[1][16:20]).String() != r.selfIP {
		t.Fatalf("reply not addressed to the client's own IP: %v", net.IP(got[1][16:20]))
	}
	pxChecksumsValid(t, got[1])

	// A reply claiming a private source is not forwarded to the client.
	spoof := pxTestPacket(17, "10.0.0.1", "0.0.0.0", 53, nil)
	copy(spoof[16:20], act.poolIP[:])
	if !pubExitFromTUN(spoof) {
		t.Fatal("pool traffic not taken")
	}
	if d := r.pump(r.cConn); len(d) != 0 {
		t.Fatal("exit forwarded a private-source packet")
	}
	// Traffic for addresses outside the pool is left to the overlay.
	if pubExitFromTUN(pxTestPacket(17, "8.8.8.8", "10.22.0.9", 53, nil)) {
		t.Fatal("non-pool traffic was captured")
	}
}

func TestPublicExitFilter(t *testing.T) {
	r := newPxTestRig(t)
	r.connect()
	r.srv.selfMu.Lock()
	r.srv.selfIPs = map[[4]byte]bool{{93, 184, 216, 99}: true}
	r.srv.selfSeen = time.Now()
	r.srv.selfMu.Unlock()
	var ss *pxSrvSession
	r.srv.mu.Lock()
	for _, s := range r.srv.sessions {
		ss = s
	}
	r.srv.mu.Unlock()

	blocked := [][]byte{
		pxTestPacket(6, "1.1.1.1", "10.22.0.5", 22, nil),        // overlay
		pxTestPacket(6, "1.1.1.1", "192.168.0.1", 80, nil),      // LAN
		pxTestPacket(6, "1.1.1.1", "127.0.0.1", 80, nil),        // loopback
		pxTestPacket(17, "1.1.1.1", "169.254.169.254", 80, nil), // cloud metadata
		pxTestPacket(6, "1.1.1.1", "93.184.216.99", 22, nil),    // the exit host itself
		pxTestPacket(6, "1.1.1.1", "93.184.216.34", 25, nil),    // SMTP
		pxTestPacket(17, "1.1.1.1", "255.255.255.255", 67, nil),
		pxTestPacket(17, "1.1.1.1", "224.0.0.251", 5353, nil),
		func() []byte { // GRE
			p := pxTestPacket(17, "1.1.1.1", "93.184.216.34", 1, nil)
			p[9] = 47
			return p
		}(),
		func() []byte { // ICMP redirect
			p := pxTestPacket(1, "1.1.1.1", "93.184.216.34", 0, nil)
			p[20] = 5
			return p
		}(),
		func() []byte {
			// IP OPTIONS: a loose-source-route header aimed at a public
			// address. Forwarding it would let a client pick the next hop and
			// use this exit as a reflector, so the header length alone is
			// enough to refuse the packet.
			base := pxTestPacket(6, "1.1.1.1", "93.184.216.34", 443, nil)
			opt := []byte{0x83, 7, 4, 10, 0, 0, 1} // LSRR -> 10.0.0.1
			p := append([]byte(nil), base[:20]...)
			p = append(p, opt...)
			p = append(p, 0)            // pad to a 4-byte boundary
			p = append(p, base[20:]...) // the original L4 payload
			p[0] = 4<<4 | 6             // IHL = 6 words (24 bytes)
			binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
			return p
		}(),
	}
	for i, p := range blocked {
		before := len(r.tun.got())
		r.srv.fromClient(ss, p)
		if len(r.tun.got()) != before {
			t.Errorf("blocked packet %d reached the OS", i)
		}
	}
	allowed := [][]byte{
		pxTestPacket(6, "1.1.1.1", "93.184.216.34", 443, nil),
		pxTestPacket(17, "1.1.1.1", "8.8.8.8", 53, nil),
		pxTestPacket(1, "1.1.1.1", "8.8.8.8", 0, nil),
	}
	for i, p := range allowed {
		before := len(r.tun.got())
		r.srv.fromClient(ss, p)
		if len(r.tun.got()) != before+1 {
			t.Errorf("allowed packet %d was dropped", i)
		}
	}

	// New-flow rate: a port scan is cut off after the burst.
	before := len(r.tun.got())
	for port := 1000; port < 1000+pxNewFlowsBurst+100; port++ {
		r.srv.fromClient(ss, pxTestPacket(6, "1.1.1.1", "93.184.216.34", uint16(port), nil))
	}
	if n := len(r.tun.got()) - before; n > pxNewFlowsBurst+5 {
		t.Fatalf("%d new flows passed; the burst is %d", n, pxNewFlowsBurst)
	}
}

func TestPublicExitRejectsReplayAndForgery(t *testing.T) {
	r := newPxTestRig(t)
	act := r.connect()
	pkt := pxTestPacket(17, r.selfIP, "8.8.8.8", 53, []byte("q"))
	dgram := act.ch.seal(pxInPacket, pkt)
	cAddr := r.cConn.LocalAddr().(*net.UDPAddr)
	before := len(r.tun.got())
	handlePubExitPacket(dgram, cAddr)
	handlePubExitPacket(dgram, cAddr) // replay
	if n := len(r.tun.got()) - before; n != 1 {
		t.Fatalf("replayed datagram delivered %d times", n)
	}
	forged := act.ch.seal(pxInPacket, pkt)
	forged[len(forged)-1] ^= 1
	handlePubExitPacket(forged, cAddr)
	if n := len(r.tun.got()) - before; n != 1 {
		t.Fatal("forged datagram accepted")
	}
}

func TestPublicExitHandshakeLimits(t *testing.T) {
	r := newPxTestRig(t)
	cAddr := r.cConn.LocalAddr().(*net.UDPAddr)

	// Wrong-size hellos get no answer at all (no amplification, no oracle).
	for _, n := range []int{10, pxHelloSize - 1, pxHelloSize + 1} {
		b := make([]byte, n)
		b[0], b[1], b[2] = PktPubExit, pxHello, pxVersion
		handlePubExitPacket(b, cAddr)
	}
	if d := r.pump(r.cConn); len(d) != 0 {
		t.Fatal("answered a malformed hello")
	}

	// Disabled: a correctly sized hello gets a 3-byte refusal, never more.
	r.srv.enabled.Store(false)
	b := make([]byte, pxHelloSize)
	b[0], b[1], b[2] = PktPubExit, pxHello, pxVersion
	handlePubExitPacket(b, cAddr)
	d := r.pump(r.cConn)
	if len(d) != 1 || len(d[0]) != 3 || d[0][1] != pxDeny || d[0][2] != pxDenyDisabled {
		t.Fatalf("disabled exit reply: %v", d)
	}
	r.srv.enabled.Store(true)

	// Replies are always smaller than the hello.
	r.cli.startAttempt(r.sAddr.String())
	for _, dg := range r.pump(r.sConn) {
		_ = dg
	}
	for _, dg := range r.pump(r.cConn) {
		if len(dg) >= pxHelloSize {
			t.Fatalf("reply of %d bytes to a %d-byte hello", len(dg), pxHelloSize)
		}
	}

	// Per-source cap: a third concurrent handshake from one address is refused.
	r.srv.mu.Lock()
	r.srv.perSource[cAddr.IP.String()] = r.srv.maxPerSrc
	r.srv.mu.Unlock()
	r.cli.mu.Lock()
	r.cli.attempts = map[string]*pxAttempt{}
	r.cli.bySID = map[uint32]*pxAttempt{}
	r.cli.mu.Unlock()
	r.cli.startAttempt(r.sAddr.String())
	r.pump(r.sConn)
	denied := false
	for _, dg := range r.pump(r.cConn) {
		if dg[1] == pxDeny && len(dg) == 3 && dg[2] == pxDenyRate {
			denied = true
		}
		if dg[1] == pxHelloReply {
			t.Fatal("a handshake beyond the per-source cap was answered")
		}
	}
	if !denied {
		t.Fatal("per-source cap not enforced")
	}
}

func TestPublicExitPrerequisites(t *testing.T) {
	oldDHT, oldRelay := gDHT, gPublicRelay
	t.Cleanup(func() { gDHT, gPublicRelay = oldDHT, oldRelay })
	gDHT, gPublicRelay = nil, nil
	s := &pxServer{limits: newBandwidthLimiter(0, 0, 0, 30, "")}
	if err := s.SetEnabled(true); err == nil || s.enabled.Load() {
		t.Fatal("public exit enabled without the DHT and a public relay")
	}
}

func TestInternalExitPreferredOverPublic(t *testing.T) {
	r := newPxTestRig(t)
	setExitPin("")
	now := time.Now()
	r.cli.mu.Lock()
	defer r.cli.mu.Unlock()
	if r.cli.wanted(now, false, true) {
		t.Fatal("public exit wanted while an internal exit is available")
	}
	if r.cli.wanted(now, false, false) {
		t.Fatal("public exit wanted before the grace period")
	}
	if !r.cli.wanted(now.Add(pxClientGrace), false, false) {
		t.Fatal("public exit not wanted after the grace period")
	}
	pxUsePublic.Store(false)
	if r.cli.wanted(now.Add(time.Hour), true, false) {
		t.Fatal("public exit used although not allowed")
	}
}
