package overlaymobile

import (
	"bytes"
	"net"
)

// handleTransportPacket processes ONE inbound transport datagram.
//
// Extracted from the read loop so that relay-delivered frames can take the
// exact same path as directly received ones: relayclient.go assigns it to
// gTransportDeliver, and a frame arriving over a circuit is handed here
// attributed to the circuit's synthetic address. Without this split the relay
// would need a second copy of the decrypt/admission/deliver logic, which is
// precisely the kind of duplicate that drifts and then silently diverges.
func handleTransportPacket(pkt []byte, raddr *net.UDPAddr, kp keypair, psk []byte) {
	if len(pkt) < 1 {
		return
	}
	// STUN demux stays in the read loop (a relay circuit never carries STUN).
	// The overlay-type guard does NOT: a relay-delivered frame arrives here
	// without having passed the read loop's check, and an unrecognised type
	// byte must be dropped rather than fed to the session layer.
	if !isOverlayPacket(pkt[0]) {
		return
	}
	typ := pkt[0]
	body := pkt[1:]

	if GlobalSessions.deliverPacket(raddr, typ, body, kp, psk) {
		return
	}
	s := GlobalSessions.GetByAddr(raddr)
	if s == nil || !s.Established() {
		if typ == PktData && GlobalSessions.RoamData(raddr, body) {
			s = GlobalSessions.GetByAddr(raddr)
		}
		if s == nil || !s.Established() {
			return
		}
	}
	pt, err := recvPacket(s, body)
	if err != nil {
		// Single failures are garbage/forgery/replay — never evict on
		// one. NoteDecryptFailure tears down only when everything has
		// failed for multiple keepalive intervals (key desync), forcing
		// a clean re-handshake instead of a minute-long blackhole.
		logDecryptError(raddr.String(), err)
		GlobalSessions.NoteDecryptFailure(raddr)
		return
	}
	GlobalSessions.TouchLastSeen(raddr)
	// Post-quantum: peel the ML-KEM AEAD layer FIRST (once up we wrap all
	// frames on a direct session), so control + data dispatch correctly.
	if isPQPacket(pt) {
		if s := GlobalSessions.GetByAddr(raddr); s != nil {
			if inner, ok := pqUnwrap(s.peerStatic, pt); ok {
				pt = inner
			} else {
				return
			}
		} else {
			return
		}
	}
	if bytes.HasPrefix(pt, ctlMagic) {
		handleControl(pt[len(ctlMagic):], raddr)
		return
	}

	// ADMISSION CONTROL — data path only; control frames above are
	// deliberately exempt so an unapproved peer can still learn the
	// admin key and its own approval (approvals.go). Past this point a
	// peer that is not admitted gets nothing: no TUN delivery, no relay
	// transit, no ipLearning entry. Mirrors client/main.go.
	// No-op when no admin key is set (admissionRequired() == false).
	if s := GlobalSessions.GetByAddr(raddr); s == nil || !admissionOK(s.peerStatic, "ingress") {
		return
	}

	if len(pt) == 5 && pt[0] == 0x00 {
		srcIP := net.IPv4(pt[1], pt[2], pt[3], pt[4]).String()
		if srcIP == myOverlayIP {
			// A peer keepalive carrying OUR address: record the claim
			// against its key and let the resolver decide who moves.
			if s := GlobalSessions.GetByAddr(raddr); s != nil && s.Established() {
				setPeerOverlayIP(s.peerStatic, srcIP)
				resolveOverlayIPCollision("keepalive")
			}
			return
		}
		ipLearning.Learn(srcIP, raddr)
		if s := GlobalSessions.GetByAddr(raddr); s != nil {
			setPeerOverlayIP(s.peerStatic, srcIP)
		}
		return
	}
	if !isIPv4Packet(pt) {
		return
	}
	if ifIP := extractIPv4Src(pt); ifIP != "" {
		ipLearning.Learn(ifIP, raddr)
	}
	if myOverlayIP != "" {
		if dst := extractIPv4Dst(pt); dst != "" && dst != myOverlayIP {
			if amExit && isInternetDst(dst) {
				tunIF.Write(pt)
				return
			}
			// Relay transit for the RETURN path. When we relay an 'R'
			// frame, the destination learns "reach the sender via us"
			// and sends its replies back here as ORDINARY data frames
			// — but this branch used to just drop them, so relayed
			// connections passed exactly one packet and then went
			// dark. Forward one hop over a direct established
			// session, same rules as the 'R' handler: never to/from a
			// revoked node, and never back out the session it arrived
			// on (split horizon — no loops).
			if !isInternetDst(dst) &&
				!isOverlayIPRevoked(dst) && !isOverlayIPRevoked(extractIPv4Src(pt)) {
				if a := ipLearning.Lookup(dst); a != nil && a.String() != raddr.String() {
					// …and admitted: never relay onward into a pending
					// device. Mirrors client/main.go.
					if s := GlobalSessions.GetByAddr(a); s != nil && s.Established() && admissionOK(s.peerStatic, "relay-return") {
						_ = sendPacket(GlobalConn, a, s, pt)
					}
				}
			}
			return
		}
	}
	tunIF.Write(pt)
}
