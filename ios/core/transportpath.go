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
				pqHealOpened(s.peerStatic)
			} else {
				// A run of these renegotiates the layer (pqheal.go).
				pqHealUnopenable(s.peerStatic, raddr)
				return
			}
		} else {
			return
		}
	} else if s := GlobalSessions.GetByAddr(raddr); s != nil {
		pqHealClassical(s.peerStatic, raddr, pt)
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
	s = GlobalSessions.GetByAddr(raddr)
	if s == nil || !admissionOK(s.peerStatic, "ingress") {
		return
	}

	if len(pt) == 5 && pt[0] == 0x00 {
		srcIP := net.IPv4(pt[1], pt[2], pt[3], pt[4]).String()
		if srcIP == myOverlayIP {
			// A peer keepalive carrying OUR address: record the claim
			// against its key and let the resolver decide who moves — only
			// if the claim is provable (ipbinding.go).
			if s.Established() {
				if !ipBindings.OwnedBy(s.peerStatic, srcIP, false) {
					statRxDropIPBinding.Add(1)
					ipBindings.noteRejected(s.peerStatic, srcIP)
					return
				}
				setPeerOverlayIP(s.peerStatic, srcIP)
				resolveOverlayIPCollision("keepalive")
			}
			return
		}
		if !ipBindings.OwnedBy(s.peerStatic, srcIP, true) {
			statRxDropIPBinding.Add(1)
			return
		}
		ipLearning.Learn(srcIP, raddr)
		notePeerAddress(s.peerStatic, srcIP)
		return
	}
	if !isIPv4Packet(pt) {
		return
	}
	// SOURCE-ADDRESS BINDING: a peer may only send from an overlay address
	// its key owns (or, as our exit, from internet addresses).
	ifIP := extractIPv4Src(pt)
	if !sourceAllowedFrom(s.peerStatic, ifIP) {
		statRxDropIPBinding.Add(1)
		return
	}
	if inOverlaySubnet(ifIP) {
		ipLearning.Learn(ifIP, raddr)
	}
	if myOverlayIP != "" {
		if dst := extractIPv4Dst(pt); dst != "" && dst != myOverlayIP {
			if amExit && isInternetDst(dst) {
				// Internet only — never into this exit's private networks
				// unless EXIT_ALLOW_LAN (exit.go).
				if exitForwardAllowed(dst) {
					tunIF.Write(pt)
				}
				return
			}
			// Plaintext data addressed to another overlay node is never
			// forwarded: relayed traffic travels only as end-to-end sealed
			// 'Z' frames (e2erelay.go). Mirrors client/main.go.
			return
		}
	}
	tunIF.Write(pt)
}
