package main

// pex.go is endpoint peer-exchange (PEX): nodes share the endpoints of the
// peers they're connected to, so a node that has fewer connections than the
// rest of the mesh catches up immediately from whichever peer it reached
// first, instead of waiting for the next tracker/rendezvous cycle.
//
//	OVLYCTL1 X <ep1,ep2,...>   — "here are the peers I'm connected to"
//
// We reply with our list whenever a peer announces itself (right after a
// handshake), and re-share it on the keepalive tick, so a newly-joined node
// learns the whole mesh within a round-trip of its first connection.
//
// PUBLIC endpoints are always shared. LAN endpoints are shared only with
// peers that are themselves on one of our directly-attached subnets, and
// accepted only when they land on one of the receiver's attached subnets.
// They used to be dropped unconditionally ("useless to a peer on a different
// network") — true for internet peers, but it starved SAME-SITE discovery: a
// phone rejoining Wi-Fi reached the always-on nodes instantly (stable public
// endpoints), yet could only learn a laptop's LAN-only endpoint from the
// slow unicast sweep. Now the first LAN peer it reaches hands it every other
// LAN peer within one round-trip.

import (
	"net"
	"strings"
)

// isAttachedLANAddr reports whether a is an IPv4 address on one of our
// directly-attached subnets — i.e. dialable without any NAT traversal.
func isAttachedLANAddr(a *net.UDPAddr) bool {
	if a == nil {
		return false
	}
	ip := a.IP.To4()
	if ip == nil {
		return false
	}
	for _, n := range localIPv4Nets() {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// buildPeerExchangeFor returns a peer-exchange frame tailored to dst: the
// public endpoints of our established sessions, plus their LAN endpoints when
// dst is on one of our attached subnets (same site — so those endpoints are
// dialable for it too). Returns nil if there is nothing to share.
func buildPeerExchangeFor(dst *net.UDPAddr) []byte {
	if GlobalSessions == nil {
		return nil
	}
	includeLAN := isAttachedLANAddr(dst)
	var eps []string
	seen := map[string]bool{}
	for _, addr := range GlobalSessions.EstablishedAddrs() {
		s := addr.String()
		if dst != nil && s == dst.String() {
			continue // don't hand a peer its own endpoint
		}
		if seen[s] {
			continue
		}
		if !isValidPeer(s) && !(includeLAN && isAttachedLANAddr(addr)) {
			continue
		}
		seen[s] = true
		eps = append(eps, s)
		if len(eps) >= 64 {
			break
		}
	}
	if len(eps) == 0 {
		return nil
	}
	out := append([]byte(nil), ctlMagic...)
	out = append(out, 'X')
	return append(out, []byte(strings.Join(eps, ","))...)
}

// handlePeerExchange dials any shared peer we're not already connected to:
// public endpoints always, LAN endpoints only when they're on one of OUR
// attached subnets (a same-site peer shared them; they're directly dialable).
func handlePeerExchange(payload []byte, kp keypair, psk []byte) {
	self := currentPublicEndpoint()
	selfIPs := map[string]bool{}
	for _, ip := range localInterfaceIPs() {
		selfIPs[ip] = true
	}
	for _, ep := range strings.Split(string(payload), ",") {
		ep = strings.TrimSpace(ep)
		if ep == "" || isSelf(ep, self, 0) {
			continue
		}
		addr, _ := net.ResolveUDPAddr("udp", ep)
		if addr == nil {
			continue
		}
		if !isValidPeer(ep) && !isAttachedLANAddr(addr) {
			continue
		}
		// Never dial ourselves — a same-site peer's list includes OUR LAN
		// endpoint exactly as it sees it.
		if selfIPs[addr.IP.String()] && addr.Port == myUDPPort {
			continue
		}
		if s := GlobalSessions.GetByAddr(addr); s != nil && s.Established() {
			continue
		}
		if GlobalSessions.ShouldSkip(addr) {
			continue
		}
		addKnownPeer(ep)
		go connectToPeer(ep, kp, psk)
	}
}

// sendPeerExchangeTo shares our peer list with a single peer (used right after
// a peer announces itself, so a new node learns the mesh immediately).
func sendPeerExchangeTo(raddr *net.UDPAddr) {
	frame := buildPeerExchangeFor(raddr)
	if frame == nil || GlobalConn == nil {
		return
	}
	if s := GlobalSessions.GetByAddr(raddr); s != nil && s.Established() {
		_ = sendPacket(GlobalConn, raddr, s, frame)
	}
}
