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
	"strconv"
	"strings"
)

// minLANPrefixLen is the widest subnet we will still call a "LAN". Anything
// broader than a /16 is not a local network — it is a misconfiguration or an
// ISP handing out an absurd netmask — and treating it as one would classify
// large swathes of the internet as directly attached. That matters because
// isPrivateUDPAddr feeds this into routing preference: a WAN peer wrongly
// judged "LAN" gets pinned as the primary route and blocks failover.
const minLANPrefixLen = 16

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
		ones, bits := n.Mask.Size()
		if bits != 32 || ones < minLANPrefixLen {
			continue
		}
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
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			eps = append(eps, s)
		}
	}
	for _, addr := range GlobalSessions.EstablishedAddrs() {
		if len(eps) >= 64 {
			break
		}
		// Same-host peer connected over loopback (static_peers pinning — see
		// docs/two-nodes-same-host.md, e.g. a second container in the host
		// netns that can't bind the LAN discovery port and is therefore mute
		// on the LAN). dst can't dial 127.0.0.1, but this peer shares OUR
		// host network namespace, so a same-site dst CAN reach it at our LAN
		// address(es) on the same port. Translate instead of dropping —
		// without this, a phone on the same Wi-Fi only ever finds such a
		// peer via the slow same-site hairpin ladder (minutes), even though
		// it is one LAN hop away the whole time.
		if includeLAN && addr.IP != nil && addr.IP.IsLoopback() {
			for _, n := range localIPv4Nets() {
				add(net.JoinHostPort(n.IP.String(), strconv.Itoa(addr.Port)))
			}
			continue
		}
		s := addr.String()
		if dst != nil && s == dst.String() {
			continue // don't hand a peer its own endpoint
		}
		// NEVER gossip an overlay-subnet endpoint, even to a same-site peer.
		// This is how a bad endpoint went viral: the attached-LAN allowance
		// below is satisfied by the OVERLAY interface itself on some hosts,
		// so one node that had dialled 10.x.overlay:port taught it to
		// everyone else, who dialled it, memorised it, and re-gossiped it.
		// The mesh then kept resurrecting an address no node actually owns,
		// long after the config that introduced it was corrected.
		if isOverlayTransportAddr(addr.IP) {
			continue
		}
		if !isValidPeer(s) && !(includeLAN && isAttachedLANAddr(addr)) {
			continue
		}
		add(s)
	}

	// OUR OWN IPv6 endpoints, gossiped to everyone.
	//
	// This is the only way a peer can learn them. The loop above shares each
	// session's CURRENT transport address, so a peer's v6 address is shared
	// only once the session already runs over v6 — circular. The other
	// discovery paths cannot carry it either: the BitTorrent tracker peer list
	// and the DHT are both compact-IPv4 formats by protocol. That left exactly
	// one carrier, the candidate list inside a coordinated-connect frame,
	// which is only exchanged between two nodes that have ALREADY found each
	// other over IPv4.
	//
	// So in practice every session started on IPv4 and, because a live route
	// is sticky, stayed there — a node with a perfectly good NAT-free IPv6
	// address spent its life hole-punching. Advertising ours here closes the
	// loop: any peer we can reach at all learns the address, dials it (the
	// receiver skips endpoints it is already connected to and damps the rest),
	// and routeClass then promotes the v6 path over the NAT'd one.
	//
	// Safe to hand to a peer that is already connected to us: the second
	// session to the same static key is kept as a backup route by design (see
	// sessions.go, "primary route ... backup route(s) kept for roaming
	// failover") and becomes primary only if it is genuinely the better class.
	if myUDPPort > 0 {
		for _, ep := range globalIPv6Endpoints(myUDPPort) {
			if dst != nil && ep == dst.String() {
				continue // never hand a peer its own endpoint
			}
			add(ep)
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
		// Same rule on receipt: an overlay address from a peer is never a
		// route we can use, whichever gossip path it arrived on.
		if isOverlayTransportAddr(addr.IP) {
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
