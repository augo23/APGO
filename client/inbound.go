package main

// inbound.go tracks whether this node has ever accepted an UNSOLICITED
// handshake — the only direct evidence that its advertised endpoint is
// reachable from outside.
//
// Why this exists: "my peer is relayed" has many possible causes and they are
// indistinguishable from the peer list alone. But one of them dominates in
// practice — inbound UDP blocked by a firewall or security group — and it has
// a crisp signature: the node initiates every session it ever has, and is the
// responder for none. A node behind a well-behaved NAT still gets inbound
// handshakes (hole punching opens the mapping first); a node behind a DROP
// rule never does.
//
// The classic case in this project: a Kubernetes pod published on a hostPort.
// The DNAT rule delivers inbound packets correctly, so the pod IS reachable —
// but only if the node's firewall permits that port. When it does not, phones
// can never reach it (their only route to a pod behind a symmetric CNI
// masquerade is that published port), while desktops still connect over the
// mesh-nested path and everything LOOKS fine from a laptop.

import (
	"net"
	"sync"
	"time"
)

var (
	inboundMu   sync.Mutex
	inboundLast time.Time // zero = never
	inboundFrom string    // remote endpoint of the most recent inbound session
	inboundWAN  bool      // at least one inbound arrived from OFF-LAN
)

// noteInboundSession records that a peer completed a handshake toward us.
func noteInboundSession(addr *net.UDPAddr) {
	if addr == nil {
		return
	}
	// A LAN peer proves nothing about internet reachability — same-subnet
	// traffic never passes the firewall being diagnosed. Track it, but only
	// an OFF-LAN arrival sets the flag the dashboards act on.
	wan := !isAttachedLANAddr(addr) && !addr.IP.IsLoopback()
	inboundMu.Lock()
	inboundLast = time.Now()
	inboundFrom = addr.String()
	if wan {
		inboundWAN = true
	}
	inboundMu.Unlock()
}

// inboundStatus reports reachability evidence for /api/info:
//
//	ok    — an off-LAN peer has reached us (inbound works)
//	last  — unix time of the most recent inbound session (0 = never)
//	from  — that peer's endpoint
func inboundStatus() (ok bool, last int64, from string) {
	inboundMu.Lock()
	defer inboundMu.Unlock()
	if !inboundLast.IsZero() {
		last = inboundLast.Unix()
	}
	return inboundWAN, last, inboundFrom
}
