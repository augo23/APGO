package main

// datastats.go counts what actually happens to data packets, so "I can see the
// peers but cannot reach anything" stops being a guessing game.
//
// The peer list only proves that CONTROL frames flow — sessions form, names and
// rosters gossip. Reaching a service needs the DATA path, and every way it can
// fail looks identical from the peer list:
//
//	tx_direct == 0 && tx_flood > 0   we never learned a route to that peer, so
//	                                 every packet is being broadcast blindly
//	tx_* > 0 && rx_data == 0         we are sending and nothing comes back:
//	                                 one-way path (NAT/firewall on the far side)
//	rx_replay_drop climbing          packets arrive but are rejected as replays
//	                                 (reordering beyond the anti-replay window)
//	rx_decrypt_fail climbing         key desync — the session needs re-handshake
//	rx_delivered > 0                 data really is reaching the OS tunnel; the
//	                                 problem is above us (routing/app/MTU)
//
// Counters are cheap atomics on the hot path and are read only when a UI asks.

import (
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
	"sync/atomic"
)

var (
	statTxDirect      atomic.Uint64 // sent straight to a known route
	statTxFlood       atomic.Uint64 // no route known: broadcast to every peer
	statRxData        atomic.Uint64 // inbound data frames that authenticated
	statRxDelivered   atomic.Uint64 // written into the OS tunnel (reached the app)
	statRxRelayed     atomic.Uint64 // delivered via a relay frame addressed to us
	statRxReplayDrop  atomic.Uint64 // rejected by the anti-replay window
	statRxDecryptFail atomic.Uint64 // failed to decrypt (key desync / forgery)

	// SEND FAILURES. tx_direct/tx_flood count ATTEMPTS: the egress path
	// discards sendPacket's error and increments regardless. So a node whose
	// every write is being rejected by the kernel reports a healthy, climbing
	// transmit count while emitting nothing at all — which is indistinguishable
	// from "we send and they ignore us", and sends you looking at the far end.
	//
	// The case that motivated this: an IPv6 dual-stack socket writing to IPv4
	// peers. It works on Linux and can be refused on macOS, so the same build
	// transmits fine on one and silently drops everything on the other.
	statTxError atomic.Uint64

	// --- WHY a decrypted frame was not delivered ------------------------------
	//
	// rx_data climbing while rx_delivered stays at zero is the single most
	// confusing state this client can be in, and until now it was also the least
	// explicable: every rejection on the receive path is a bare `return`, so
	// thousands of frames could vanish without a counter, a log line, or any way
	// to tell WHICH rejection swallowed them. Diagnosing it meant guessing at
	// the ladder in order and testing each guess against a live mesh.
	//
	// These name every exit from that ladder. They are exhaustive by
	// construction: rx_data must equal rx_ctl + the drops below + rx_relay_out +
	// rx_delivered. If that identity does not hold, a path is missing a counter.
	statRxCtl          atomic.Uint64 // control frame (gossip/keepalive) — never reaches the TUN
	statRxDropNoSess   atomic.Uint64 // decrypted, but the session vanished underneath us
	statRxDropAdmit    atomic.Uint64 // blocked by admission control (peer not approved HERE)
	statRxDropPQ       atomic.Uint64 // ML-KEM layer could not open it (PQ generation mismatch)
	statRxDropNotIPv4  atomic.Uint64 // plaintext was not an IPv4 packet (noop/padding/garbage)
	statRxDropNotForUs atomic.Uint64 // addressed to another overlay IP and not relayable
	statRxDropRevoked  atomic.Uint64 // source or destination is revoked
	statRxRelayOut     atomic.Uint64 // forwarded one hop on someone else's behalf
	statRxKeepalive    atomic.Uint64 // overlay-IP keepalive ([0x00][ipv4])
)

// --- WHO are the undelivered frames addressed to? ---------------------------
//
// rx_drop_not_for_us counts frames addressed to some other overlay IP, but the
// count alone cannot distinguish the two cases that matter, and they call for
// opposite fixes:
//
//	normal transit  — a handful of destinations, all other nodes, because this
//	                  node sits on a path between them;
//	WRONG ADDRESS   — one destination, over and over, which is almost always
//	                  THIS machine's PREVIOUS overlay address. Peers reply to
//	                  the source they saw, so if packets leave carrying a stale
//	                  address (a leftover interface still holding it, say),
//	                  every reply comes back addressed to an IP this node no
//	                  longer answers to and is dropped here, silently.
//
// The second case is invisible without naming the destination — it looks
// exactly like "the tunnel is dead". So record the top few.
var (
	notForUsMu   sync.Mutex
	notForUsSeen = map[string]uint64{}
)

func noteNotForUs(dst string) {
	if dst == "" {
		return
	}
	notForUsMu.Lock()
	// Bounded: this is fed by the receive path, and an unbounded map keyed by
	// attacker-chosen destinations is a memory leak with a nice interface.
	if len(notForUsSeen) < 32 || notForUsSeen[dst] > 0 {
		notForUsSeen[dst]++
	}
	notForUsMu.Unlock()
}

// notForUsTop returns the most-seen misaddressed destinations, highest first.
func notForUsTop(n int) []map[string]any {
	notForUsMu.Lock()
	type kv struct {
		k string
		v uint64
	}
	all := make([]kv, 0, len(notForUsSeen))
	for k, v := range notForUsSeen {
		all = append(all, kv{k, v})
	}
	notForUsMu.Unlock()
	sort.Slice(all, func(i, j int) bool { return all[i].v > all[j].v })
	if len(all) > n {
		all = all[:n]
	}
	out := make([]map[string]any, 0, len(all))
	for _, e := range all {
		out = append(out, map[string]any{"dst": e.k, "count": e.v})
	}
	return out
}

// dataStats snapshots the counters for the status API.
func dataStats() map[string]any {
	return map[string]any{
		"tx_direct":       statTxDirect.Load(),
		"tx_flood":        statTxFlood.Load(),
		"rx_data":         statRxData.Load(),
		"rx_delivered":    statRxDelivered.Load(),
		"rx_relayed":      statRxRelayed.Load(),
		"rx_replay_drop":  statRxReplayDrop.Load(),
		"rx_decrypt_fail": statRxDecryptFail.Load(),
		"tx_error":        statTxError.Load(),

		// Drop reasons. Exactly one of these (or rx_delivered) accounts for
		// every frame counted in rx_data.
		"rx_ctl":             statRxCtl.Load(),
		"rx_keepalive":       statRxKeepalive.Load(),
		"rx_drop_no_session": statRxDropNoSess.Load(),
		"rx_drop_admission":  statRxDropAdmit.Load(),
		"rx_drop_pq_unwrap":  statRxDropPQ.Load(),
		"rx_drop_not_ipv4":   statRxDropNotIPv4.Load(),
		"rx_drop_not_for_us": statRxDropNotForUs.Load(),
		"rx_drop_revoked":    statRxDropRevoked.Load(),
		"rx_relay_out":       statRxRelayOut.Load(),

		// The destinations those undelivered frames were actually addressed
		// to. One dominant entry that is not this node's address is the
		// answer, not a hint.
		"rx_not_for_us_top": notForUsTop(5),

		// rx_data counts every frame that DECRYPTED, which includes control
		// frames and keepalives -- statRxData is incremented before the
		// ctlMagic branch. So rx_ctl and rx_keepalive are SUBSETS of rx_data,
		// not siblings, and rx_data minus them is the real overlay payload.
		// Reading them as siblings makes it look like thousands of frames are
		// vanishing unaccounted; this field removes the ambiguity.
		"rx_payload_est": payloadEstimate(),
	}
}

// dataPathVerdict turns the counters into the one sentence an operator needs.
// Reading nine numbers correctly is a skill; being told "every frame is being
// dropped because this peer is not approved here" is not.
func dataPathVerdict() string {
	// Checked FIRST. If our own sends are failing, nothing else in these
	// counters means what it appears to mean.
	if e := statTxError.Load(); e > 0 {
		tx := statTxDirect.Load() + statTxFlood.Load()
		if tx > 0 && e*2 >= tx {
			return fmt.Sprintf("OUR OWN SENDS ARE FAILING — %d of %d writes to the UDP socket "+
				"were rejected by the kernel. Nothing is leaving this machine. If the socket is "+
				"IPv6 dual-stack and the peers are IPv4, set ipv6: false and reconnect", e, tx)
		}
		return fmt.Sprintf("%d send(s) failed at the socket — see the log for the error text", e)
	}
	// Checked before any counter is interpreted, because when it is true every
	// other number here is a red herring.
	//
	// An unapproved node is not a broken node. Peers that enforce admission
	// accept its CONTROL traffic by design -- that is how it learns the admin
	// key and its own approval record -- and silently discard every DATA
	// frame. So sessions establish, keepalives flow, rx_ctl climbs, routes are
	// learned, sends succeed, and not one byte of overlay data moves in either
	// direction. Outbound looks broken too, because the far side drops the
	// request and therefore never generates a reply.
	//
	// Every counter-based verdict below will confidently blame something else:
	// a handful of stale post-quantum frames reads as "the ML-KEM layer is
	// desynced", transit frames read as "this node is only a relay". Diagnosing
	// this from the counters alone cost a very long debugging session; the
	// answer was in the log the entire time, one line a minute, and the verdict
	// line -- the thing an operator actually reads -- never mentioned it.
	if !selfApproved() {
		return "THIS DEVICE IS NOT APPROVED on this network (key " +
			peerKeyFingerprint(gKP.pub[:]) + "). Peers accept our control traffic but " +
			"DISCARD ALL DATA, so both directions fail while every session looks " +
			"healthy. Nothing below is wrong. Approve this key in the admin panel."
	}
	rx := statRxData.Load()
	if rx == 0 {
		if statTxDirect.Load()+statTxFlood.Load() > 0 {
			return "sending, but nothing is coming back — one-way path (NAT/firewall on the far side)"
		}
		return "no data traffic yet"
	}
	if statRxDelivered.Load() > 0 {
		return "data is reaching the OS tunnel normally"
	}
	// Frames arrive but none are delivered: name the dominant reason.
	type reason struct {
		n   uint64
		why string
	}
	worst := reason{}
	for _, r := range []reason{
		{statRxDropAdmit.Load(), "every data frame is being DROPPED BY ADMISSION CONTROL — those peers are not approved on THIS node"},
		{statRxDropPQ.Load(), "every data frame fails the post-quantum unwrap — the ML-KEM layer is keyed to a session generation that no longer exists; disable post_quantum or force a re-handshake"},
		{statRxDropNotForUs.Load(), "data frames arrive addressed to OTHER overlay IPs — this node is being used as a transit path, and nothing is addressed to it"},
		{statRxDropRevoked.Load(), "data frames are being dropped as revoked"},
		{statRxDropNotIPv4.Load(), "decrypted plaintext is not IPv4 — framing/compression mismatch between builds"},
		{statRxDropNoSess.Load(), "the session disappears between decrypt and delivery"},
	} {
		if r.n > worst.n {
			worst = r
		}
	}
	if worst.n > 0 {
		return worst.why
	}
	// Control frames and keepalives are NOT data. Comparing rx_ctl alone
	// against rx_data missed this case whenever a single keepalive had arrived,
	// which is always — and the verdict fell through to "no counted reason"
	// precisely when it had the most useful thing to say.
	if statRxCtl.Load()+statRxKeepalive.Load() >= rx-4 {
		return "only CONTROL traffic is arriving — no peer is sending this node any overlay data. " +
			"If tx_flood far exceeds tx_direct, no routes are resolving in either direction: " +
			"check for a DUPLICATE claim on this node's overlay IP (provisions bound to another key)"
	}
	return "data frames arrive but none are delivered, for no counted reason (please report)"
}

// noteSendError counts a failed transmit and logs the first few with the exact
// kernel error, rate-limited. The error TEXT is the diagnosis here — "no route
// to host", "address family not supported", "message too long" and "operation
// not permitted" call for four completely different fixes, and a bare counter
// distinguishes none of them.
var (
	sendErrMu   sync.Mutex
	sendErrSeen = map[string]int{}
)

func noteSendError(where string, addr *net.UDPAddr, err error) {
	statTxError.Add(1)
	if err == nil {
		return
	}
	key := where + "|" + err.Error()
	sendErrMu.Lock()
	n := sendErrSeen[key]
	sendErrSeen[key] = n + 1
	sendErrMu.Unlock()
	// First three of each distinct error, then every thousandth.
	if n < 3 || n%1000 == 0 {
		log.Printf("[transport] SEND FAILED (%s) to %s: %v — nothing left this machine for that packet", where, addr, err)
	}
}

// payloadEstimate is rx_data with the control-plane subsets removed: an
// estimate of how many frames carried actual overlay payload. Clamped at zero
// because the counters are sampled independently and can cross momentarily.
func payloadEstimate() uint64 {
	rx := statRxData.Load()
	ctl := statRxCtl.Load() + statRxKeepalive.Load()
	if ctl >= rx {
		return 0
	}
	return rx - ctl
}

// logTunWriteError reports failures to write a delivered frame into the OS
// tunnel, rate-limited to the first few of each distinct error.
//
// Silence here is what made the missing-delivery bug so hard to see: a receive
// path that drops packets without a counter or a log is indistinguishable from
// a network that is not delivering any.
var (
	tunWriteErrMu   sync.Mutex
	tunWriteErrSeen = map[string]int{}
)

func logTunWriteError(err error) {
	if err == nil {
		return
	}
	key := err.Error()
	tunWriteErrMu.Lock()
	tunWriteErrSeen[key]++
	n := tunWriteErrSeen[key]
	tunWriteErrMu.Unlock()
	if n <= 3 {
		log.Printf("[tun] WRITE FAILED (delivered frame did not reach the OS tunnel): %v", err)
	}
}
