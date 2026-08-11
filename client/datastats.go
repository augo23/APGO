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

import "sync/atomic"

var (
	statTxDirect      atomic.Uint64 // sent straight to a known route
	statTxFlood       atomic.Uint64 // no route known: broadcast to every peer
	statRxData        atomic.Uint64 // inbound data frames that authenticated
	statRxDelivered   atomic.Uint64 // written into the OS tunnel (reached the app)
	statRxRelayed     atomic.Uint64 // delivered via a relay frame addressed to us
	statRxReplayDrop  atomic.Uint64 // rejected by the anti-replay window
	statRxDecryptFail atomic.Uint64 // failed to decrypt (key desync / forgery)
)

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
	}
}
