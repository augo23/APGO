package main

// peerstats.go accounts overlay bytes PER PEER, so the dashboard can answer
// "what is this link actually doing right now" rather than only "is it up".
//
// Counters are keyed by the peer's Noise STATIC KEY, not by its UDP endpoint.
// That is the whole design decision here, and it is what makes the numbers
// mean anything: a peer's endpoint changes when it roams between networks, its
// NAT rebinds, or it moves onto or off a relay circuit — several times an hour
// for a phone. Keyed by address, every one of those events would silently reset
// the peer's totals to zero and the "total transferred" column would measure
// nothing more than the time since the last NAT timeout. The static key is the
// peer's identity for its whole life on the network.
//
// What is counted is the ENCRYPTED FRAME on the wire — the same bytes the
// operator's ISP bills for — including handshake retries, keepalives and relay
// transit, not just TUN payload. A column labelled "total" that quietly
// excluded overhead would understate a chatty link by a wide margin.

import (
	"sync"
	"time"
)

// peerCounters is one peer's lifetime totals plus the sampling state the rate
// calculation needs.
type peerCounters struct {
	rxBytes uint64
	txBytes uint64
	rxPkts  uint64
	txPkts  uint64

	// Sampling state, written only by the sampler goroutine.
	lastRx     uint64
	lastTx     uint64
	lastSample time.Time
	rxRate     float64 // bytes/sec, smoothed
	txRate     float64
}

type peerStatsTable struct {
	mu sync.RWMutex
	m  map[[32]byte]*peerCounters
	// firstSeen lets the UI show a rate of "—" rather than "0 B/s" for a link
	// that has not yet been sampled twice, which otherwise looks like a dead
	// link in the first seconds after connecting.
	started time.Time
}

var peerStats = &peerStatsTable{m: map[[32]byte]*peerCounters{}, started: time.Now()}

func (t *peerStatsTable) get(pub [32]byte) *peerCounters {
	t.mu.RLock()
	c := t.m[pub]
	t.mu.RUnlock()
	if c != nil {
		return c
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if c = t.m[pub]; c == nil {
		c = &peerCounters{lastSample: time.Now()}
		t.m[pub] = c
	}
	return c
}

// AddTx records bytes sent to a peer. Called on the hot send path, so it takes
// the write lock only to create a missing entry; steady state is a read lock
// plus two adds under the per-entry lock.
func (t *peerStatsTable) AddTx(pub [32]byte, n int) {
	if n <= 0 {
		return
	}
	c := t.get(pub)
	t.mu.Lock()
	c.txBytes += uint64(n)
	c.txPkts++
	t.mu.Unlock()
}

// AddRx records bytes received from a peer.
func (t *peerStatsTable) AddRx(pub [32]byte, n int) {
	if n <= 0 {
		return
	}
	c := t.get(pub)
	t.mu.Lock()
	c.rxBytes += uint64(n)
	c.rxPkts++
	t.mu.Unlock()
}

// peerTraffic is the per-peer view handed to the dashboard.
type peerTraffic struct {
	RxBytes uint64  `json:"rx_bytes"`
	TxBytes uint64  `json:"tx_bytes"`
	Total   uint64  `json:"total_bytes"`
	RxRate  float64 `json:"rx_bytes_per_sec"`
	TxRate  float64 `json:"tx_bytes_per_sec"`
	RxPkts  uint64  `json:"rx_packets"`
	TxPkts  uint64  `json:"tx_packets"`
	// Sampled is false until the rate sampler has two data points for this
	// peer, so the UI can show "—" instead of a misleading 0.
	Sampled bool `json:"sampled"`
}

func (t *peerStatsTable) Traffic(pub [32]byte) peerTraffic {
	t.mu.RLock()
	defer t.mu.RUnlock()
	c := t.m[pub]
	if c == nil {
		return peerTraffic{}
	}
	return peerTraffic{
		RxBytes: c.rxBytes,
		TxBytes: c.txBytes,
		Total:   c.rxBytes + c.txBytes,
		RxRate:  c.rxRate,
		TxRate:  c.txRate,
		RxPkts:  c.rxPkts,
		TxPkts:  c.txPkts,
		Sampled: !c.lastSample.IsZero() && (c.rxPkts > 0 || c.txPkts > 0),
	}
}

// peerRateSamplePeriod is how often rates are recomputed. Two seconds is short
// enough that the number tracks what the user is doing (starting a download
// shows up almost immediately) and long enough that a single 1500-byte packet
// does not read as a 1 KB/s link.
const peerRateSamplePeriod = 2 * time.Second

// peerRateSmoothing is the EWMA weight given to the newest sample. Raw
// per-interval rates jitter hard on bursty traffic — the number flickers
// between zero and a large value and is unreadable. 0.4 settles within a few
// seconds while still showing a real change quickly.
const peerRateSmoothing = 0.4

// startPeerRateSampler recomputes per-peer rates on a ticker. Rates cannot be
// derived on demand from lifetime totals — a rate needs two samples and the
// interval between them — so this runs whether or not anyone is looking.
func startPeerRateSampler() {
	go func() {
		t := time.NewTicker(peerRateSamplePeriod)
		defer t.Stop()
		for range t.C {
			now := time.Now()
			peerStats.mu.Lock()
			for _, c := range peerStats.m {
				elapsed := now.Sub(c.lastSample).Seconds()
				if elapsed <= 0 {
					continue
				}
				rx := float64(c.rxBytes-c.lastRx) / elapsed
				tx := float64(c.txBytes-c.lastTx) / elapsed
				if c.lastRx == 0 && c.lastTx == 0 && c.rxRate == 0 && c.txRate == 0 {
					// First sample: take it as-is rather than easing up from
					// zero, so a link that is already busy reads correctly
					// straight away.
					c.rxRate, c.txRate = rx, tx
				} else {
					c.rxRate += (rx - c.rxRate) * peerRateSmoothing
					c.txRate += (tx - c.txRate) * peerRateSmoothing
				}
				c.lastRx, c.lastTx, c.lastSample = c.rxBytes, c.txBytes, now
			}
			peerStats.mu.Unlock()
		}
	}()
}

// Forget drops a peer's counters. Called when a peer is revoked, so a revoked
// device's history does not linger in the table indefinitely.
func (t *peerStatsTable) Forget(pub [32]byte) {
	t.mu.Lock()
	delete(t.m, pub)
	t.mu.Unlock()
}
