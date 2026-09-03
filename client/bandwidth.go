package main

// bandwidth.go is the metering that makes "share my node publicly" a decision
// with a KNOWN cost rather than an open-ended one.
//
// Nobody enables a public relay if the honest answer to "how much will this
// use?" is "as much as strangers want". So every byte that transits this node
// on behalf of someone outside our own overlay passes through:
//
//	1. a token bucket   — a hard rate ceiling (KB/s up and down), with a burst
//	                      allowance so ordinary traffic is not shaped to death;
//	2. a period quota   — a total byte budget per rolling month, after which
//	                      relaying stops until the period rolls over;
//	3. circuit limits   — caps on concurrent circuits and per-circuit rate, so
//	                      one greedy peer cannot consume the whole allowance.
//
// The quota counters are PERSISTED. A relay that forgot its usage on every
// restart would let a crashing (or deliberately restarted) node exceed the
// operator's monthly budget without limit — which is exactly the surprise this
// file exists to prevent.

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// tokenBucket is a standard rate limiter: tokens (bytes) accrue at rate/sec up
// to burst, and each send/receive spends them. Chosen over a fixed window
// because a window lets a full period's allowance be spent in its first
// millisecond — which on a relay means a periodic saturation spike rather than
// the smooth ceiling an operator asked for.
type tokenBucket struct {
	mu       sync.Mutex
	rate     float64 // bytes per second; 0 = unlimited
	burst    float64 // maximum accumulated bytes
	tokens   float64
	lastFill time.Time
}

func newTokenBucket(bytesPerSec int64) *tokenBucket {
	b := &tokenBucket{lastFill: time.Now()}
	b.SetRate(bytesPerSec)
	// Start FULL, not empty. An empty bucket means the first second after
	// startup (or after any live rate change) refuses everything, which shows
	// up as relayed sessions that fail to handshake and then retry — an
	// outage indistinguishable from the relay being down.
	b.mu.Lock()
	b.tokens = b.burst
	b.mu.Unlock()
	return b
}

// SetRate reconfigures the bucket live (an operator dragging a slider in the
// panel). Burst is one second of traffic, floored at 64 KiB so that a single
// MTU-sized packet is never larger than the burst — a bucket that cannot ever
// hold one whole packet blocks forever instead of rate-limiting.
func (b *tokenBucket) SetRate(bytesPerSec int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.rate = float64(bytesPerSec)
	if bytesPerSec <= 0 {
		b.burst, b.tokens = 0, 0
		return
	}
	burst := float64(bytesPerSec)
	if burst < 65536 {
		burst = 65536
	}
	b.burst = burst
	if b.tokens > burst {
		b.tokens = burst
	}
}

func (b *tokenBucket) Rate() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return int64(b.rate)
}

// Allow spends n bytes if available. It does NOT block or queue: a relay that
// buffered over-limit traffic would grow unbounded memory under exactly the
// abuse the limit exists to stop, and the overlay above is a UDP tunnel that
// already treats loss as normal and backs off on its own.
func (b *tokenBucket) Allow(n int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.rate <= 0 {
		return true // unlimited
	}
	now := time.Now()
	elapsed := now.Sub(b.lastFill).Seconds()
	b.lastFill = now
	b.tokens += elapsed * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	if b.tokens < float64(n) {
		return false
	}
	b.tokens -= float64(n)
	return true
}

// quotaCounters is the persisted usage ledger for the current period.
type quotaCounters struct {
	PeriodStart time.Time `json:"period_start"`
	BytesUp     int64     `json:"bytes_up"`   // bytes we sent on others' behalf
	BytesDown   int64     `json:"bytes_down"` // bytes we received on others' behalf
	Circuits    int64     `json:"circuits"`   // circuits served this period
}

// bandwidthLimiter ties the buckets and the quota together. One instance,
// owned by the public relay.
type bandwidthLimiter struct {
	up   *tokenBucket
	down *tokenBucket

	mu sync.Mutex
	// quotaBytes is the total (up+down) byte budget per period. 0 = no quota.
	quotaBytes int64
	// periodDays is the rolling period length. 30 by default.
	periodDays int
	counters   quotaCounters
	path       string
	dirty      bool
}

func newBandwidthLimiter(upBps, downBps, quotaBytes int64, periodDays int, statePath string) *bandwidthLimiter {
	if periodDays <= 0 {
		periodDays = 30
	}
	l := &bandwidthLimiter{
		up:         newTokenBucket(upBps),
		down:       newTokenBucket(downBps),
		quotaBytes: quotaBytes,
		periodDays: periodDays,
		path:       statePath,
	}
	l.load()
	go l.flushLoop()
	return l
}

func (l *bandwidthLimiter) load() {
	if l.path == "" {
		l.counters.PeriodStart = time.Now()
		return
	}
	data, err := os.ReadFile(l.path)
	if err != nil {
		l.counters.PeriodStart = time.Now()
		return
	}
	_ = json.Unmarshal(data, &l.counters)
	if l.counters.PeriodStart.IsZero() {
		l.counters.PeriodStart = time.Now()
	}
}

func (l *bandwidthLimiter) save() {
	l.mu.Lock()
	if !l.dirty || l.path == "" {
		l.mu.Unlock()
		return
	}
	c := l.counters
	l.dirty = false
	l.mu.Unlock()
	out, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return
	}
	tmp := l.path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, l.path)
}

// flushLoop persists counters periodically rather than on every packet — a
// disk write per relayed datagram would cost more than the relaying does.
func (l *bandwidthLimiter) flushLoop() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for range t.C {
		l.save()
	}
}

// rollPeriod resets the ledger when the period has elapsed. Caller holds l.mu.
func (l *bandwidthLimiter) rollPeriodLocked() {
	if time.Since(l.counters.PeriodStart) < time.Duration(l.periodDays)*24*time.Hour {
		return
	}
	l.counters = quotaCounters{PeriodStart: time.Now()}
	l.dirty = true
}

// QuotaExceeded reports whether the period budget is spent.
func (l *bandwidthLimiter) QuotaExceeded() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rollPeriodLocked()
	if l.quotaBytes <= 0 {
		return false
	}
	return l.counters.BytesUp+l.counters.BytesDown >= l.quotaBytes
}

// AllowUp charges n bytes of egress against the rate limit and the quota.
func (l *bandwidthLimiter) AllowUp(n int) bool {
	if l.QuotaExceeded() || !l.up.Allow(n) {
		return false
	}
	l.mu.Lock()
	l.counters.BytesUp += int64(n)
	l.dirty = true
	l.mu.Unlock()
	return true
}

// AllowDown charges n bytes of ingress against the rate limit and the quota.
func (l *bandwidthLimiter) AllowDown(n int) bool {
	if l.QuotaExceeded() || !l.down.Allow(n) {
		return false
	}
	l.mu.Lock()
	l.counters.BytesDown += int64(n)
	l.dirty = true
	l.mu.Unlock()
	return true
}

func (l *bandwidthLimiter) NoteCircuit() {
	l.mu.Lock()
	l.counters.Circuits++
	l.dirty = true
	l.mu.Unlock()
}

// Configure updates the limits live. Rates are in BYTES per second; quota in
// bytes. Zero means unlimited for each independently, so an operator can cap
// the rate without a monthly cap, or vice versa.
func (l *bandwidthLimiter) Configure(upBps, downBps, quotaBytes int64, periodDays int) {
	l.up.SetRate(upBps)
	l.down.SetRate(downBps)
	l.mu.Lock()
	l.quotaBytes = quotaBytes
	if periodDays > 0 {
		l.periodDays = periodDays
	}
	l.dirty = true
	l.mu.Unlock()
}

// bandwidthStatus is the dashboard view of the meter.
type bandwidthStatus struct {
	UpLimitBps    int64     `json:"up_limit_bytes_per_sec"`
	DownLimitBps  int64     `json:"down_limit_bytes_per_sec"`
	QuotaBytes    int64     `json:"quota_bytes"`
	PeriodDays    int       `json:"period_days"`
	PeriodStart   time.Time `json:"period_start"`
	UsedUpBytes   int64     `json:"used_up_bytes"`
	UsedDownBytes int64     `json:"used_down_bytes"`
	UsedPct       float64   `json:"used_pct"`
	Circuits      int64     `json:"circuits_served"`
	QuotaHit      bool      `json:"quota_exceeded"`
}

func (l *bandwidthLimiter) Status() bandwidthStatus {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rollPeriodLocked()
	s := bandwidthStatus{
		UpLimitBps:    l.up.Rate(),
		DownLimitBps:  l.down.Rate(),
		QuotaBytes:    l.quotaBytes,
		PeriodDays:    l.periodDays,
		PeriodStart:   l.counters.PeriodStart,
		UsedUpBytes:   l.counters.BytesUp,
		UsedDownBytes: l.counters.BytesDown,
		Circuits:      l.counters.Circuits,
	}
	if l.quotaBytes > 0 {
		s.UsedPct = float64(l.counters.BytesUp+l.counters.BytesDown) / float64(l.quotaBytes) * 100
		s.QuotaHit = l.counters.BytesUp+l.counters.BytesDown >= l.quotaBytes
	}
	return s
}

// parseRate turns a human limit ("5MB", "500kbps", "2mbit", "1.5GB") into
// BYTES PER SECOND (for rates) or BYTES (for quotas — same parser, since the
// units are identical and only the caller's interpretation differs).
//
// Bit units are accepted and divided by 8 because ISP plans are quoted in
// bits and operators reach for the number on their bill; silently treating
// "100mbit" as 100 MB/s would make a relay use 8x the intended bandwidth.
func parseRate(s string) int64 {
	s = trimLowerSpace(s)
	if s == "" || s == "0" || s == "unlimited" || s == "none" {
		return 0
	}
	// Split the numeric prefix from the unit suffix.
	i := 0
	for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
		i++
	}
	if i == 0 {
		return 0
	}
	val := parseFloatSafe(s[:i])
	unit := trimLowerSpace(s[i:])
	unit = trimSuffixAny(unit, "/s", "ps", "per second", "sec")

	bits := false
	switch {
	case hasSuffixAny(unit, "bit", "bits", "b") && !hasSuffixAny(unit, "byte", "bytes", "B"):
		bits = true
	}
	mult := float64(1)
	switch {
	case hasPrefixAny(unit, "k"):
		mult = 1000
	case hasPrefixAny(unit, "m"):
		mult = 1000 * 1000
	case hasPrefixAny(unit, "g"):
		mult = 1000 * 1000 * 1000
	case hasPrefixAny(unit, "t"):
		mult = 1000 * 1000 * 1000 * 1000
	}
	// "kib"/"mib"/"gib" mean binary multiples.
	if hasSuffixAny(unit, "ib", "ib/s", "ibps") {
		switch mult {
		case 1000:
			mult = 1024
		case 1000 * 1000:
			mult = 1024 * 1024
		case 1000 * 1000 * 1000:
			mult = 1024 * 1024 * 1024
		case 1000 * 1000 * 1000 * 1000:
			mult = 1024 * 1024 * 1024 * 1024
		}
	}
	out := val * mult
	if bits {
		out /= 8
	}
	if out < 0 {
		return 0
	}
	return int64(out)
}

// formatRate renders bytes/sec (or a byte count) for the UI and logs.
func formatRate(n int64) string {
	if n <= 0 {
		return "unlimited"
	}
	const k = 1000
	switch {
	case n >= k*k*k*k:
		return formatFloat1(float64(n)/(k*k*k*k)) + " TB"
	case n >= k*k*k:
		return formatFloat1(float64(n)/(k*k*k)) + " GB"
	case n >= k*k:
		return formatFloat1(float64(n)/(k*k)) + " MB"
	case n >= k:
		return formatFloat1(float64(n)/k) + " KB"
	}
	return formatFloat1(float64(n)) + " B"
}

// --- small string helpers, kept local so parseRate has no wider dependencies

func trimLowerSpace(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func parseFloatSafe(s string) float64 {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f < 0 {
		return 0
	}
	return f
}

func trimSuffixAny(s string, suffixes ...string) string {
	for _, suf := range suffixes {
		if strings.HasSuffix(s, suf) {
			return strings.TrimSpace(strings.TrimSuffix(s, suf))
		}
	}
	return s
}

func hasSuffixAny(s string, suffixes ...string) bool {
	for _, suf := range suffixes {
		if strings.HasSuffix(s, strings.ToLower(suf)) {
			return true
		}
	}
	return false
}

func hasPrefixAny(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func formatFloat1(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}
