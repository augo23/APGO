package main

// loginthrottle.go adds brute-force resistance to the dashboard login. PBKDF2
// (600k iterations) already makes each guess cost tens of milliseconds, but
// nothing stopped an attacker from pipelining thousands of attempts. This adds
// a per-source-IP exponential backoff: after a few failures the source must
// wait, growing up to a cap, and successes reset it. In-memory only (resets on
// restart), which is fine for a live-guessing defense.

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

const (
	loginFreeAttempts = 5                // failures allowed before backoff starts
	loginBackoffBase  = 2 * time.Second  // first penalty
	loginBackoffMax   = 5 * time.Minute  // penalty ceiling
	loginRecordTTL    = 30 * time.Minute // forget a quiet source after this
)

type loginAttempt struct {
	fails    int
	nextOK   time.Time // earliest time this source may try again
	lastSeen time.Time
}

var (
	loginMu       sync.Mutex
	loginAttempts = map[string]*loginAttempt{}
)

// loginThrottlePath is where backoff state is persisted so a restart can't
// clear an attacker's accrued penalty. Lives on the same protected volume as
// the credentials file; disabled (in-memory only) if it can't be set.
func loginThrottlePath() string {
	return env("ADMIN_THROTTLE_FILE", "/adminkey/login-throttle.json")
}

// persistedAttempt is the on-disk shape (times as unix nanos for portability).
type persistedAttempt struct {
	IP       string `json:"ip"`
	Fails    int    `json:"fails"`
	NextOK   int64  `json:"next_ok"`
	LastSeen int64  `json:"last_seen"`
}

// loadLoginThrottle restores backoff state at startup. Best-effort: a missing
// or unreadable file just means starting with a clean (in-memory) slate.
func loadLoginThrottle() {
	data, err := os.ReadFile(loginThrottlePath())
	if err != nil {
		return
	}
	var recs []persistedAttempt
	if json.Unmarshal(data, &recs) != nil {
		return
	}
	loginMu.Lock()
	defer loginMu.Unlock()
	for _, r := range recs {
		loginAttempts[r.IP] = &loginAttempt{
			fails:    r.Fails,
			nextOK:   time.Unix(0, r.NextOK),
			lastSeen: time.Unix(0, r.LastSeen),
		}
	}
	pruneLoginLocked()
}

// saveLoginThrottleLocked atomically writes current state. Caller holds loginMu.
// Best-effort — a write failure never blocks a login decision.
func saveLoginThrottleLocked() {
	p := loginThrottlePath()
	recs := make([]persistedAttempt, 0, len(loginAttempts))
	for ip, a := range loginAttempts {
		recs = append(recs, persistedAttempt{
			IP: ip, Fails: a.fails,
			NextOK: a.nextOK.UnixNano(), LastSeen: a.lastSeen.UnixNano(),
		})
	}
	data, err := json.Marshal(recs)
	if err != nil {
		return
	}
	tmp := p + ".tmp"
	if os.WriteFile(tmp, data, 0o600) == nil {
		_ = os.Rename(tmp, p)
	}
}

// clientIP extracts the source IP (host part) from RemoteAddr. The admin
// dashboard is meant to be reached directly or over a trusted tunnel, so we do
// NOT trust X-Forwarded-For here (it is client-settable and would let an
// attacker rotate the key trivially).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// loginAllowed reports whether this source may attempt a login now, and if not,
// how long it must wait.
func loginAllowed(ip string) (bool, time.Duration) {
	loginMu.Lock()
	defer loginMu.Unlock()
	a := loginAttempts[ip]
	if a == nil {
		return true, 0
	}
	if wait := time.Until(a.nextOK); wait > 0 {
		return false, wait
	}
	return true, 0
}

// loginFailed records a failed attempt and arms the backoff.
func loginFailed(ip string) {
	loginMu.Lock()
	defer loginMu.Unlock()
	pruneLoginLocked()
	a := loginAttempts[ip]
	if a == nil {
		a = &loginAttempt{}
		loginAttempts[ip] = a
	}
	a.fails++
	a.lastSeen = time.Now()
	if a.fails > loginFreeAttempts {
		// Exponential: base * 2^(fails-free-1), capped.
		backoff := loginBackoffBase << uint(a.fails-loginFreeAttempts-1)
		if backoff <= 0 || backoff > loginBackoffMax {
			backoff = loginBackoffMax
		}
		a.nextOK = time.Now().Add(backoff)
	}
	saveLoginThrottleLocked() // durable so a restart can't clear the penalty
}

// loginSucceeded clears any backoff for a source after a valid login.
func loginSucceeded(ip string) {
	loginMu.Lock()
	delete(loginAttempts, ip)
	saveLoginThrottleLocked()
	loginMu.Unlock()
}

// pruneLoginLocked drops stale records so the map can't grow unbounded from a
// spray of one-off source IPs. Caller holds loginMu.
func pruneLoginLocked() {
	cutoff := time.Now().Add(-loginRecordTTL)
	for ip, a := range loginAttempts {
		if a.lastSeen.Before(cutoff) && time.Now().After(a.nextOK) {
			delete(loginAttempts, ip)
		}
	}
}
