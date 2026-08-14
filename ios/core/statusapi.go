// Status/diagnostics calls exposed to the mobile apps over gomobile.
//
// # WHY THIS FILE EXISTS AGAIN
//
// The iOS core was reverted on 2026-08-10 to a known-good version, and the
// newer core's status API went with it — this file was left as a build-ignored
// stub. The Android UI was not reverted: MainActivity.kt still calls
// Overlaymobile.exitsJSON() and .networkStatusJSON(), so every APK build failed
// with "Unresolved reference" on those two names. (android/build-aar.sh binds
// THIS package, ios/core, which is why an Android build depends on the iOS
// core at all.)
//
// Rather than restore the reverted core — the original file was never committed,
// only ever the stub, so there is nothing to restore — these two functions are
// rebuilt here from state this package already maintains. Nothing new is
// computed and no behaviour changes: exit selection and NAT classification
// already run, they simply had no way out to the UI.
//
// The field names match client/control.go's /api/exits and /api/info exactly,
// so the phone and the desktop report the same thing under the same keys.
package overlaymobile

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"time"
)

// exitInfoView is the JSON view of one known exit node. Kept field-for-field
// identical to ExitInfoView in client/control.go — the Android UI reads
// "name", "overlay_ip", "rtt_ms", "reachable" and "selected", and a rename on
// either side would silently blank the exit card rather than fail loudly.
type exitInfoView struct {
	OverlayIP string `json:"overlay_ip"`
	Name      string `json:"name"`
	KeyFP     string `json:"key_fp"`
	PubKey    string `json:"pubkey"`
	RttMs     int64  `json:"rtt_ms"` // -1 = not yet measured
	Reachable bool   `json:"reachable"`
	Selected  bool   `json:"selected"` // currently carrying this node's traffic
	Pinned    bool   `json:"pinned"`   // matches the configured pin
}

// ExitsJSON returns full-VPN outproxy diagnostics as
// {"use_exit":bool,"pin":string,"exits":[…]} — the same shape the desktop
// serves at /api/exits.
//
// This is what turns "internet is paused" from a dead end into something
// diagnosable: it distinguishes no exit announcement ever arriving, an exit
// that is known but unreachable, and a pin that matches nothing.
//
// gomobile exposes this to Kotlin/Swift as exitsJSON(). It returns a JSON
// string rather than a struct because gomobile cannot bind slices of structs.
func ExitsJSON() string {
	// Snapshot under the lock, then do the formatting outside it: resolvePeerIP
	// and resolvePeerName take their own locks, and calling them while holding
	// exitMu is a lock-order inversion waiting to deadlock.
	type raw struct {
		pub       [32]byte
		addr      *net.UDPAddr
		rttMs     int64
		lastReply time.Time
		selected  bool
	}
	exitMu.Lock()
	pin := exitPin
	useExitNow := useExit
	raws := make([]raw, 0, len(exitCandidates))
	for _, e := range exitCandidates {
		raws = append(raws, raw{
			pub: e.pub, addr: e.addr, rttMs: e.rttMs,
			lastReply: e.lastReply, selected: e == selectedExit,
		})
	}
	exitMu.Unlock()

	out := make([]exitInfoView, 0, len(raws))
	for _, r := range raws {
		v := exitInfoView{
			OverlayIP: resolvePeerIP(r.pub),
			Name:      resolvePeerName(r.pub),
			KeyFP:     peerKeyFingerprint(r.pub[:]),
			PubKey:    base64.StdEncoding.EncodeToString(r.pub[:]),
			RttMs:     -1,
			Selected:  r.selected,
			Pinned:    pin != "" && exitPinMatches(pin, r.pub),
		}
		// A zero lastReply means the probe has never come back, so rttMs holds
		// nothing meaningful — report -1 instead of a stale or zero latency.
		if !r.lastReply.IsZero() {
			v.RttMs = r.rttMs
		}
		// "Reachable" deliberately requires an ESTABLISHED session as well as a
		// recent reply. An exit heard about only through gossip cannot carry
		// traffic, and showing it as reachable is precisely the wrong answer to
		// "why is my internet paused".
		if GlobalSessions != nil && r.addr != nil {
			if s := GlobalSessions.GetByAddr(r.addr); s != nil && s.Established() &&
				time.Since(r.lastReply) <= 90*time.Second {
				v.Reachable = true
			}
		}
		out = append(out, v)
	}

	b, err := json.Marshal(map[string]any{
		"use_exit": useExitNow,
		"pin":      pin,
		"exits":    out,
	})
	if err != nil {
		return `{"use_exit":false,"pin":"","exits":[]}`
	}
	return string(b)
}

// NetworkStatusJSON returns this device's connectivity diagnosis:
//
//	{"nat_type":"symmetric|port-restricted|…","nat":{…},"sessions":N,"session_routes":N}
//
// nat_type is the field the app cares about: a symmetric NAT gives this device
// no predictable external port, so peers behind one of their own can never
// punch to it and stay relayed forever. That is invisible in the peer list —
// the peer shows as connected either way — so without this the user sees "it
// works but everything is slow" with no explanation.
//
// The LAN-discovery counters the UI can also render (lan_targets / lan_peer)
// are deliberately NOT emitted: this core has no LAN sweep to report them from,
// and the app already treats them as absent (optInt default -1) by hiding those
// lines. Emitting a fabricated zero would render "cannot see any local
// addresses" as a hard finding, which would be worse than saying nothing.
//
// gomobile exposes this to Kotlin/Swift as networkStatusJSON().
func NetworkStatusJSON() string {
	status := map[string]any{
		"nat_type": natTypeLabel(),
		"nat":      natSummary(),
	}
	if GlobalSessions != nil {
		status["sessions"] = GlobalSessions.EstablishedPeerCount()
		status["session_routes"] = len(GlobalSessions.EstablishedAddrs())
	}
	b, err := json.Marshal(status)
	if err != nil {
		return `{}`
	}
	return string(b)
}
