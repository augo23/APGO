package main

// exit.go implements "outproxy" / full-tunnel support:
//
//   * A node with exit_node=true advertises itself as an EXIT and forwards
//     internet-bound overlay traffic out to the real internet (NAT), so a client
//     can use it as a full VPN. (NAT setup is per-OS; see setupExitNAT.)
//   * A client with use_exit=true routes every non-overlay packet to an exit.
//     By default it picks the FASTEST reachable exit (latency-probed, re-measured
//     every ~5 minutes, auto-switching if the current one goes down or a faster
//     one appears). Alternatively, exit_peer pins ONE specific node as the
//     outproxy — identified by its overlay IP, friendly name, base64 public key,
//     or key fingerprint — and traffic only ever egresses there (dropped, never
//     re-routed, while the pinned exit is unreachable).
//
// Control frames (inside the encrypted tunnel):
//   OVLYCTL1 E                 — "I am an exit" (advertised on keepalive)
//   OVLYCTL1 e <8B unixnano>   — exit latency ping
//   OVLYCTL1 r <8B unixnano>   — ping reply (echoes the timestamp)

import (
	"encoding/base64"
	"encoding/binary"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

var (
	amExit  bool // this node forwards internet traffic for clients
	useExit bool // this node routes its own internet traffic via an exit

	overlayNet *net.IPNet // parsed overlay subnet, for dst classification

	exitMu         sync.Mutex
	exitCandidates = map[[32]byte]*exitInfo{}
	selectedExit   *exitInfo

	// exitPin selects the outproxy mode: "" = automatic (fastest reachable
	// exit); anything else pins one node — matched against the exit's overlay
	// IP, friendly name, base64 static key, or key-fingerprint prefix.
	exitPin string

	// exitRepick nudges the selection loop to re-probe + re-pick immediately
	// (e.g. after the pin is changed at runtime via the control API).
	exitRepick = make(chan struct{}, 1)
)

type exitInfo struct {
	pub       [32]byte
	addr      *net.UDPAddr
	rttMs     int64
	lastSeen  time.Time
	lastReply time.Time
}

func initExit(cfg *ClientConfig) {
	amExit = cfg.ExitNode
	useExit = cfg.UseExit
	exitPin = strings.TrimSpace(cfg.ExitPeer)
	if _, n, err := net.ParseCIDR(cfg.OverlayCIDR); err == nil {
		overlayNet = n
	}
	if amExit {
		if err := setupExitNAT(); err != nil {
			// Do NOT keep advertising: a node that announces 'E' but cannot
			// actually forward makes every full-VPN client that selects it
			// lose ALL internet ("connected to no internet"). Better to be
			// no exit than a black hole.
			amExit = false
			log.Printf("[exit] exit-node mode DISABLED — could not enable internet forwarding (NAT): %v", err)
		} else {
			log.Printf("[exit] exit-node mode ON — forwarding internet traffic for overlay clients")
		}
	}
	if useExit {
		if exitPin != "" {
			log.Printf("[exit] full-VPN mode ON — routing internet traffic via pinned exit %q", exitPin)
		} else {
			log.Printf("[exit] full-VPN mode ON — routing internet traffic via the fastest exit node")
		}
	}
}

// setExitPin changes the outproxy selection at runtime ("" = automatic/fastest)
// and nudges the selection loop so the change applies within seconds.
func setExitPin(pin string) {
	exitMu.Lock()
	exitPin = strings.TrimSpace(pin)
	exitMu.Unlock()
	select {
	case exitRepick <- struct{}{}:
	default:
	}
}

// exitPinMatches reports whether the pinned-exit identifier refers to the peer
// with static key pub. Accepts the peer's overlay IP, friendly name
// (case-insensitive), full base64 static key, or a key-fingerprint prefix
// (≥6 hex chars).
func exitPinMatches(pin string, pub [32]byte) bool {
	pin = strings.TrimSpace(pin)
	if pin == "" {
		return false
	}
	low := strings.ToLower(pin)
	if ip := resolvePeerIP(pub); ip != "" && ip == pin {
		return true
	}
	if n := resolvePeerName(pub); n != "" && strings.EqualFold(n, pin) {
		return true
	}
	if base64.StdEncoding.EncodeToString(pub[:]) == pin {
		return true
	}
	if len(low) >= 6 && strings.HasPrefix(peerKeyFingerprint(pub[:]), low) {
		return true
	}
	return false
}

// isInternetDst reports whether dst is OUTSIDE the overlay subnet (so it should
// go to an exit rather than a peer). Unknown/blank is treated as overlay (safe).
func isInternetDst(dst string) bool {
	if dst == "" || overlayNet == nil {
		return false
	}
	ip := net.ParseIP(dst)
	if ip == nil {
		return false
	}
	return !overlayNet.Contains(ip)
}

// buildExitAnnounce returns "OVLYCTL1E" if this node is an exit, else nil.
func buildExitAnnounce() []byte {
	if !amExit {
		return nil
	}
	return append(append([]byte(nil), ctlMagic...), 'E')
}

// handleExitAnnounce records a peer that advertised itself as an exit.
func handleExitAnnounce(raddr *net.UDPAddr) {
	s := GlobalSessions.GetByAddr(raddr)
	if s == nil {
		return
	}
	exitMu.Lock()
	e := exitCandidates[s.peerStatic]
	isNew := e == nil
	if e == nil {
		e = &exitInfo{pub: s.peerStatic, rttMs: 1 << 30}
		exitCandidates[s.peerStatic] = e
	}
	e.addr = raddr
	e.lastSeen = time.Now()
	noneSelected := selectedExit == nil
	exitMu.Unlock()
	// A brand-new exit while we have none selected: nudge the selection loop
	// so full-VPN converges in seconds instead of waiting for the next tick.
	if isNew && noneSelected {
		select {
		case exitRepick <- struct{}{}:
		default:
		}
	}
}

// handleExitPing replies to a latency ping, echoing the timestamp.
func handleExitPing(raddr *net.UDPAddr, ts []byte) {
	if len(ts) < 8 {
		return
	}
	s := GlobalSessions.GetByAddr(raddr)
	if s == nil || !s.Established() {
		return
	}
	reply := append(append([]byte(nil), ctlMagic...), 'r')
	reply = append(reply, ts[:8]...)
	_ = sendPacket(GlobalConn, raddr, s, reply)
}

// handleExitPong computes RTT from the echoed timestamp.
func handleExitPong(raddr *net.UDPAddr, ts []byte) {
	if len(ts) < 8 {
		return
	}
	sent := int64(binary.BigEndian.Uint64(ts[:8]))
	rtt := (time.Now().UnixNano() - sent) / int64(time.Millisecond)
	s := GlobalSessions.GetByAddr(raddr)
	if s == nil {
		return
	}
	exitMu.Lock()
	if e := exitCandidates[s.peerStatic]; e != nil {
		e.rttMs = rtt
		e.lastReply = time.Now()
	}
	exitMu.Unlock()
}

// exitStatusFor reports whether the peer with static key pub advertises as an
// exit node, and whether it is the exit THIS device currently egresses
// through (full-VPN mode). Used by the session snapshot so every UI can badge
// the active exit next to the peer.
func exitStatusFor(pub [32]byte) (isExit, isActive bool) {
	exitMu.Lock()
	defer exitMu.Unlock()
	e, ok := exitCandidates[pub]
	if !ok {
		return false, false
	}
	return true, useExit && selectedExit != nil && selectedExit == e
}

// currentExit returns the selected exit's endpoint + session, or (nil,nil).
func currentExit() (*net.UDPAddr, *session) {
	exitMu.Lock()
	e := selectedExit
	exitMu.Unlock()
	if e == nil || e.addr == nil {
		return nil, nil
	}
	s := GlobalSessions.GetByAddr(e.addr)
	if s == nil || !s.Established() {
		return nil, nil
	}
	return e.addr, s
}

// exitSelectionLoop periodically pings every known exit, then selects one:
// the lowest-latency reachable exit in automatic mode, or the pinned node
// (and ONLY the pinned node) when exit_peer is set. Runs only when use_exit
// is on.
func exitSelectionLoop() {
	if !useExit {
		return
	}
	probe := func() {
		exitMu.Lock()
		cands := make([]*exitInfo, 0, len(exitCandidates))
		for _, e := range exitCandidates {
			cands = append(cands, e)
		}
		exitMu.Unlock()
		var ts [8]byte
		binary.BigEndian.PutUint64(ts[:], uint64(time.Now().UnixNano()))
		for _, e := range cands {
			if s := GlobalSessions.GetByAddr(e.addr); s != nil && s.Established() {
				ping := append(append([]byte(nil), ctlMagic...), 'e')
				ping = append(ping, ts[:]...)
				_ = sendPacket(GlobalConn, e.addr, s, ping)
			}
		}
	}
	pick := func() {
		exitMu.Lock()
		defer exitMu.Unlock()
		pin := exitPin
		var best, pinned *exitInfo
		for _, e := range exitCandidates {
			if s := GlobalSessions.GetByAddr(e.addr); s == nil || !s.Established() {
				continue
			}
			if time.Since(e.lastReply) > 90*time.Second {
				continue // no recent latency reply — treat as down
			}
			if best == nil || e.rttMs < best.rttMs {
				best = e
			}
			if pin != "" && pinned == nil && exitPinMatches(pin, e.pub) {
				pinned = e
			}
		}
		chosen := best
		if pin != "" {
			// Pinned mode is strict: use the chosen node or nothing. Traffic is
			// dropped (never silently re-routed elsewhere) while it's unreachable.
			chosen = pinned
			if pinned == nil && selectedExit != nil {
				log.Printf("[exit] pinned exit %q unreachable — internet traffic paused until it returns", pin)
			}
		}
		if chosen != nil && chosen != selectedExit {
			mode := "fastest"
			if pin != "" {
				mode = "pinned"
			}
			log.Printf("[exit] selected exit %v (rtt %dms, %s)", chosen.addr, chosen.rttMs, mode)
		}
		selectedExit = chosen
	}

	// Convergence: while NO exit is selected, retry every few seconds — at
	// startup the first probe fires before any session (let alone an exit
	// announce) exists, so a fixed 5-minute tick left full-VPN mode with no
	// internet for up to 5 minutes after connecting. Once an exit is selected,
	// relax to a 5-minute re-evaluation (or on demand via exitRepick).
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		probe()
		time.Sleep(3 * time.Second)
		pick()
		exitMu.Lock()
		haveExit := selectedExit != nil
		exitMu.Unlock()
		if haveExit {
			select {
			case <-ticker.C:
			case <-exitRepick:
			}
		} else {
			select {
			case <-ticker.C:
			case <-exitRepick:
			case <-time.After(4 * time.Second):
			}
		}
	}
}
