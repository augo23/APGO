package main

// selfendpoints.go remembers the transport endpoints THIS node has recently
// announced, ACROSS PROCESS RESTARTS, so we never dial a former incarnation of
// ourselves.
//
// The problem it solves is specific to how discovery works. We announce
// <public-ip>:<udp-port> to public trackers, and those records live in the
// swarm for the announce interval — 25 to 35 minutes in practice. The UDP port
// is chosen fresh on every start. So every restart mints a NEW endpoint while
// the PREVIOUS one is still being handed out by the trackers, and we read our
// own dead address back as if it were a peer.
//
// Then it gets worse rather than merely wasteful:
//
//   - Our old endpoint carries our own public IP, so the same-site logic
//     classifies it as "a peer at our site with no LAN path" and drives the
//     hairpin ladder at it, forever.
//   - punchCandidates/addKnownPeer memorise it, so holePunchRetryLoop dials it
//     on every pass — a full Noise handshake (X25519 keygen + DH, plus
//     retransmits) to an address that is definitionally dead.
//   - The peer's LAN address is ours too, so BOTH <lan-ip>:<old-port> and
//     <public-ip>:<old-port> get dialled.
//
// A phone restarts its tunnel constantly — every network change, sleep/wake and
// app relaunch — so it accumulates several ghosts of itself at once. That is
// why this is felt on mobile far more than on a server that runs for weeks.
//
// In-memory tracking cannot fix it: the whole point is that the stale records
// belong to PREVIOUS runs. The history has to outlive the process, so it is
// persisted next to the node key.

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// selfEndpointTTL is how long a former endpoint of ours stays suspect. It must
// comfortably exceed the longest tracker announce interval we honour, or a
// record can outlive our memory of it and we are back to dialling ourselves.
const selfEndpointTTL = 45 * time.Minute

var (
	selfEPMu   sync.Mutex
	selfEPs    = map[string]time.Time{}
	selfEPPath string
)

// selfEndpointsFile returns the persistence path, or "" when this build has no
// writable state directory (in which case we degrade to in-memory only).
func selfEndpointsFile() string {
	if selfEPPath != "" {
		return selfEPPath
	}
	if p := os.Getenv("SELF_ENDPOINTS_FILE"); p != "" {
		selfEPPath = p
		return selfEPPath
	}
	// Derive from any state path the bridge already set up.
	for _, k := range []string{"PROVISIONS_FILE", "APPROVALS_FILE", "TRACKERS_FILE"} {
		if p := os.Getenv(k); p != "" {
			selfEPPath = filepath.Join(filepath.Dir(p), "self-endpoints.json")
			return selfEPPath
		}
	}
	return ""
}

// loadSelfEndpoints restores the history written by previous runs. Called once
// at startup, BEFORE any tracker response is processed.
func loadSelfEndpoints() {
	path := selfEndpointsFile()
	if path == "" {
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var stored map[string]int64
	if json.Unmarshal(b, &stored) != nil {
		return
	}
	now := time.Now()
	selfEPMu.Lock()
	for ep, unix := range stored {
		t := time.Unix(unix, 0)
		if now.Sub(t) < selfEndpointTTL {
			selfEPs[ep] = t
		}
	}
	selfEPMu.Unlock()
}

func saveSelfEndpointsLocked() {
	path := selfEndpointsFile()
	if path == "" {
		return
	}
	out := make(map[string]int64, len(selfEPs))
	for ep, t := range selfEPs {
		out[ep] = t.Unix()
	}
	b, err := json.Marshal(out)
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, path)
	}
}

// rememberSelfEndpoint records an endpoint as ours. Safe to call repeatedly;
// it only writes to disk when something actually changed.
func rememberSelfEndpoint(ep string) {
	if ep == "" {
		return
	}
	host, port, err := net.SplitHostPort(ep)
	if err != nil || host == "" || port == "" || port == "0" {
		return
	}
	now := time.Now()
	selfEPMu.Lock()
	_, existed := selfEPs[ep]
	selfEPs[ep] = now
	changed := !existed
	for k, t := range selfEPs {
		if now.Sub(t) > selfEndpointTTL {
			delete(selfEPs, k)
			changed = true
		}
	}
	if changed {
		saveSelfEndpointsLocked()
	}
	selfEPMu.Unlock()
}

// rememberSelfEndpointsAt records every address this host currently answers on
// at the given port: the STUN-discovered public endpoint plus each local
// interface address. A stale record of ANY of them is a ghost of us — the LAN
// form matters as much as the public one, because a same-site peer's PEX
// gossip carries our LAN address exactly as it saw it.
func rememberSelfEndpointsAt(publicEndpoint string, port int) {
	if port <= 0 {
		return
	}
	rememberSelfEndpoint(publicEndpoint)
	p := strconv.Itoa(port)
	if publicEndpoint != "" {
		if h, _, err := net.SplitHostPort(publicEndpoint); err == nil {
			rememberSelfEndpoint(net.JoinHostPort(h, p))
		}
	}
	for _, ip := range localInterfaceIPs() {
		rememberSelfEndpoint(net.JoinHostPort(ip, p))
	}
}

// wasSelfEndpoint reports whether addr is one this node announced recently —
// i.e. a former incarnation of ourselves, not a peer.
func wasSelfEndpoint(addr string) bool {
	if addr == "" {
		return false
	}
	selfEPMu.Lock()
	defer selfEPMu.Unlock()
	t, ok := selfEPs[addr]
	if !ok {
		return false
	}
	if time.Since(t) > selfEndpointTTL {
		delete(selfEPs, addr)
		return false
	}
	return true
}
