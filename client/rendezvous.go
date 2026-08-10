package main

// rendezvous.go is an alternative to BitTorrent-tracker discovery for networks
// that block BitTorrent. A rendezvous server is a tiny HTTP(S) service: a node
// POSTs its network id (the same info-hash the tracker uses) and its public
// endpoint, and gets back the other endpoints in that network. Run behind TLS on
// 443 and it is indistinguishable from ordinary HTTPS, so DPI/port filters that
// block torrents let it through.
//
// The rendezvous only exchanges endpoints — exactly like a tracker. Membership
// is still gated by the Noise handshake + PSK, so a rogue or nosy rendezvous can
// learn endpoints (metadata) but can never join the overlay.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

type rendezvousResponse struct {
	Peers []string `json:"peers"`
}

// gRendezvousCred is the credential presented to rendezvous servers that
// require one. ONE field covers both schemes the server accepts:
//
//	"user:password" (contains a colon) -> HTTP Basic
//	"sometoken"     (no colon)         -> Bearer
//
// Empty = send no Authorization header (open server). See rendezvous/auth.go.
var gRendezvousCred string

// applyRendezvousAuth sets the Authorization header for the configured
// credential style. No-op when no credential is configured.
func applyRendezvousAuth(req *http.Request) {
	cred := strings.TrimSpace(gRendezvousCred)
	if cred == "" {
		return
	}
	if user, pass, isBasic := strings.Cut(cred, ":"); isBasic {
		req.SetBasicAuth(user, pass)
		return
	}
	req.Header.Set("Authorization", "Bearer "+cred)
}

// rendezvousAnnounce announces to one server and returns the peers it reports.
func rendezvousAnnounce(server string, infoHash []byte, peerID, endpoint string) ([]string, error) {
	reqBody, _ := json.Marshal(map[string]string{
		"network":  hex.EncodeToString(infoHash),
		"endpoint": endpoint,
		"peer_id":  peerID,
	})
	req, err := http.NewRequest(http.MethodPost,
		strings.TrimRight(server, "/")+"/api/rendezvous", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	applyRendezvousAuth(req)

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		// Distinct message: this is a CREDENTIAL problem, not an outage —
		// the single most confusing failure to debug from a generic "status
		// 401" line.
		return nil, fmt.Errorf("rendezvous %s rejected our credential (401) — "+
			"check the rendezvous username/password or token in Settings", server)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rendezvous %s status %d", server, resp.StatusCode)
	}
	var r rendezvousResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return r.Peers, nil
}

// announceRendezvous announces to every configured rendezvous server and starts
// handshakes to the peers they return. Safe to call on the same cadence as the
// tracker announce; it's a no-op when no servers are configured.
func announceRendezvous(servers []string, infoHash []byte, peerID, endpoint string, kp keypair, psk []byte) {
	for _, s := range servers {
		s = strings.TrimSpace(s)
		// Skip blanks and anything that isn't an http(s) URL — this guards against
		// an unexpanded env placeholder like "${RENDEZVOUS_SERVERS:-}" leaking in.
		if s == "" || !(strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")) {
			continue
		}
		peers, err := rendezvousAnnounce(s, infoHash, peerID, endpoint)
		if err != nil {
			log.Printf("rendezvous %s failed: %v", s, err)
			continue
		}
		log.Printf("rendezvous %s returned %d peer(s)", s, len(peers))
		for _, p := range peers {
			if !isValidPeer(p) || isSelf(p, endpoint, 0) {
				continue
			}
			addKnownPeer(p)
			go connectToPeer(p, kp, psk)
		}
	}
}
