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

// rendezvousAnnounce announces to one server and returns the peers it reports.
func rendezvousAnnounce(server string, infoHash []byte, peerID, endpoint string) ([]string, error) {
	reqBody, _ := json.Marshal(map[string]string{
		"network":  hex.EncodeToString(infoHash),
		"endpoint": endpoint,
		"peer_id":  peerID,
	})
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Post(strings.TrimRight(server, "/")+"/api/rendezvous",
		"application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
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
