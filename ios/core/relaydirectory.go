package overlaymobile

// relaydirectory.go — finding public relays WITHOUT the DHT.
//
// Relays advertise themselves under relayDirectoryKey() in the DHT
// (publicrelay.go). That works on desktop and on nothing else: the mobile
// cores carry trackers, rendezvous and PEX, but no DHT — it is the one
// discovery mechanism that was never ported, because a phone has no business
// maintaining a routing table it must keep warm with constant traffic.
//
// The consequence went unnoticed for as long as the only peers that NEEDED a
// relay were desktops. A phone on a cellular carrier is the case that breaks:
// carrier NAT is symmetric (a fresh external port per destination), a home
// router is port-restricted (no inbound without a matching outbound first),
// and that pairing cannot be hole-punched from either side. Relay is not a
// fallback there — it is the only path that can ever work. A phone that
// cannot FIND a relay therefore retries doomed direct punches indefinitely,
// which is exactly what the field logs showed: hours of "no handshake reply"
// against a carrier address whose external port had already moved.
//
// The fix is to publish the same directory somewhere a phone already looks.
// BitTorrent trackers are that place: every client already speaks to them for
// peer discovery, the announce is one UDP round trip, and the directory key is
// deliberately public and unblinded (see relayDirectoryKey), so announcing it
// to a public tracker leaks nothing the DHT did not already publish.
//
// Both transports run in parallel and their results are merged. A desktop
// keeps the DHT as its primary source and gains trackers as a backup for when
// the DHT is firewalled; a phone uses trackers only.

import (
	"crypto/hmac"
	"crypto/sha1"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	// relayDirectoryAnnounceTimeout bounds one discovery pass. Discovery runs
	// on a ten-minute loop in the background, so a slow tracker must never
	// hold the caller: it is abandoned and picked up on the next pass.
	relayDirectoryAnnounceTimeout = 8 * time.Second

	// relayDirectoryTrackerFanout is how many trackers to ask per pass.
	// Relays announce to every tracker they know, so any single one suffices;
	// three bounds the cost while tolerating two dead trackers. Public
	// tracker lists are long and mostly stale — asking all of them is minutes
	// of timeouts for no additional relays.
	relayDirectoryTrackerFanout = 3
)

// relayDirectoryPeers asks up to relayDirectoryTrackerFanout trackers for the
// public relay directory and returns the endpoints they report.
//
// port is the announce port: pass the local UDP port to PUBLISH this node as a
// relay, or 0 to look up without publishing. That mirrors the port argument of
// dht.lookupPeers, so the two directory transports stay interchangeable.
func relayDirectoryPeers(trackers []string, port int) []string {
	if len(trackers) == 0 {
		return nil
	}
	key := relayDirectoryKey()
	peerID := buildPeerID()

	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		seen  = map[string]bool{}
		found []string
	)
	asked := 0
	for _, t := range trackers {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if asked >= relayDirectoryTrackerFanout {
			break
		}
		asked++
		wg.Add(1)
		// Trackers are independent; querying them serially would make the
		// slowest one set the latency of the whole pass.
		go func(tracker string) {
			defer wg.Done()
			var (
				resp TrackerResponse
				err  error
			)
			switch {
			case strings.HasPrefix(tracker, "udp://"):
				resp, err = doUDPTrackerAnnounce(tracker, key, peerID, port)
			case strings.HasPrefix(tracker, "http://"), strings.HasPrefix(tracker, "https://"):
				resp, err = doHTTPTrackerAnnounce(tracker, key, peerID, port)
			default:
				return
			}
			if err != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, ep := range parsePeersFromTracker(resp) {
				if !seen[ep] {
					seen[ep] = true
					found = append(found, ep)
				}
			}
		}(t)
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(relayDirectoryAnnounceTimeout):
		// Take what arrived in time; late answers are dropped and the next
		// pass will see them.
	}

	mu.Lock()
	defer mu.Unlock()
	out := make([]string, 0, len(found))
	for _, ep := range found {
		// A relay must be dialable from the public internet. A private or
		// overlay address here is a mis-announce (or a LAN address echoed
		// back by a tracker) and would burn a reservation slot on something
		// that can never forward a packet.
		if addr, err := net.ResolveUDPAddr("udp", ep); err != nil || addr == nil {
			continue
		}
		if !isValidPeer(ep) {
			continue
		}
		out = append(out, ep)
	}
	if len(out) > 0 {
		log.Printf("[relay] tracker directory returned %d relay endpoint(s)", len(out))
	}
	return out
}

// relayGroupKey is the per-network key a client presents to a relay. It is
// the same blinded key the desktop derives in dht.go: HMAC-SHA1 over the
// network name, keyed by the PSK, so the public swarm cannot correlate a
// relay reservation with a network name — and rotating the PSK rotates the
// key, which silently evicts revoked members from relay pairing too.
//
// It MUST stay byte-identical to client/dht.go's dhtKey, or a phone and a
// desktop on the same overlay present different groups and the relay, which
// only ever pairs within a group, will never introduce them to each other.
// That failure would be invisible: both ends hold healthy reservations and
// simply never meet.
func relayGroupKey(networkName string, psk []byte) []byte {
	if len(psk) == 0 {
		return deriveInfoHash(networkName)
	}
	m := hmac.New(sha1.New, psk)
	m.Write([]byte("apgo-dht-v1|"))
	m.Write([]byte(networkName))
	return m.Sum(nil)[:20]
}
