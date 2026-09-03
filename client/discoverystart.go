package main

// discoverystart.go is the one place the DHT and the two relay halves are
// configured and started, so the policy ("what is on by default, and what does
// a bad value fall back to") lives in a single readable function instead of
// being scattered through main().

import (
	"log"
	"net"
	"os"
	"strings"
	"time"
)

// Defaults chosen to be a visibly modest donation rather than a blank cheque:
// 1 MB/s each way is enough to carry several relayed tunnels comfortably and
// small enough that an operator who forgets they enabled it never notices.
const (
	defaultRelayUpLimit         = int64(1000 * 1000)
	defaultRelayDownLimit       = int64(1000 * 1000)
	defaultRelayPerCircuitLimit = int64(256 * 1000)
	defaultRelayQuotaDays       = 30
)

// gDHTKey is the blinded lookup key in use, kept for the status API.
var gDHTKey []byte

func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

// relayStatePath returns where the bandwidth ledger is persisted. It follows
// the same /state convention as the tracker list and node settings, so a
// container that already mounts /state gets quota persistence for free.
func relayStatePath() string {
	if p := os.Getenv("RELAY_STATE_FILE"); p != "" {
		return p
	}
	if p := os.Getenv("NODE_SETTINGS_FILE"); p != "" {
		return strings.TrimSuffix(p, ".json") + "-relay.json"
	}
	if _, err := os.Stat("/state"); err == nil {
		return "/state/relay-usage.json"
	}
	return ""
}

// startDiscoveryAndRelay brings up the DHT, the relay client, and (only if
// explicitly enabled) the public relay server.
func startDiscoveryAndRelay(cfg *ClientConfig, conn *net.UDPConn, port int, kp keypair, psk []byte) {
	// Persisted panel choices win over config/env, matching how the IPv6 and
	// rendezvous toggles already behave.
	ns := loadNodeSettings()

	// DEFAULT OFF, both of these. They were shipped defaulting ON and that was
	// wrong: each one attaches new behaviour to the SAME UDP socket the overlay
	// transport uses, and neither is needed by a network that already has
	// trackers or a rendezvous server working.
	//
	// The DHT feeds endpoints from the public mainline swarm straight into
	// connectToPeer. Some mainline nodes answer any get_peers with junk, so a
	// node can spend its dial budget handshaking with unrelated hosts — visible
	// as a wall of "handshake to <random internet address> failed" and a
	// doubled handshake-failure rate.
	//
	// The relay client is worse, because it does not merely add traffic — it
	// changes where traffic GOES. When a circuit opens it registers a peer at a
	// synthetic 240.0.0.0/4 address, and overlayWriteTo diverts every frame
	// bound for such an address off the socket and into that circuit. If a
	// route ever resolves to one of those addresses, data leaves the node into
	// a circuit instead of to the peer, while control frames — which the
	// keepalive loop sends by walking established sessions directly — keep
	// flowing to the real peers. Working control plane, dead data plane.
	//
	// Neither had any business being on by default on a node that was working
	// fine without them. Opt in per network once the network wants them.
	dhtOn := boolOr(cfg.DHT, false)
	if ns.DHT != nil {
		dhtOn = *ns.DHT
	}
	useRelays := boolOr(cfg.UseRelays, false)
	if ns.UseRelays != nil {
		useRelays = *ns.UseRelays
	}
	publicRelay := cfg.PublicRelay
	if ns.PublicRelay != nil {
		publicRelay = *ns.PublicRelay
	}

	// The lookup key. Blinded with the PSK unless the operator explicitly
	// asked for the plain infohash — see the DHTPublicKey comment for why
	// that is a bad idea.
	key := dhtKey(cfg.NetworkName, psk)
	if cfg.DHTPublicKey {
		key = deriveInfoHash(cfg.NetworkName)
		log.Printf("[dht] WARNING: announcing the PLAIN infohash. Anyone who " +
			"guesses network_name can enumerate this network's members on the " +
			"public DHT. Set dht_public_key: false to blind it with the PSK.")
	}
	gDHTKey = key

	if !dhtOn {
		log.Printf("[dht] disabled by configuration")
	} else {
		startDHT(conn, key, port, kp, psk)
	}

	// --- bandwidth meter, shared by both relay halves
	up := parseRate(cfg.RelayUpLimit)
	if cfg.RelayUpLimit == "" {
		up = defaultRelayUpLimit
	}
	down := parseRate(cfg.RelayDownLimit)
	if cfg.RelayDownLimit == "" {
		down = defaultRelayDownLimit
	}
	perCircuit := parseRate(cfg.RelayPerCircuitLimit)
	if cfg.RelayPerCircuitLimit == "" {
		perCircuit = defaultRelayPerCircuitLimit
	}
	quota := parseRate(cfg.RelayQuota)
	days := cfg.RelayQuotaDays
	if days <= 0 {
		days = defaultRelayQuotaDays
	}
	if ns.RelayUpLimit != nil {
		up = *ns.RelayUpLimit
	}
	if ns.RelayDownLimit != nil {
		down = *ns.RelayDownLimit
	}
	if ns.RelayQuota != nil {
		quota = *ns.RelayQuota
	}

	limits := newBandwidthLimiter(up, down, quota, days, relayStatePath())
	gBandwidth = limits

	// --- client half: use other people's relays (costs nobody anything)
	rc := startRelayClient(conn, key, port, kp, psk)
	rc.SetEnabled(useRelays)
	for _, ep := range cfg.StaticRelays {
		rc.AddRelay(ep)
	}

	// --- server half: BE a relay. Off unless asked for.
	pr := startPublicRelay(conn, limits, cfg.RelayMaxCircuits, cfg.RelayMaxPerIP, perCircuit)
	pr.SetEnabled(publicRelay)
	if publicRelay {
		go func() {
			// Advertise in the DHT directory on a slow loop. The first
			// advertisement waits for the DHT to have a routing table —
			// announcing into an empty table publishes nothing and just
			// looks, in the logs, like the relay is working when it is not.
			time.Sleep(30 * time.Second)
			for {
				if gDHT != nil && gDHT.table.Count() >= dhtK {
					pr.Advertise(port)
				}
				time.Sleep(dhtJitter(relayAdvertisePeriod))
			}
		}()
	}

	log.Printf("[discovery] dht=%v public_relay=%v use_relays=%v up=%s down=%s quota=%s/%dd",
		dhtOn, publicRelay, useRelays, formatRate(up), formatRate(down), formatRate(quota), days)
}

// gBandwidth is the live meter, exposed for the admin API.
var gBandwidth *bandwidthLimiter
