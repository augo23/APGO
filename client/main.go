package main

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/flynn/noise"
	"github.com/pierrec/lz4/v4"
	"golang.org/x/crypto/curve25519"
	"gopkg.in/yaml.v3"
)

type CompressionConfig struct {
	Enabled bool
	MinSize int
}

var compressionCfg = CompressionConfig{
	Enabled: true,
	MinSize: 64,
}

var (
	trackerOffset   int
	trackerOffsetMu sync.Mutex
)

type CompressedPacketTag [4]byte

var compressedTag = CompressedPacketTag{0xCF, 0x4C, 0x36, 0x42}

type TunConfig struct {
	Name        string `yaml:"name"`
	AddressCIDR string `yaml:"address_cidr"`
	MTU         int    `yaml:"mtu"`
}

type ClientConfig struct {
	NetworkName    string `yaml:"network_name"`
	NodePrivateKey string `yaml:"node_private_key"`
	PSK            string `yaml:"psk"`
	// FriendlyName is a human label this node advertises to peers (shown in the
	// admin dashboard). Optional; also settable via the FRIENDLY_NAME env var and
	// remotely by an admin-signed provision.
	FriendlyName string `yaml:"friendly_name"`
	// OverlayCIDR is the overlay subnet (e.g. "10.28.55.0/24"). Each node
	// derives its own address inside this subnet from its public key, so
	// no per-node IP configuration is needed. Overridable per node by
	// setting tun.address_cidr explicitly, and per deployment with the
	// OVERLAY_CIDR environment variable.
	OverlayCIDR                string    `yaml:"overlay_cidr"`
	Tun                        TunConfig `yaml:"tun"`
	UDPListenPort              int       `yaml:"udp_listen_port"`
	STUNServers                []string  `yaml:"stun_servers"`
	AnnounceOnlyOnIPChange     bool      `yaml:"announce_only_on_ip_change"`
	Trackers                   []string  `yaml:"trackers"`
	TrackerListFile            string    `yaml:"tracker_list_file"`
	// RendezvousServers are HTTP(S) discovery servers used INSTEAD OF or in
	// addition to BitTorrent trackers — essential on networks that block
	// BitTorrent. Each is a base URL (e.g. https://rv.example.com); the client
	// POSTs to <url>/api/rendezvous. Also settable via RENDEZVOUS_SERVERS
	// (comma-separated).
	RendezvousServers []string `yaml:"rendezvous_servers"`
	ControllerURL              string    `yaml:"controller_url"`
	MinAnnounceIntervalSeconds int       `yaml:"min_announce_interval_seconds"`
	Compression                bool      `yaml:"compression"`
	// Cipher selects the transport AEAD: "chacha" (default; fast in
	// software everywhere) or "aesgcm" (uses AES-NI hardware acceleration
	// on x86 — noticeably faster there). MUST be identical on every node.
	Cipher string `yaml:"cipher"`
	// PostQuantum enables the hybrid post-quantum layer (ML-KEM-768 on top of
	// classical Noise). ON by default — quantum-safe is the default posture.
	// MUST be enabled on both peers to engage; mixed networks fall back to
	// classical per-peer. Set post_quantum: false / POST_QUANTUM=0 to disable.
	// See pq.go / the README (perf note).
	PostQuantum bool `yaml:"post_quantum"`
	// PQAuth mixes the PSK into the Noise handshake key schedule (XXpsk0) for
	// quantum-resistant AUTHENTICATION. ON by default. It changes the handshake
	// wire format, so every node must match — disable network-wide (pq_auth:
	// false / PQ_AUTH=0) only if the fleet still runs builds that predate it.
	PQAuth bool `yaml:"pq_auth"`
	// PortPrediction enables symmetric-NAT hole punching: this node probes
	// its NAT's port-allocation pattern and advertises a spread of predicted
	// ports in connect signaling. Off by default (it emits a small burst of
	// packets that aggressive firewalls may flag). Toggle per node with the
	// PORT_PREDICTION environment variable. Only takes effect behind a
	// symmetric NAT; port-stable NATs ignore it.
	PortPrediction  bool `yaml:"port_prediction"`
	// IPv6 enables the dual-stack transport: bind on :: and advertise/dial
	// global IPv6 endpoints (no NAT on v6, which fixes CGNAT/hotspot). ON by
	// default. The overlay itself stays IPv4 regardless. Set false to force the
	// transport to IPv4 only. Also settable via the IPV6 environment variable.
	IPv6            bool `yaml:"ipv6"`
	TrackEncryption bool `yaml:"track_encryption"`
	StaticPeers                []string  `yaml:"static_peers"`
	// TrackerMode controls how this node participates in the tracker swarm.
	//   "bootstrap" (default) — announces with the real UDP port so other
	//                           nodes can discover this peer.
	//   "passive"             — announces with port=0, which hides this node
	//                           from the swarm peer list while still allowing
	//                           it to receive and connect to bootstrap peers.
	//                           Use a low min_announce_interval_seconds (e.g.
	//                           30) in passive configs for fast re-discovery.
	TrackerMode string `yaml:"tracker_mode"`
	// KeepaliveSeconds is the per-peer NAT keepalive interval. Default 10s —
	// chosen to survive aggressive consumer/carrier NATs whose UDP mappings
	// expire in as little as 15-30s (the old 20s tick left such users with
	// intermittent one-way sessions). Raise it on networks you control to
	// save (tiny amounts of) bandwidth; clamped to 5..120. Also settable via
	// KEEPALIVE_SECONDS.
	KeepaliveSeconds int `yaml:"keepalive_seconds"`
	// ExitNode makes this node an internet exit ("outproxy"): it forwards and
	// NATs internet-bound traffic for overlay clients (Linux only). UseExit makes
	// this node route its OWN internet traffic through an exit (full VPN).
	ExitNode bool `yaml:"exit_node"`
	UseExit  bool `yaml:"use_exit"`
	// ExitPeer pins WHICH exit carries this node's internet traffic when
	// use_exit is on. Blank (default) = automatic: the fastest reachable exit,
	// re-probed every ~5 minutes. Set it to a specific node's overlay IP,
	// friendly name, base64 public key, or key-fingerprint prefix to always
	// egress through that one node (traffic pauses — is never re-routed
	// elsewhere — while the pinned exit is unreachable). Also settable via
	// the EXIT_PEER environment variable.
	ExitPeer string `yaml:"exit_peer"`
}

// myOverlayIP is this node's overlay address (no mask), set once in main()
// before any traffic goroutine starts. Announced to peers in control frames
// for routing and address-conflict detection.
var myOverlayIP string

// noiseCipher is the AEAD used for handshakes and transport. Default is
// ChaCha20-Poly1305 (fast everywhere, no hardware needed). "aesgcm" uses
// Go's AES-GCM, which reaches AES-NI hardware speeds on x86 — set the same
// value on EVERY node or handshakes will fail.
var noiseCipher noise.CipherFunc = noise.CipherChaChaPoly

// aeadTagLen is the authentication-tag overhead added by the transport AEAD.
// Both supported ciphers (ChaCha20-Poly1305 and AES-256-GCM) use a fixed
// 16-byte tag, so an outbound frame buffer can be sized exactly up front and
// the ciphertext appended in place — no second buffer, no copy.
const aeadTagLen = 16

// Control frames ride INSIDE the encrypted tunnel as plaintext payloads
// prefixed with ctlMagic (a real IPv4 packet can never start with 'O').
//
//	OVLYCTL1 A <ip>                       — "my overlay IP is <ip>" (announce)
//	OVLYCTL1 R <ipv4 packet>              — "please forward this one hop" (relay)
//	OVLYCTL1 C <dstIP>|<srcIP>|<srcEP>    — connect-request (relayed signaling)
//	OVLYCTL1 K <dstIP>|<srcIP>|<srcEP>    — connect-ack       (relayed signaling)
//
// C/K are the coordinated-hole-punch signaling. When A can only reach B
// through a relay, A sends a connect-request THROUGH the relay carrying A's
// public (STUN-reflexive) endpoint. B replies with a connect-ack carrying
// its own. Both then punch toward each other within the same ~8s msg1-blast
// window, so their NAT pinholes open together and a DIRECT session forms —
// which then auto-promotes over the relay. No tracker round-trip involved,
// so recovery is sub-second instead of minutes.
var ctlMagic = []byte("OVLYCTL1")

// gKP / gPSK are the node keypair and PSK, set once in main() so control
// handlers (which run in the read loop) can launch handshakes without
// threading them through every call.
var (
	gKP  keypair
	gPSK []byte
)

// connectAttempt throttles how often we kick off a coordinated-connect
// toward a given destination, so relaying a burst of packets doesn't emit a
// storm of signaling frames.
var (
	connectAttemptMu sync.Mutex
	connectAttempt   = map[string]time.Time{}
)

const connectAttemptInterval = 15 * time.Second

func shouldTryConnect(dstIP string) bool {
	connectAttemptMu.Lock()
	defer connectAttemptMu.Unlock()
	if t, ok := connectAttempt[dstIP]; ok && time.Since(t) < connectAttemptInterval {
		return false
	}
	connectAttempt[dstIP] = time.Now()
	return true
}

// currentPublicEndpoint returns our best-known public UDP endpoint (the STUN
// reflexive address), or "" if STUN hasn't succeeded yet.
func currentPublicEndpoint() string {
	mu.Lock()
	defer mu.Unlock()
	return lastPublicIP
}

// buildConnectFrame assembles a C/K signaling frame.
func buildConnectFrame(kind byte, dstIP, srcIP, srcEndpoint string) []byte {
	payload := dstIP + "|" + srcIP + "|" + srcEndpoint
	return append(append(append([]byte{}, ctlMagic...), kind), []byte(payload)...)
}

// sendControlToward emits a control frame that ORIGINATES here toward
// overlayIP: unicast if we have a direct session to it, otherwise broadcast
// to every established peer so whichever one can reach the destination
// relays it. Safe to broadcast because relays forward with
// forwardControlToward (unicast-only), so a frame is never re-broadcast.
func sendControlToward(overlayIP string, frame []byte) {
	if a := ipLearning.Lookup(overlayIP); a != nil {
		if s := GlobalSessions.GetByAddr(a); s != nil && s.Established() {
			_ = sendPacket(GlobalConn, a, s, frame)
			return
		}
	}
	for _, addr := range GlobalSessions.EstablishedAddrs() {
		if s := GlobalSessions.GetByAddr(addr); s != nil && s.Established() {
			_ = sendPacket(GlobalConn, addr, s, frame)
		}
	}
}

// forwardControlToward relays SOMEONE ELSE'S control frame one hop, and ONLY
// over a direct session to the destination. It never broadcasts: that would
// let two relays that both lack a direct route bounce the frame back and
// forth forever. If we don't have a direct session to overlayIP, we drop it
// — some other relay that does will carry it.
func forwardControlToward(overlayIP string, frame []byte) {
	if a := ipLearning.Lookup(overlayIP); a != nil {
		if s := GlobalSessions.GetByAddr(a); s != nil && s.Established() {
			_ = sendPacket(GlobalConn, a, s, frame)
		}
	}
}

var (
	lastPublicIP     string
	lastAnnounceTime time.Time
	mu               sync.Mutex
	tunIF            io.ReadWriteCloser
	// sessions / GlobalSessions / GlobalConn are populated in main() once
	// the real UDP listener exists. They start nil; callers that run
	// before main() finishes setup must not touch them.
	sessions       *SessionTable
	ipLearning     = NewIPLearningTable()
	GlobalSessions *SessionTable
	GlobalConn     *net.UDPConn
)

func loadConfig() (*ClientConfig, error) {
	p := os.Getenv("CLIENT_CONFIG")
	if p == "" {
		p = "/config/client.yaml"
	}
	// Post-quantum is ON by default (confidentiality AND handshake auth): absent
	// keys stay true; only an explicit `post_quantum: false` / `pq_auth: false`
	// (or POST_QUANTUM=0 / PQ_AUTH=0) disables them. yaml.v3 only overwrites keys
	// present in the file, so these defaults survive decode. NOTE: pq_auth changes
	// the handshake wire format — every node must run a build that has it (any
	// recent build does), so keep the whole fleet on the same version.
	cfg := ClientConfig{PostQuantum: true, PQAuth: true, IPv6: true}
	if f, err := os.Open(p); err == nil {
		defer f.Close()
		if err := yaml.NewDecoder(f).Decode(&cfg); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	// A missing config file is OK: the client can be configured entirely from the
	// environment (e.g. Kubernetes Secrets). Below, env vars override the file.

	if env := os.Getenv("NETWORK_NAME"); env != "" {
		cfg.NetworkName = env
	}
	if env := os.Getenv("PSK"); env != "" {
		cfg.PSK = env
	}
	if env := os.Getenv("NODE_KEY_FILE"); env != "" {
		cfg.NodePrivateKey = env
	}
	if cfg.NodePrivateKey == "" {
		cfg.NodePrivateKey = "/state/node.key"
	}
	if env := os.Getenv("OVERLAY_CIDR"); env != "" {
		cfg.OverlayCIDR = env
	}
	if cfg.OverlayCIDR == "" {
		cfg.OverlayCIDR = "10.28.55.0/24"
	}
	if env := strings.TrimSpace(os.Getenv("RENDEZVOUS_SERVERS")); env != "" {
		for _, s := range strings.Split(env, ",") {
			if s = strings.TrimSpace(s); s != "" {
				cfg.RendezvousServers = append(cfg.RendezvousServers, s)
			}
		}
	}
	switch strings.ToLower(os.Getenv("PORT_PREDICTION")) {
	case "1", "true", "yes", "on":
		cfg.PortPrediction = true
	case "0", "false", "no", "off":
		cfg.PortPrediction = false
	}
	switch strings.ToLower(os.Getenv("EXIT_NODE")) {
	case "1", "true", "yes", "on":
		cfg.ExitNode = true
	}
	switch strings.ToLower(os.Getenv("USE_EXIT")) {
	case "1", "true", "yes", "on":
		cfg.UseExit = true
	}
	// EXIT_PEER pins one specific node as the outproxy (overlay IP, friendly
	// name, base64 public key, or key-fingerprint prefix). Blank = fastest.
	if env := strings.TrimSpace(os.Getenv("EXIT_PEER")); env != "" {
		cfg.ExitPeer = env
	}
	if env := os.Getenv("KEEPALIVE_SECONDS"); env != "" {
		if n, err := strconv.Atoi(env); err == nil && n > 0 {
			cfg.KeepaliveSeconds = n
		}
	}
	// OVERLAY_ADDRESS pins this node's overlay IP (static assignment),
	// overriding both tun.address_cidr and the key-derived auto IP.
	// Accepts "10.28.55.2" or "10.28.55.2/24"; a bare IP inherits the
	// subnet mask from overlay_cidr.
	if env := os.Getenv("OVERLAY_ADDRESS"); env != "" {
		cfg.Tun.AddressCIDR = env
	}
	if cfg.Compression {
		compressionCfg.Enabled = true
		log.Println("[config] compression enabled")
	} else {
		compressionCfg.Enabled = false
		log.Println("[config] compression disabled")
	}
	if cfg.MinAnnounceIntervalSeconds == 0 {
		cfg.MinAnnounceIntervalSeconds = 900
	}
	if cfg.TrackerMode == "" {
		cfg.TrackerMode = "bootstrap"
	}
	if cfg.TrackerMode != "bootstrap" && cfg.TrackerMode != "passive" {
		return nil, fmt.Errorf("tracker_mode must be \"bootstrap\" or \"passive\", got %q", cfg.TrackerMode)
	}
	switch cfg.Cipher {
	case "", "chacha", "chacha20poly1305":
		noiseCipher = noise.CipherChaChaPoly
		gCipherName = "chacha"
	case "aesgcm", "aes-gcm", "aes":
		noiseCipher = noise.CipherAESGCM
		gCipherName = "aesgcm"
		log.Println("[config] cipher=AES-GCM (hardware accelerated on x86)")
	default:
		return nil, fmt.Errorf("cipher must be \"chacha\" or \"aesgcm\", got %q", cfg.Cipher)
	}
	// NAT keepalive cadence: default 10s, clamped 5..120. A healthy session
	// receives the peer's keepalive every interval, so anything quiet for ~3
	// intervals is a dead path — that drives sessionStaleTimeout below.
	if cfg.KeepaliveSeconds == 0 {
		cfg.KeepaliveSeconds = 10
	}
	if cfg.KeepaliveSeconds < 5 {
		cfg.KeepaliveSeconds = 5
	}
	if cfg.KeepaliveSeconds > 120 {
		cfg.KeepaliveSeconds = 120
	}
	gKeepaliveInterval = time.Duration(cfg.KeepaliveSeconds) * time.Second
	sessionStaleTimeout = 3*gKeepaliveInterval + 15*time.Second
	// Passive nodes poll trackers more aggressively because they are seekers,
	// not announcers. If the operator left the default 900s, drop it to 30s so
	// bootstrap peers are found quickly after startup or reconnect.
	if cfg.TrackerMode == "passive" && cfg.MinAnnounceIntervalSeconds >= 900 {
		cfg.MinAnnounceIntervalSeconds = 30
	}
	return &cfg, nil
}

// deriveOverlayIP deterministically maps a node's public key to an address
// inside the overlay subnet. Every node runs the same computation on its
// own key, so no coordination, DHCP, or per-node config is required: bring
// a new machine up with the same network_name/PSK/overlay_cidr and it picks
// its own stable IP (e.g. 10.28.55.213/24). Network and broadcast addresses
// are never produced. With a /24 (253 usable hosts) the birthday-collision
// odds stay negligible for small fleets; if two nodes ever do collide, pin
// one of them with an explicit tun.address_cidr.
func deriveOverlayIP(cidr string, pub [32]byte) (string, error) {
	return deriveOverlayIPSalted(cidr, pub, 0)
}

// deriveOverlayIPSalted is deriveOverlayIP with a hop counter mixed into the
// hash. Salt 0 produces the classic (unchanged) derivation; salts 1..n give a
// deterministic sequence of alternative addresses used to self-heal when two
// nodes' derived IPs collide (see handleAddrConflict).
func deriveOverlayIPSalted(cidr string, pub [32]byte, salt int) (string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("overlay_cidr: %w", err)
	}
	ip4 := ipnet.IP.To4()
	if ip4 == nil {
		return "", errors.New("overlay_cidr must be IPv4")
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 || ones > 30 {
		return "", errors.New("overlay_cidr mask must be /30 or wider")
	}
	hostBits := uint(32 - ones)
	usable := (uint32(1) << hostBits) - 2 // exclude network + broadcast

	seed := append([]byte("OVLY-ip-v1:"), pub[:]...)
	if salt > 0 {
		seed = append(seed, []byte(fmt.Sprintf("|hop%d", salt))...)
	}
	h := sha256.Sum256(seed)
	hostNum := binary.BigEndian.Uint32(h[:4])%usable + 1 // 1 .. usable

	base := binary.BigEndian.Uint32(ip4)
	out := make(net.IP, 4)
	binary.BigEndian.PutUint32(out, base|hostNum)
	return fmt.Sprintf("%s/%d", out.String(), ones), nil
}

// --- overlay-IP conflict self-healing --------------------------------------

// addrAutoDerived marks that this node's overlay IP was auto-derived from its
// key (not pinned via config/env or assigned by an admin), so it is safe to
// hop to a different derived address when a collision is detected.
var (
	addrAutoDerived bool
	addrConflictMu  sync.Mutex
	addrHopSalt     int
	lastAddrHop     time.Time
)

// handleAddrConflict fires when a peer claims OUR overlay IP. Auto-derived
// addresses self-heal: hop deterministically to the next free derived address
// and re-announce, live (the other collider, if it also auto-derived and runs
// this build, hops to its own new address — both sides converge). Pinned or
// admin-assigned addresses never hop; that conflict is the operator's call.
func handleAddrConflict(raddr *net.UDPAddr, ip string) {
	if !addrAutoDerived {
		log.Printf("[WARN] OVERLAY IP CONFLICT: peer %s claims OUR address %s! "+
			"Two nodes were assigned the same IP — fix one assignment (admin "+
			"panel, OVERLAY_ADDRESS, or tun.address_cidr).", raddr, ip)
		return
	}
	addrConflictMu.Lock()
	defer addrConflictMu.Unlock()
	if time.Since(lastAddrHop) < 30*time.Second {
		return // hop already in flight — let the mesh converge first
	}
	for i := 0; i < 8; i++ {
		addrHopSalt++
		cand, err := deriveOverlayIPSalted(overlayCIDR, gKP.pub, addrHopSalt)
		if err != nil {
			break
		}
		candIP := stripMask(cand)
		if candIP == myOverlayIP || ipLearning.Lookup(candIP) != nil {
			continue // that one's taken too — keep hopping
		}
		lastAddrHop = time.Now()
		log.Printf("[conflict] overlay IP %s is also claimed by %s — self-healing: "+
			"hopping to %s (pin an IP via the admin panel to make this permanent)",
			ip, raddr, cand)
		applyAddressLive(cand)
		return
	}
	log.Printf("[WARN] OVERLAY IP CONFLICT: peer %s claims OUR address %s and no free "+
		"derived alternative was found — pin one node's IP via OVERLAY_ADDRESS.", raddr, ip)
}

// applyAddressLive re-addresses the overlay interface in place to a new
// admin-assigned CIDR, updates this node's overlay IP, clears the pending flag,
// and re-announces so peers relearn the mapping. Runs entirely in-process with
// the privileges the client already holds — no restart or prompt.
func applyAddressLive(newCIDR string) {
	oldIP := myOverlayIP
	if err := reAddressTUN(oldIP, newCIDR); err != nil {
		log.Printf("[provision] live re-address to %s failed: %v (applies on next restart)", newCIDR, err)
		return
	}
	if ip, _, err := net.ParseCIDR(newCIDR); err == nil && ip.To4() != nil {
		myOverlayIP = ip.To4().String()
	}
	pendingAddrMu.Lock()
	pendingAddress = ""
	pendingAddrMu.Unlock()
	log.Printf("[provision] overlay address changed %s -> %s (applied live)", oldIP, myOverlayIP)
	if GlobalSessions != nil && GlobalConn != nil {
		frame := buildAddrAnnounce()
		for _, addr := range GlobalSessions.EstablishedAddrs() {
			if s := GlobalSessions.GetByAddr(addr); s != nil && s.Established() {
				_ = sendPacket(GlobalConn, addr, s, frame)
			}
		}
	}
}

func deriveInfoHash(networkName string) []byte {
	h := sha1.Sum([]byte(networkName))
	out := make([]byte, 20)
	copy(out, h[:])
	return out
}

// buildPeerID returns a unique peer ID in the format "-OVLY01-<hex>".
// BitTorrent peer IDs MUST be exactly 20 bytes: 8-byte prefix + 6 random
// bytes → 12 hex chars. (The old 32-char ID was silently truncated on the
// UDP tracker path and rejected outright by strict HTTP trackers.)
func buildPeerID() string {
	prefix := "-OVLY01-"
	b := make([]byte, 6)
	_, err := io.ReadFull(crand.Reader, b)
	if err != nil {
		panic("crypto/rand failure")
	}
	return prefix + hex.EncodeToString(b)
}

// stunMagicCookie is the constant value at bytes [4..7] of every STUN
// message (RFC 5389 §6). The data-socket read loop uses this to recognize
// STUN responses arriving on the overlay UDP socket and route them away
// from the overlay handshake path.
var stunMagicCookie = [4]byte{0x21, 0x12, 0xA4, 0x42}

// stunPending holds the single in-flight STUN binding request, if any.
// The data-socket read loop checks this on every non-overlay packet; if
// the packet is a STUN response with a matching transaction id, it is
// handed to the callback. STUN queries are infrequent (~once per announce
// cycle), so one in-flight slot is plenty.
var (
	stunPendingMu sync.Mutex
	stunPendingCb func(reflexive string)
	stunPendingTx [12]byte
)

// dispatchSTUN parses a candidate STUN binding-response message and, if the
// transaction id matches our outstanding query, calls the registered
// callback with the reflexive endpoint (e.g. "1.2.3.4:51820"). Returns
// true if the packet was a STUN message (even if it didn't match or was an
// error response); the caller should NOT then try to process it as overlay
// traffic.
func dispatchSTUN(pkt []byte) bool {
	if len(pkt) < 20 {
		return false
	}
	// Verify the STUN magic cookie. Without this we cannot be sure it's
	// STUN at all — random UDP traffic could happen to start with any byte.
	if pkt[4] != stunMagicCookie[0] || pkt[5] != stunMagicCookie[1] ||
		pkt[6] != stunMagicCookie[2] || pkt[7] != stunMagicCookie[3] {
		return false
	}
	// Only "binding success response" (type 0x0101) is interesting. Drop
	// indications and error responses on the floor.
	msgType := binary.BigEndian.Uint16(pkt[0:2])
	if msgType != 0x0101 {
		return true
	}
	stunPendingMu.Lock()
	cb := stunPendingCb
	wantTx := stunPendingTx
	stunPendingMu.Unlock()
	if cb == nil {
		return true
	}
	// Transaction id must match.
	for i := 0; i < 12; i++ {
		if pkt[8+i] != wantTx[i] {
			return true
		}
	}
	// Walk attributes looking for XOR-MAPPED-ADDRESS (0x0020) or, as a
	// last resort, the legacy MAPPED-ADDRESS (0x0001).
	attrs := pkt[20:]
	for len(attrs) >= 4 {
		atyp := binary.BigEndian.Uint16(attrs[0:2])
		alen := int(binary.BigEndian.Uint16(attrs[2:4]))
		if 4+alen > len(attrs) {
			break
		}
		val := attrs[4 : 4+alen]
		padded := 4 + alen
		if padded%4 != 0 {
			padded += 4 - (padded % 4)
		}
		if atyp == 0x0020 && len(val) >= 8 && val[1] == 0x01 {
			// XOR-MAPPED-ADDRESS, IPv4 family. Port is XORed with the
			// first 2 bytes of the magic cookie; address is XORed with
			// the full cookie.
			xorPort := binary.BigEndian.Uint16(val[2:4])
			port := xorPort ^ binary.BigEndian.Uint16(stunMagicCookie[0:2])
			ip := make([]byte, 4)
			for i := 0; i < 4; i++ {
				ip[i] = val[4+i] ^ stunMagicCookie[i]
			}
			cb(fmt.Sprintf("%d.%d.%d.%d:%d", ip[0], ip[1], ip[2], ip[3], port))
			return true
		}
		if atyp == 0x0001 && len(val) >= 8 && val[1] == 0x01 {
			// Legacy MAPPED-ADDRESS, IPv4 family. No XOR.
			port := binary.BigEndian.Uint16(val[2:4])
			cb(fmt.Sprintf("%d.%d.%d.%d:%d", val[4], val[5], val[6], val[7], port))
			return true
		}
		if padded >= len(attrs) {
			break
		}
		attrs = attrs[padded:]
	}
	return true
}

// stunQueryOnSocket sends a STUN binding request from conn to stunServer
// and waits up to timeout for the response. The response is delivered via
// the dispatchSTUN path called by the main UDP read loop.
//
// CRITICAL: this MUST run on the same socket the overlay uses for data,
// otherwise the reflexive endpoint we discover belongs to a different NAT
// mapping than the one peers will hit when they try to reach us. That was
// the latent bug in the old fetchPublicEndpoint: it dialed a fresh
// ephemeral UDP socket, so STUN's reported port was useless for inbound
// peer traffic.
func stunQueryOnSocket(conn *net.UDPConn, stunServer string, timeout time.Duration) (string, error) {
	addr := stunServer
	if strings.HasPrefix(addr, "stun:") {
		addr = addr[5:]
	}
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return "", err
	}

	var txid [12]byte
	if _, err := io.ReadFull(crand.Reader, txid[:]); err != nil {
		return "", err
	}

	// 20-byte STUN binding request header. No attributes.
	req := make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:2], 0x0001) // Binding Request
	binary.BigEndian.PutUint16(req[2:4], 0)      // Attributes length
	copy(req[4:8], stunMagicCookie[:])
	copy(req[8:20], txid[:])

	resultCh := make(chan string, 1)
	stunPendingMu.Lock()
	stunPendingCb = func(reflexive string) {
		select {
		case resultCh <- reflexive:
		default:
		}
	}
	stunPendingTx = txid
	stunPendingMu.Unlock()
	defer func() {
		stunPendingMu.Lock()
		stunPendingCb = nil
		stunPendingMu.Unlock()
	}()

	if _, err := conn.WriteToUDP(req, raddr); err != nil {
		return "", err
	}

	select {
	case reflexive := <-resultCh:
		return reflexive, nil
	case <-time.After(timeout):
		return "", fmt.Errorf("stun timeout to %s", stunServer)
	}
}

// fetchPublicEndpoint discovers our externally-visible UDP endpoint by
// trying each configured STUN server in turn until one answers. Runs on
// the supplied overlay socket so the reflexive endpoint matches the NAT
// mapping peers will actually hit.
func fetchPublicEndpoint(conn *net.UDPConn, stunServers []string, timeout time.Duration) (string, error) {
	if len(stunServers) == 0 {
		return "", errors.New("no STUN servers configured")
	}
	perServer := timeout / time.Duration(len(stunServers))
	if perServer < 2*time.Second {
		perServer = 2 * time.Second
	}
	for _, s := range stunServers {
		ep, err := stunQueryOnSocket(conn, s, perServer)
		if err == nil && ep != "" {
			return ep, nil
		}
	}
	return "", errors.New("no STUN reflexive address")
}

// natMapping captures how this node's NAT allocates external ports, learned
// by querying several STUN servers on the SAME socket and comparing the
// external ports they each report.
//
//   - If every server reports the SAME external port, the NAT preserves the
//     port (full-cone / port-restricted / endpoint-independent). The single
//     STUN port is exactly what a peer should punch — no prediction needed.
//   - If the ports DIFFER, the NAT is symmetric: it hands out a new external
//     port per destination. The step between consecutive ports (often +1) is
//     the allocation stride, so the port it will open toward a NEW peer is
//     approximately lastPort + stride. We punch a spread around that guess.
type natMapping struct {
	ip        string // external IP (stable even on symmetric NATs)
	port      int    // most recently observed external port
	stride    int    // per-allocation port increment (0 = port-stable)
	symmetric bool
}

var (
	natMu            sync.Mutex
	natInfo          natMapping
	portPredictionOn bool
)

// ipv6Enabled gates the dual-stack transport (bind ::, advertise/dial global
// IPv6). ON by default; set by config/env before the socket is opened.
var ipv6Enabled = true

// probeNAT queries up to 3 STUN servers on conn and infers the NAT mapping
// behaviour. Must run on the overlay socket so the observed mapping is the
// one peers will actually hit.
func probeNAT(conn *net.UDPConn, stunServers []string, timeout time.Duration) (natMapping, error) {
	if len(stunServers) == 0 {
		return natMapping{}, errors.New("no STUN servers configured")
	}
	perServer := timeout / 3
	if perServer < 2*time.Second {
		perServer = 2 * time.Second
	}
	var ports []int
	var ip string
	for _, s := range stunServers {
		ep, err := stunQueryOnSocket(conn, s, perServer)
		if err != nil || ep == "" {
			continue
		}
		host, portStr, err := net.SplitHostPort(ep)
		if err != nil {
			continue
		}
		p, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}
		ip = host
		ports = append(ports, p)
		if len(ports) >= 3 {
			break
		}
	}
	if len(ports) == 0 {
		return natMapping{}, errors.New("no STUN reflexive address")
	}
	m := natMapping{ip: ip, port: ports[len(ports)-1]}
	if len(ports) >= 2 {
		allSame := true
		for _, p := range ports[1:] {
			if p != ports[0] {
				allSame = false
				break
			}
		}
		if !allSame {
			m.symmetric = true
			// Average stride across the observed allocations. Round to at
			// least 1 so a symmetric NAT always yields a moving prediction.
			span := ports[len(ports)-1] - ports[0]
			m.stride = span / (len(ports) - 1)
			if m.stride == 0 {
				m.stride = 1
			}
		}
	}
	return m, nil
}

// startNATProbing keeps natInfo fresh in the background so connect signaling
// always advertises current predictions. Runs on the overlay socket.
func startNATProbing(conn *net.UDPConn, stunServers []string) {
	update := func() {
		m, err := probeNAT(conn, stunServers, 6*time.Second)
		if err != nil {
			return
		}
		natMu.Lock()
		natInfo = m
		natMu.Unlock()
		if m.symmetric {
			log.Printf("[nat] symmetric NAT detected (ext %s, port ~%d, stride %d) — enabling port prediction",
				m.ip, m.port, m.stride)
		} else {
			log.Printf("[nat] port-stable NAT (ext %s:%d) — direct punch should work", m.ip, m.port)
		}
	}
	update()
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			update()
		}
	}()
}

// myConnectCandidates returns the comma-separated list of public endpoint
// candidates a peer should punch to reach us. For a port-stable NAT this is
// a single endpoint; for a symmetric NAT it's a spread of predicted ports
// around the next expected allocation. Falls back to the plain STUN
// reflexive endpoint if NAT probing hasn't produced anything yet.
// myUDPPort is our actual UDP listen port (no NAT translation on IPv6), used
// to build directly-dialable IPv6 candidates.
var myUDPPort int

// hasGlobalIPv6 reports whether this host currently has any global IPv6
// address (cached briefly — it's called on every connect attempt). Used to
// skip punching v6 candidates that can only fail with "no route to host".
var (
	v6CheckMu   sync.Mutex
	v6CheckAt   time.Time
	v6CheckHave bool
)

func hasGlobalIPv6() bool {
	v6CheckMu.Lock()
	defer v6CheckMu.Unlock()
	if time.Since(v6CheckAt) < 30*time.Second {
		return v6CheckHave
	}
	v6CheckAt = time.Now()
	v6CheckHave = len(globalIPv6Endpoints(1)) > 0
	return v6CheckHave
}

func myConnectCandidates() string {
	natMu.Lock()
	m := natInfo
	natMu.Unlock()

	var cands []string
	if m.ip == "" {
		if ep := currentPublicEndpoint(); ep != "" {
			cands = append(cands, ep)
		}
	} else if !portPredictionOn || !m.symmetric || m.stride == 0 {
		// Prediction disabled, or a port-stable NAT: advertise the single real
		// endpoint.
		cands = append(cands, fmt.Sprintf("%s:%d", m.ip, m.port))
	} else {
		// Symmetric: spray predicted next allocations plus the raw observed
		// port (some NATs briefly reuse the last mapping).
		for k := 1; k <= 8; k++ {
			p := m.port + k*m.stride
			if p > 0 && p < 65536 {
				cands = append(cands, fmt.Sprintf("%s:%d", m.ip, p))
			}
		}
		cands = append(cands, fmt.Sprintf("%s:%d", m.ip, m.port))
	}

	// LAN candidates: our private IPv4 addresses (real interfaces only — the
	// overlay's own TUN is filtered so peers never punch an overlay IP).
	// When a connect request is relayed through a mutual peer, a device on
	// the SAME network punches these directly. This is the deterministic
	// same-Wi-Fi path that needs no beacons at all — critical for iOS peers,
	// which can't send broadcast (no multicast entitlement) and whose beacon
	// probes are at the mercy of AP filtering.
	if myUDPPort > 0 {
		for _, n := range localIPv4Nets() {
			if ip4 := n.IP.To4(); ip4 != nil && ip4.IsPrivate() {
				cands = append(cands, fmt.Sprintf("%s:%d", ip4, myUDPPort))
			}
		}
	}
	// Always advertise our global IPv6 endpoints. Over v6 there is no NAT, so a
	// v6-capable peer can reach these directly — this is the path that fixes
	// CGNAT/hotspot without any server. The overlay stays IPv4; only the
	// transport uses v6.
	if myUDPPort > 0 {
		cands = append(cands, globalIPv6Endpoints(myUDPPort)...)
	}
	// Also advertise a router-mapped (NAT-PMP/PCP) endpoint if we have one.
	if me := getMappedEndpoint(); me != "" {
		cands = append(cands, me)
	}
	return strings.Join(cands, ",")
}

// punchCandidates fires a handshake attempt at each comma-separated
// candidate endpoint. On a symmetric peer only one will match the real
// mapping; the rest fail quickly and back off. Invalid entries are skipped.
// Unlike tracker peer lists (isValidPeer), candidates from a relayed connect
// frame legitimately include PRIVATE addresses — that's the same-LAN direct
// path. A stale/foreign private address just fails its handshake and backs
// off, so accepting them is safe (the Noise handshake authenticates peers,
// not the transport address).
func punchCandidates(candidateList string, kp keypair, psk []byte) {
	for _, c := range strings.Split(candidateList, ",") {
		c = strings.TrimSpace(c)
		if c == "" || !isPunchableAddr(c) {
			continue
		}
		addKnownPeer(c)
		go connectToPeer(c, kp, psk)
	}
}

// isPunchableAddr validates a punch candidate: well-formed host:port, not
// loopback/unspecified/multicast — private LAN addresses allowed.
func isPunchableAddr(addr string) bool {
	h, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(h)
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() {
		return false
	}
	p, err := strconv.Atoi(portStr)
	return err == nil && p > 0 && p < 65535
}

type TrackerResponse struct {
	Interval int      `json:"interval"`
	Peers    []string `json:"peers"`
}

func percentEncode(b []byte) string {
	var buf strings.Builder
	buf.Grow(len(b) * 3)
	for _, c := range b {
		fmt.Fprintf(&buf, "%%%02X", c)
	}
	return buf.String()
}

func doHTTPTrackerAnnounce(trackerURL string, infoHash []byte, peerID string, port int) (TrackerResponse, error) {
	u, err := url.Parse(trackerURL)
	if err != nil {
		return TrackerResponse{}, err
	}
	raw := fmt.Sprintf(
		"info_hash=%s&peer_id=%s&port=%d&uploaded=0&downloaded=0&left=0&compact=1&numwant=50",
		percentEncode(infoHash),
		url.QueryEscape(peerID),
		port,
	)
	// BEP7: advertise our global IPv6 so the tracker lists us in peers6 and
	// other v6-capable nodes can reach us with no NAT. Best-effort — trackers
	// that ignore it simply don't include the param.
	if v6s := globalIPv6Endpoints(port); len(v6s) > 0 {
		if host, _, err := net.SplitHostPort(v6s[0]); err == nil {
			raw += "&ipv6=" + url.QueryEscape(host)
		}
	}
	if u.RawQuery != "" {
		u.RawQuery += "&" + raw
	} else {
		u.RawQuery = raw
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(u.String())
	if err != nil {
		return TrackerResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return TrackerResponse{}, fmt.Errorf("tracker status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return TrackerResponse{}, err
	}
	// Real BitTorrent HTTP trackers reply with bencode (BEP 3). Fall back
	// to JSON only for legacy custom trackers.
	tr, bencErr := parseTrackerBencode(body)
	if bencErr == nil {
		return tr, nil
	}
	if jsonErr := json.Unmarshal(body, &tr); jsonErr == nil {
		return tr, nil
	}
	return TrackerResponse{}, fmt.Errorf("tracker response parse: %w", bencErr)
}

// defaultTrackers is the curated set of currently-reachable public UDP trackers
// (kept in sync with ios/core and the top of config/trackers.txt). The old dead
// entries (openbittorrent / leechers-paradise / pomeranian) are deliberately
// omitted — they only produce failed lookups and slow discovery.
func defaultTrackers() []string {
	return []string{
		"udp://tracker.opentrackr.org:1337/announce",
		"udp://open.demonii.com:1337/announce",
		"udp://open.stealth.si:80/announce",
		"udp://exodus.desync.com:6969/announce",
		"udp://tracker.torrent.eu.org:451/announce",
		"udp://explodie.org:6969/announce",
		"udp://opentracker.io:6969/announce",
		"udp://tracker.dler.org:6969/announce",
	}
}

func doUDPTrackerAnnounce(tracker string, infoHash []byte, peerID string, port int) (TrackerResponse, error) {
	s := strings.TrimPrefix(strings.ToLower(tracker), "udp://")
	hostPort := s
	if i := strings.IndexByte(s, '/'); i >= 0 {
		hostPort = s[:i]
	}
	raddr, err := net.ResolveUDPAddr("udp", hostPort)
	if err != nil {
		return TrackerResponse{}, err
	}
	// Unconnected socket so it can be pinned to the physical interface in
	// full-VPN mode — otherwise the announce would be routed into the overlay
	// TUN (and dropped) before an exit is even selected, deadlocking bootstrap.
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return TrackerResponse{}, err
	}
	defer conn.Close()
	pinAuxUDPSocket(conn) // no-op unless full-tunnel routes are active
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	var txid [4]byte
	if _, err := io.ReadFull(crand.Reader, txid[:]); err != nil {
		return TrackerResponse{}, err
	}

	connID := uint64(0x41727101980)
	buf := make([]byte, 16)
	binary.BigEndian.PutUint64(buf[0:8], connID)
	binary.BigEndian.PutUint32(buf[8:12], 0)
	binary.BigEndian.PutUint32(buf[12:16], binary.BigEndian.Uint32(txid[:]))
	if _, err := conn.WriteToUDP(buf, raddr); err != nil {
		return TrackerResponse{}, err
	}

	resp := make([]byte, 2048)
	n, _, err := conn.ReadFromUDP(resp)
	if err != nil || n < 16 {
		return TrackerResponse{}, fmt.Errorf("udp connect failed")
	}
	if binary.BigEndian.Uint32(resp[0:4]) != 0 || binary.BigEndian.Uint32(resp[4:8]) != binary.BigEndian.Uint32(txid[:]) {
		return TrackerResponse{}, fmt.Errorf("bad connect response")
	}
	connectionID := make([]byte, 8)
	copy(connectionID, resp[8:16])

	pkt := make([]byte, 98)
	copy(pkt[0:8], connectionID)
	binary.BigEndian.PutUint32(pkt[8:12], 1)
	binary.BigEndian.PutUint32(pkt[12:16], binary.BigEndian.Uint32(txid[:])+1)
	copy(pkt[16:36], infoHash)

	peerIDb := []byte(peerID)
	if len(peerIDb) < 20 {
		peerIDb = append(peerIDb, make([]byte, 20-len(peerIDb))...)
	}
	if len(peerIDb) > 20 {
		peerIDb = peerIDb[:20]
	}
	copy(pkt[36:56], peerIDb)

	binary.BigEndian.PutUint32(pkt[80:84], 2)
	binary.BigEndian.PutUint32(pkt[84:88], 0)

	if _, err := io.ReadFull(crand.Reader, pkt[88:92]); err != nil {
		binary.BigEndian.PutUint32(pkt[88:92], binary.BigEndian.Uint32(txid[:]))
	}
	binary.BigEndian.PutUint32(pkt[92:96], 0xFFFFFFFF)
	binary.BigEndian.PutUint16(pkt[96:98], uint16(port))

	if _, err := conn.WriteToUDP(pkt, raddr); err != nil {
		return TrackerResponse{}, err
	}
	n, _, err = conn.ReadFromUDP(resp)
	if err != nil || n < 20 {
		return TrackerResponse{}, fmt.Errorf("udp announce failed")
	}
	if binary.BigEndian.Uint32(resp[0:4]) != 1 || binary.BigEndian.Uint32(resp[4:8]) != (binary.BigEndian.Uint32(txid[:])+1) {
		return TrackerResponse{}, fmt.Errorf("bad announce response")
	}
	interval := int(binary.BigEndian.Uint32(resp[8:12]))

	var trpeers []string
	if n > 20 {
		body := resp[20:n]
		var r2 TrackerResponse
		if jsonErr := json.Unmarshal(body, &r2); jsonErr == nil && len(r2.Peers) > 0 {
			trpeers = parsePeersFromTracker(r2)
		} else if raddr.IP.To4() == nil {
			// Announced over IPv6 (BEP-15 over v6): the swarm list is compact
			// 18-byte [ip6][port] entries. Parsing them as 6-byte v4 records
			// (the old behavior) shredded every v6 peer — which matters, since
			// v6 endpoints have no NAT and connect directly.
			trpeers = parseCompactPeers6(body)
		} else {
			trpeers = parseCompactPeers(body)
		}
	}
	return TrackerResponse{Interval: interval, Peers: trpeers}, nil
}

func parsePeersFromTracker(resp TrackerResponse) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, p := range resp.Peers {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

func parseCompactPeers(body []byte) []string {
	var peers []string
	for i := 0; i+6 <= len(body); i += 6 {
		ip := net.IPv4(body[i], body[i+1], body[i+2], body[i+3])
		port := int(binary.BigEndian.Uint16(body[i+4 : i+6]))
		peers = append(peers, net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)))
	}
	return peers
}

// parseCompactPeers6 decodes BEP7 compact IPv6 peers: 18 bytes each (16-byte
// address + 2-byte port). Over IPv6 there is no NAT, so these endpoints are
// directly dialable — this is the serverless path that fixes CGNAT.
func parseCompactPeers6(body []byte) []string {
	var peers []string
	for i := 0; i+18 <= len(body); i += 18 {
		ip := make(net.IP, 16)
		copy(ip, body[i:i+16])
		port := int(binary.BigEndian.Uint16(body[i+16 : i+18]))
		peers = append(peers, net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)))
	}
	return peers
}

// globalIPv6Endpoints returns this node's globally-routable IPv6 endpoints
// (as "[addr]:port") — skipping link-local, ULA, loopback, and deprecated
// temporary addresses. Because IPv6 has no NAT, these are what we advertise so
// other v6-capable nodes can reach us directly with no hole punching.
func globalIPv6Endpoints(port int) []string {
	var out []string
	if !ipv6Enabled {
		return out // IPv6 turned off for this node
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if isVirtualInterface(iface.Name) {
			continue // never advertise ZeroTier/Tailscale/overlay addresses
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP
			if ip.To4() != nil {
				continue // IPv4
			}
			if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
				continue // skip ULA (fc00::/7) and fe80:: link-local
			}
			out = append(out, net.JoinHostPort(ip.String(), strconv.Itoa(port)))
		}
	}
	return out
}

type keypair struct{ priv, pub [32]byte }

func loadOrCreateKey(path string) (keypair, error) {
	var kp keypair
	if _, err := os.Stat(path); err == nil {
		b, err := os.ReadFile(path)
		if err != nil {
			return kp, err
		}
		b = bytes.TrimSpace(b)
		if len(b) == 64 {
			decoded, hexErr := hex.DecodeString(string(b))
			if hexErr != nil {
				return kp, fmt.Errorf("invalid hex key: %w", hexErr)
			}
			b = decoded
		}
		if len(b) != 32 {
			return kp, fmt.Errorf("invalid key length: %d (want 32-byte raw or 64-char hex)", len(b))
		}
		copy(kp.priv[:], b)
	} else {
		if _, err := io.ReadFull(crand.Reader, kp.priv[:]); err != nil {
			return kp, err
		}
		if err := os.WriteFile(path, kp.priv[:], 0600); err != nil {
			return kp, err
		}
		log.Printf("Generated new X25519 key at %s", path)
	}
	pub, err := curve25519.X25519(kp.priv[:], curve25519.Basepoint)
	if err != nil {
		return kp, err
	}
	copy(kp.pub[:], pub)
	return kp, nil
}

func parsePSK(pskStr string) ([]byte, error) {
	if pskStr == "" {
		return nil, nil
	}
	if strings.HasPrefix(pskStr, "base64:") {
		return base64.StdEncoding.DecodeString(pskStr[7:])
	}
	return nil, fmt.Errorf("unsupported PSK format; use base64:<...>")
}

func udpListener(listenPort int) (*net.UDPConn, int, error) {
	// Bind the wildcard address (IP == nil) on network "udp": Go opens a
	// DUAL-STACK socket (IPV6_V6ONLY=0) where the OS supports it, so this one
	// socket receives BOTH IPv4 and IPv6 traffic. Incoming v4 peers arrive as
	// v4-mapped addresses whose .String() normalizes back to plain a.b.c.d, so
	// the rest of the code (which keys on the string form) is unaffected. This
	// is what lets the transport fall back to IPv6 — with no NAT — while the
	// overlay itself stays IPv4 (10.x) and nothing changes for the user.
	// IPv4-only when IPv6 is disabled.
	if !ipv6Enabled {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: listenPort})
		if err != nil {
			return nil, 0, err
		}
		la := conn.LocalAddr().(*net.UDPAddr)
		return conn, la.Port, nil
	}
	addr := &net.UDPAddr{Port: listenPort}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		// Fall back to explicit IPv4 if dual-stack bind is unavailable.
		conn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: listenPort})
		if err != nil {
			return nil, 0, err
		}
	}
	la := conn.LocalAddr().(*net.UDPAddr)
	return conn, la.Port, nil
}

// maxFrameSize bounds the reusable outbound datagram buffers: the 11-byte
// header, the largest payload we ever encrypt (a full 65535-byte IP packet
// plus the 9-byte relay wrapper), and the AEAD tag. Sizing them once means
// Encrypt never has to grow — and thus abandon — a pooled buffer.
const maxFrameSize = 11 + (65535 + 9) + aeadTagLen

var (
	// framePool recycles outbound datagram buffers so steady-state forwarding
	// allocates nothing per packet. A buffer returns to the pool as soon as
	// WriteToUDP has copied it into the kernel (which it does synchronously).
	framePool = sync.Pool{New: func() any { b := make([]byte, maxFrameSize); return &b }}

	// lz4WriterPool / lz4ReaderPool recycle the LZ4 codecs (each carries
	// sizable internal block buffers) so enabling compression doesn't allocate
	// a fresh encoder/decoder per packet.
	lz4WriterPool = sync.Pool{New: func() any { return lz4.NewWriter(nil) }}
	lz4ReaderPool = sync.Pool{New: func() any { return lz4.NewReader(nil) }}
)

func compressAndFrame(data []byte) ([]byte, error) {
	if len(data) < compressionCfg.MinSize {
		return nil, errors.New("payload below MinSize, skipping compression")
	}

	var buf bytes.Buffer
	buf.Grow(len(data))

	buf.Write(compressedTag[:])

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	buf.Write(lenBuf[:])

	// Recycle the encoder; Reset re-points it at buf without allocating.
	w := lz4WriterPool.Get().(*lz4.Writer)
	w.Reset(&buf)
	_, err := w.Write(data)
	if err == nil {
		err = w.Close()
	}
	lz4WriterPool.Put(w)
	if err != nil {
		return nil, fmt.Errorf("lz4 compress: %w", err)
	}

	result := buf.Bytes()
	if len(result) >= len(data) {
		return nil, errors.New("compression not beneficial for this payload")
	}
	return result, nil
}

func decompressAndUnframe(data []byte) ([]byte, error) {
	if len(data) < 8 {
		return nil, errors.New("not a compressed frame: too short")
	}
	if !bytes.Equal(data[0:4], compressedTag[:]) {
		return nil, errors.New("not a compressed frame: wrong tag")
	}

	originalLen := binary.BigEndian.Uint32(data[4:8])
	if originalLen == 0 {
		return nil, errors.New("compressed frame: zero original length")
	}

	var buf bytes.Buffer
	buf.Grow(int(originalLen))
	// Recycle the decoder; Reset re-points it at the new source without
	// allocating a fresh decoder (and its internal block buffers) per packet.
	reader := lz4ReaderPool.Get().(*lz4.Reader)
	reader.Reset(bytes.NewReader(data[8:]))
	actualLen, err := io.Copy(&buf, reader)
	reader.Reset(nil)
	lz4ReaderPool.Put(reader)
	if err != nil {
		return nil, fmt.Errorf("lz4 decode: %w", err)
	}
	if uint32(actualLen) != originalLen {
		return nil, fmt.Errorf("lz4 decode: length mismatch (got %d, want %d)", actualLen, originalLen)
	}

	return buf.Bytes(), nil
}

// sendPacket frames a plaintext payload as
//
//	[PktData][8 bytes nonce][2 bytes length][ciphertext+MAC]
//
// then writes it to addr. The 1-byte type prefix lets the receiver
// disambiguate data packets from in-flight handshake messages. The explicit
// nonce lets the receiver decrypt out-of-order and lossy UDP streams: both
// sides no longer depend on counting packets in lockstep.
func sendPacket(conn *net.UDPConn, addr *net.UDPAddr, s *session, payload []byte) error {
	// Post-quantum: once the ML-KEM layer is established for this peer, wrap EVERY
	// frame in the ML-KEM AEAD — data, relayed packets, exit traffic, and the
	// control frames that gossip the admin key — so nothing on a direct session is
	// classical-only. The PQ negotiation frames themselves ('M'/'m') are excluded,
	// since they bootstrap the layer and must travel classically. pqWrap is a
	// no-op (returns !ok) until the layer is ready, so pre-PQ traffic is unchanged.
	if pqEnabled && s != nil && !isPQNegotiation(payload) {
		if w, ok := pqWrap(s.peerStatic, payload); ok {
			payload = w
		}
	}
	toEncrypt := payload
	if compressionCfg.Enabled {
		if compressed, err := compressAndFrame(payload); err == nil {
			toEncrypt = compressed
		}
	}

	// Reuse a pooled buffer for the whole datagram. The 11-byte header
	// ([type][8B nonce][2B len]) is laid down first, then the AEAD ciphertext
	// is appended in place directly after it: Encrypt appends to its out
	// argument, the tag length is fixed, and the pooled buffer is sized so
	// Encrypt never grows it — so the steady-state path allocates nothing and
	// avoids the separate ciphertext buffer and copy the original code did.
	const hdrLen = 11
	bufp := framePool.Get().(*[]byte)
	defer framePool.Put(bufp)
	frame := (*bufp)[:hdrLen]
	frame[0] = PktData

	// Serialize nonce allocation + encryption: the TUN reader and the
	// keepalive ticker share this cipher state.
	s.sendMu.Lock()
	nonce := s.sendNonce
	s.sendNonce++
	binary.BigEndian.PutUint64(frame[1:9], nonce)
	s.send.SetNonce(nonce)
	frame, err := s.send.Encrypt(frame, nil, toEncrypt)
	s.sendMu.Unlock()
	if err != nil {
		return err
	}

	binary.BigEndian.PutUint16(frame[9:11], uint16(len(frame)-hdrLen))
	_, err = conn.WriteToUDP(frame, addr)
	return err
}

// recvPacket decodes a data frame body (the bytes AFTER the leading PktData
// type byte): an 8-byte nonce followed by a 2-byte length-prefixed
// ciphertext. The caller is responsible for having already verified the
// type byte is PktData. Duplicate/ancient nonces are dropped before
// decryption (replay defense).
func recvPacket(s *session, body []byte) ([]byte, error) {
	if len(body) < 10 {
		return nil, io.ErrUnexpectedEOF
	}

	nonce := binary.BigEndian.Uint64(body[:8])
	n := int(binary.BigEndian.Uint16(body[8:10]))
	if 10+n > len(body) {
		return nil, io.ErrUnexpectedEOF
	}

	if !s.replayCheck(nonce) {
		return nil, errors.New("replayed or expired nonce")
	}

	s.recv.SetNonce(nonce)
	// Decrypt in place over the ciphertext (dst == ciphertext[:0]): the AEAD
	// writes the plaintext back into the read buffer instead of allocating a
	// new one. The plaintext is consumed synchronously by the single UDP
	// reader before the buffer is reused for the next datagram, so reusing the
	// storage is safe.
	pt, err := s.recv.Decrypt(body[10:10], nil, body[10:10+n])
	if err != nil {
		return nil, err
	}
	s.replayMark(nonce)

	if len(pt) >= 8 && bytes.Equal(pt[:4], compressedTag[:]) {
		decompressed, err := decompressAndUnframe(pt)
		if err != nil {
			return nil, fmt.Errorf("decompression failed: %w", err)
		}
		return decompressed, nil
	}

	return pt, nil
}

// RoamData implements endpoint roaming (PEX). A data frame arrived from an
// address with no session. If it authenticates against an established session,
// that peer has moved to a new public endpoint (NAT rebind / network change):
// adopt the new address for the session and repoint its overlay-IP routing, so
// the tunnel recovers instantly without a tracker round-trip. Returns true if a
// session was roamed onto raddr.
//
// This is safe: a frame can only authenticate under a session key held solely
// by that peer. Trial decryption uses a throwaway buffer and does NOT touch the
// replay window — the real recvPacket that follows does — and recv cipher state
// is reset via SetNonce on every decrypt, so trialing other sessions is
// harmless. Only the single UDP read goroutine calls this and mutates recv
// state, so no lock is needed for the trial; the table re-key is done locked.
func (t *SessionTable) RoamData(raddr *net.UDPAddr, body []byte) bool {
	if len(body) < 10 {
		return false
	}
	nonce := binary.BigEndian.Uint64(body[:8])
	n := int(binary.BigEndian.Uint16(body[8:10]))
	if 10+n > len(body) {
		return false
	}
	ct := body[10 : 10+n]

	type cand struct {
		key string
		s   *session
	}
	t.mu.RLock()
	cands := make([]cand, 0, len(t.byAddr))
	for k, s := range t.byAddr {
		if s.established && s.recv != nil {
			cands = append(cands, cand{k, s})
		}
	}
	t.mu.RUnlock()

	for _, c := range cands {
		c.s.recv.SetNonce(nonce)
		if _, err := c.s.recv.Decrypt(nil, nil, ct); err != nil {
			continue
		}
		// Authenticated → this peer moved. Re-key the session onto raddr.
		old := c.s.addr
		t.mu.Lock()
		if cur, ok := t.byAddr[c.key]; ok && cur == c.s {
			delete(t.byAddr, c.key)
			c.s.addr = raddr
			t.byAddr[raddr.String()] = c.s
		}
		t.mu.Unlock()
		if old != nil {
			ipLearning.RemapAddr(old, raddr)
		}
		log.Printf("[roam] peer moved %v -> %v (endpoint roaming)", old, raddr)
		return true
	}
	return false
}

// buildAddrAnnounce returns an "OVLYCTL1A<ip>" control payload advertising
// this node's overlay IP. Sent right after every handshake and as the 20s
// keepalive, so peers always have a fresh overlay-IP -> endpoint mapping
// (which is also what the relay path routes with).
func buildAddrAnnounce() []byte {
	return append(append(append([]byte{}, ctlMagic...), 'A'), []byte(myOverlayIP)...)
}

// handleControl processes a decrypted control payload from raddr.
// body is everything after the ctlMagic prefix.
func handleControl(body []byte, raddr *net.UDPAddr) {
	// Control frames carry untrusted, peer-supplied bytes. Never let a malformed
	// frame or a handler bug crash the whole node — contain it to this frame.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[control] recovered from panic handling a frame from %s: %v", raddr, r)
		}
	}()
	if len(body) < 2 {
		return
	}
	switch body[0] {
	case 'P':
		// Peer seeds the network admin public key (trust-on-first-use). Adopted
		// only if we don't already trust one.
		adoptSeededAdminPub(string(body[1:]), adminSourceLabel(raddr))
		return
	case 'Q':
		// Peer seeds the password-encrypted admin key blob (superseded by epoch).
		if storeSealedAdminKey(body[1:], true) {
			log.Printf("[adminkey] sealed admin key received from peer %s", adminSourceLabel(raddr))
		}
		return
	case 'N':
		// Peer announces its friendly name; record it against its static key.
		if s := GlobalSessions.GetByAddr(raddr); s != nil {
			setPeerName(s.peerStatic, string(body[1:]))
		}
		return
	case 'V':
		// Admin-signed provision (IP/name assignment), gossiped across the mesh.
		handleProvision(body[1:])
		return
	case 'W':
		// Admin-signed revocation/restore, gossiped across the mesh.
		handleRevocationGossip(body[1:])
		return
	case 'Y':
		// Admin-signed device approval (admission control), gossiped.
		handleApprovalGossip(body[1:])
		return
	case 'G':
		// Admin-signed network name/PSK rotation, gossiped. Restarts this node.
		handleNetConfigGossip(body[1:])
		return
	case 'D':
		// Admin-signed network policy (e.g. post-quantum on/off), applied live.
		handlePolicyGossip(body[1:])
		return
	case 'p':
		// Peer advertises its live post-quantum state (for the admin per-node view).
		if s := GlobalSessions.GetByAddr(raddr); s != nil && len(body) >= 2 {
			setPeerPQ(s.peerStatic, body[1] == 1)
		}
		return
	case 'M':
		// Post-quantum ML-KEM public-key offer (initiator → us). Encapsulate and
		// reply with the ciphertext.
		if s := GlobalSessions.GetByAddr(raddr); s != nil {
			if reply := handlePQOffer(s.peerStatic, body[1:]); reply != nil {
				_ = sendPacket(GlobalConn, raddr, s, reply)
			}
		}
		return
	case 'm':
		// Post-quantum ML-KEM ciphertext reply (responder → us). Decapsulate.
		if s := GlobalSessions.GetByAddr(raddr); s != nil {
			handlePQReply(s.peerStatic, body[1:])
		}
		return
	case 'X':
		// Peer exchange: dial any public peers we're told about.
		handlePeerExchange(body[1:], gKP, gPSK)
		return
	case 'E':
		// Peer advertises it's an internet exit node.
		handleExitAnnounce(raddr)
		return
	case 'e':
		// Exit latency ping — reply with a pong echoing the timestamp.
		handleExitPing(raddr, body[1:])
		return
	case 'r':
		// Exit latency pong — record the round-trip time.
		handleExitPong(raddr, body[1:])
		return
	case 'A':
		// Peer announces its overlay IP.
		ip := string(body[1:])
		if net.ParseIP(ip) == nil {
			return
		}
		if ip == myOverlayIP {
			handleAddrConflict(raddr, ip)
			return
		}
		ipLearning.Learn(ip, raddr)
		if s := GlobalSessions.GetByAddr(raddr); s != nil {
			setPeerOverlayIP(s.peerStatic, ip)
		}
		// A peer just announced itself (right after a handshake) — hand it our
		// peer list so a node with fewer connections catches up immediately, and
		// push the full admin/network state so it converges without waiting for
		// the slow gossip tick.
		sendPeerExchangeTo(raddr)
		syncAdminStateTo(raddr)
	case 'R':
		// Relay request: forward the inner IPv4 packet ONE hop, and only
		// over a direct established session (never relay-of-relay, so a
		// routing loop is impossible).
		pkt := body[1:]
		if !isIPv4Packet(pkt) {
			return
		}
		dst := extractIPv4Dst(pkt)
		// Never relay to OR from a revoked peer — a revoked node must not be
		// reachable through us as an intermediary.
		if isOverlayIPRevoked(dst) || isOverlayIPRevoked(extractIPv4Src(pkt)) {
			return
		}
		if dst == myOverlayIP {
			// We were the destination all along (sender had no direct
			// mapping yet). Deliver locally.
			tunIF.Write(pkt)
			return
		}
		if a := ipLearning.Lookup(dst); a != nil {
			if s := GlobalSessions.GetByAddr(a); s != nil && s.Established() {
				// Forward as a NORMAL data frame. The destination sees the
				// original src IP arriving from our endpoint and learns
				// "reach that src via this relay" — return traffic then
				// flows back through us automatically.
				_ = sendPacket(GlobalConn, a, s, pkt)
			}
		}

	case 'C', 'K':
		// Coordinated-connect signaling. Either destined for us (punch!) or
		// to be relayed one hop toward its target overlay IP.
		parts := strings.SplitN(string(body[1:]), "|", 3)
		if len(parts) != 3 {
			return
		}
		dstIP, srcIP, srcCands := parts[0], parts[1], parts[2]

		if dstIP != myOverlayIP {
			// We're the relay: forward the intact frame one hop toward
			// dstIP, unicast-only (never re-broadcast — loop prevention).
			full := append(append([]byte{}, ctlMagic...), body...)
			forwardControlToward(dstIP, full)
			return
		}

		// This signaling is for us. Punch at every candidate endpoint the
		// peer advertised (a spread of predicted ports if it's behind a
		// symmetric NAT).
		if body[0] == 'C' {
			log.Printf("[connect] punch-request from %s (candidates: %s); punching + acking", srcIP, srcCands)
		} else {
			log.Printf("[connect] punch-ack from %s (candidates: %s); punching", srcIP, srcCands)
		}
		punchCandidates(srcCands, gKP, gPSK)

		// On a request, reply with OUR candidate set so the initiator
		// punches back at the same time (relayed the reverse way).
		if body[0] == 'C' {
			if myCands := myConnectCandidates(); myCands != "" {
				ack := buildConnectFrame('K', srcIP, myOverlayIP, myCands)
				sendControlToward(srcIP, ack)
			}
		}
	}
}

func extractIPv4Src(pkt []byte) string {
	if len(pkt) < 20 || (pkt[0]>>4) != 4 {
		return ""
	}
	return net.IPv4(pkt[12], pkt[13], pkt[14], pkt[15]).String()
}

func extractIPv4Dst(pkt []byte) string {
	if len(pkt) < 20 || (pkt[0]>>4) != 4 {
		return ""
	}
	return net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19]).String()
}

// isIPv4Packet returns true if pkt looks like a parseable IPv4 datagram.
// Used to filter noop keepalives (1-byte 0x00) and other non-IP payloads
// out of the TUN write path.
func isIPv4Packet(pkt []byte) bool {
	return len(pkt) >= 20 && (pkt[0]>>4) == 4
}

func loadTrackerList(cfg *ClientConfig) []string {
	// If an admin has managed the tracker list (added/removed via the dashboard),
	// the managed file is authoritative — it fully replaces the config list so
	// removals stick.
	if mf := managedTrackerFile(); mf != "" {
		if b, err := os.ReadFile(mf); err == nil {
			out := []string{}
			seen := map[string]bool{}
			for _, line := range strings.Split(string(b), "\n") {
				s := strings.TrimSpace(line)
				if s == "" || seen[s] {
					continue
				}
				seen[s] = true
				out = append(out, s)
			}
			return out // authoritative, even if empty is unlikely (POST guards >0)
		}
	}
	list := make([]string, 0, len(cfg.Trackers)+8)
	list = append(list, cfg.Trackers...)
	// Union in the curated defaults so a flaky/dead tracker never starves
	// discovery. The old inline list included openbittorrent / leechers-paradise
	// / pomeranian, all long dead (NXDOMAIN) — exactly the failing lookups in
	// the logs. Dedup happens below.
	list = append(list, defaultTrackers()...)
	m := map[string]bool{}
	out := []string{}
	for _, t := range list {
		if !m[t] {
			m[t] = true
			out = append(out, t)
		}
	}
	return out
}

func controllerHeartbeatLoop(baseURL, peerID string) {
	if baseURL == "" {
		return
	}
	log.Printf("Heartbeat enabled, URL: %s", baseURL)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		mu.Lock()
		pub := lastPublicIP
		mu.Unlock()

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Post(
			baseURL+"/api/heartbeat",
			"application/json",
			bytes.NewReader([]byte(fmt.Sprintf(`{"NodeID":"%s","PublicEP":"%s"}`, peerID, pub))),
		)
		if err != nil {
			log.Printf("heartbeat to controller failed: %v", err)
		} else if resp != nil {
			resp.Body.Close()
		}
	}
}

// knownPeers remembers every peer endpoint we have ever learned (from
// trackers, LAN discovery, or static config) with the time we last saw it
// advertised. NAT hole punching only succeeds when BOTH sides are sending
// at the same time, so a single connection attempt at discovery time is
// nearly useless — the retry loop re-dials every known-but-unconnected
// peer until the two sides' attempts finally overlap.
var (
	knownPeersMu sync.Mutex
	knownPeers   = map[string]time.Time{}
)

const knownPeerExpiry = 30 * time.Minute

func addKnownPeer(p string) {
	knownPeersMu.Lock()
	knownPeers[p] = time.Now()
	knownPeersMu.Unlock()
}

func knownPeerList() []string {
	knownPeersMu.Lock()
	defer knownPeersMu.Unlock()
	now := time.Now()
	out := make([]string, 0, len(knownPeers))
	for p, seen := range knownPeers {
		if now.Sub(seen) > knownPeerExpiry {
			delete(knownPeers, p)
			continue
		}
		out = append(out, p)
	}
	return out
}

// holePunchRetryLoop periodically re-attempts handshakes to every known
// peer that doesn't have an established session yet. Combined with msg1
// retransmits (300ms for 8s per attempt) and the peer running the same
// loop, the two sides' windows overlap within a few cycles and the NAT
// pinholes open.
func holePunchRetryLoop(kp keypair, psk []byte) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		for _, p := range knownPeerList() {
			addr, _ := net.ResolveUDPAddr("udp", p)
			if addr == nil {
				continue
			}
			if s := GlobalSessions.GetByAddr(addr); s != nil && s.Established() {
				continue
			}
			if GlobalSessions.ShouldSkip(addr) {
				continue
			}
			go connectToPeer(p, kp, psk)
		}
	}
}

func isValidPeer(addr string) bool {
	h, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(h)
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p <= 0 || p >= 65535 {
		return false
	}
	return true
}

func isSelf(addr string, stunEndpoint string, listenPort int) bool {
	if addr == stunEndpoint {
		return true
	}
	if stunEndpoint == "" {
		return false
	}
	host, _, err := net.SplitHostPort(stunEndpoint)
	if err != nil {
		return false
	}
	return addr == net.JoinHostPort(host, strconv.Itoa(listenPort))
}

// connectToPeer is the worker spawned per tracker-discovered candidate.
func connectToPeer(annPeer string, kp keypair, psk []byte) {
	addr, _ := net.ResolveUDPAddr("udp", annPeer)
	if addr == nil {
		return
	}
	// IPv6 target but we have no global IPv6 ourselves: the write can only
	// fail ("no route to host"), and peers roaming between cellular and Wi-Fi
	// leave a trail of stale v6 endpoints in trackers/PEX that used to spam
	// the log with pointless punches every cycle. Skip silently.
	if v4 := addr.IP.To4(); v4 == nil && !hasGlobalIPv6() {
		return
	}
	// Same-site candidate: this endpoint is on OUR OWN public IP — a LAN-mate
	// seen from the outside (trackers list every node's reflexive endpoint,
	// including our neighbors'). Dialing it requires NAT hairpin, which home
	// routers either drop (endless "no handshake reply" retries against our
	// own IP) or bounce back WITHOUT rewriting the source — so the two ends
	// classify the SAME session differently (they see our private address,
	// we dialed their public one), make opposite keep/drop decisions, and
	// enter a perpetual key-desync/teardown cycle. Same-site peers are
	// reached via LAN discovery and the relay path instead; punch candidate
	// lists also carry the LAN address, which is not filtered here.
	mu.Lock()
	pubSelf := lastPublicIP
	mu.Unlock()
	if pubSelf != "" {
		if host, _, err := net.SplitHostPort(pubSelf); err == nil && addr.IP.String() == host {
			return
		}
	}
	if GlobalSessions.ShouldSkip(addr) {
		return
	}
	if s := GlobalSessions.GetByAddr(addr); s != nil && s.Established() {
		return
	}
	s, err := GlobalSessions.EnsureSession(addr, kp, psk)
	if err == nil {
		log.Printf("handshake to %s established", annPeer)
		GlobalSessions.RecordSuccess(addr)
		// Announce our overlay IP immediately so the peer can route to us
		// (and act as our relay) without waiting for the first keepalive.
		if s != nil && s.Established() && myOverlayIP != "" {
			_ = sendPacket(GlobalConn, addr, s, buildAddrAnnounce())
		}
		// Kick off the post-quantum handshake right away so the PQ layer is up
		// within one round-trip (not waiting for the 20s keepalive tick).
		if s != nil && s.Established() && pqEnabled && pqInitiator(s.peerStatic) && !pqReady(s.peerStatic) {
			if offer := buildPQOffer(s.peerStatic); offer != nil {
				_ = sendPacket(GlobalConn, addr, s, offer)
			}
		}
		return
	}
	// Lost a race to another goroutine, or lost the simultaneous-init
	// tiebreak (the responder path is completing the handshake): not a
	// real failure. Stay silent and don't increment back-off.
	if errors.Is(err, ErrHandshakeInProgress) || errors.Is(err, ErrHandshakeAborted) {
		return
	}
	log.Printf("handshake to %s failed: %v", annPeer, err)
	GlobalSessions.RecordFailure(addr)
}

// announceAndConnect announces to every tracker and spawns handshake
// attempts for each peer returned. Returns the minimum tracker interval
// reported.
//
// The announced port is taken from pubEndpoint (our STUN-discovered
// reflexive endpoint) when available, NOT the local listen port. This is
// critical: when NAT remaps source ports — common on CGNAT and some
// consumer routers — our public-facing port differs from the local port.
// Peers must connect to us at the public-facing port, so that's what we
// publish to the tracker.
func announceAndConnect(trackers []string, infoHash []byte, peerID string,
	port int, pubEndpoint string, kp keypair, psk []byte, passive bool) int {

	announcePort := port
	// Prefer the reflexive port from STUN — that's the port other peers
	// can actually reach us at through our NAT.
	if pubEndpoint != "" {
		if _, portStr, err := net.SplitHostPort(pubEndpoint); err == nil {
			if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
				announcePort = p
			}
		}
	}
	if passive {
		announcePort = 0
	}

	// Announce to trackers CONCURRENTLY (bounded). Sequential announces
	// took minutes across a long tracker list — each dead tracker costs
	// 5-10s of timeout — which delayed peer discovery so badly that the
	// two sides' hole-punch windows never overlapped.
	var (
		respMu      sync.Mutex
		seenPeers   = map[string]struct{}{}
		minInterval int
	)
	sem := make(chan struct{}, 20)
	var wg sync.WaitGroup
	for _, tr := range trackers {
		tr := tr
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			var trResp TrackerResponse
			var err error
			if strings.HasPrefix(strings.ToLower(tr), "udp://") {
				trResp, err = doUDPTrackerAnnounce(tr, infoHash, peerID, announcePort)
			} else {
				trResp, err = doHTTPTrackerAnnounce(tr, infoHash, peerID, announcePort)
			}
			if err != nil {
				log.Printf("tracker %s failed, skipping: %v", tr, err)
				return
			}

			log.Printf("tracker %s interval=%ds peers=%d", tr, trResp.Interval, len(trResp.Peers))

			var fresh []string
			respMu.Lock()
			if trResp.Interval > 0 && (minInterval == 0 || trResp.Interval < minInterval) {
				minInterval = trResp.Interval
			}
			for _, p := range trResp.Peers {
				if !isValidPeer(p) || isSelf(p, pubEndpoint, port) {
					continue
				}
				if _, dup := seenPeers[p]; dup {
					continue
				}
				seenPeers[p] = struct{}{}
				fresh = append(fresh, p)
			}
			respMu.Unlock()

			for _, p := range fresh {
				// Remember the peer for the hole-punch retry loop AND
				// try immediately.
				addKnownPeer(p)
				go connectToPeer(p, kp, psk)
			}
		}()
	}
	wg.Wait()
	return minInterval
}

// localDiscoveryPort derives a stable LAN broadcast port from the infohash
// so that nodes on the same network automatically find the right port without
// any configuration. Range 40000-49999.
func localDiscoveryPort(infoHash []byte) int {
	return 40000 + (int(infoHash[0])<<8|int(infoHash[1]))%10000
}

// startLocalDiscovery broadcasts this node's presence on the LAN every 5s and
// connects to any overlay peer it hears from. This solves the NAT hairpin
// problem when two nodes share the same public IP — they find each other via
// their private LAN addresses instead of going through the router.
//
// Beacon format (plain text, no auth needed — the Noise handshake provides
// authentication):
//
//	OVLY1:<hex_infohash>:<udp_port>\n
func startLocalDiscovery(infoHash []byte, udpPort int, kp keypair, psk []byte) {
	discPort := localDiscoveryPort(infoHash)
	infoHashHex := hex.EncodeToString(infoHash)
	beacon := fmt.Sprintf("OVLY1:%s:%d\n", infoHashHex, udpPort)

	// Listen for beacons from peers on the same LAN.
	listenAddr := &net.UDPAddr{IP: net.IPv4zero, Port: discPort}
	ln, err := net.ListenUDP("udp4", listenAddr)
	if err != nil {
		log.Printf("[local-discovery] listen on :%d failed: %v (LAN discovery disabled)", discPort, err)
		return
	}
	log.Printf("[local-discovery] listening on :%d (infohash %s)", discPort, infoHashHex[:8])

	// Receiver goroutine.
	go func() {
		buf := make([]byte, 256)
		// Per-sender reply damping (receiver is single-threaded — plain map).
		lastReply := map[string]time.Time{}
		for {
			n, raddr, err := ln.ReadFromUDP(buf)
			if err != nil {
				return
			}
			line := strings.TrimSpace(string(buf[:n]))
			// Format: OVLY1:<infohash>:<port>
			parts := strings.Split(line, ":")
			if len(parts) != 3 || parts[0] != "OVLY1" {
				continue
			}
			if parts[1] != infoHashHex {
				// Different overlay network — ignore.
				continue
			}
			peerPort, err := strconv.Atoi(parts[2])
			if err != nil || peerPort <= 0 || peerPort >= 65535 {
				continue
			}
			// Use the sender's LAN IP with the port they advertised.
			peerAddr := net.JoinHostPort(raddr.IP.String(), strconv.Itoa(peerPort))
			// Don't connect to ourselves.
			if peerPort == udpPort {
				localIPs := localInterfaceIPs()
				isSelfIP := false
				for _, lip := range localIPs {
					if lip == raddr.IP.String() {
						isSelfIP = true
						break
					}
				}
				if isSelfIP {
					continue
				}
			}
			addKnownPeer(peerAddr)
			// The beacon repeats every 5s. Skip (and don't log) if we already
			// have a live session to this peer — otherwise it spams the log and
			// re-kicks a connect that just no-ops.
			if ua, err := net.ResolveUDPAddr("udp", peerAddr); err == nil {
				if GlobalSessions.GetByAddr(ua).Established() {
					continue
				}
			}
			// Reply with our own beacon (unicast, damped to one per sender
			// per 5s) so discovery converges even when only ONE side's probes
			// get through — e.g. an iPhone that heard our sweep/broadcast but
			// whose own probes were lost (iOS can't broadcast at all without
			// Apple's multicast entitlement).
			if t, ok := lastReply[raddr.IP.String()]; !ok || time.Since(t) > 5*time.Second {
				lastReply[raddr.IP.String()] = time.Now()
				_, _ = ln.WriteToUDP([]byte(beacon), &net.UDPAddr{IP: raddr.IP, Port: discPort})
			}
			log.Printf("[local-discovery] found LAN peer %s", peerAddr)
			go connectToPeer(peerAddr, kp, psk)
		}
	}()

	// Broadcaster goroutine — send to 255.255.255.255 every 5s.
	go func() {
		broadcastAddr := &net.UDPAddr{
			IP:   net.IPv4bcast,
			Port: discPort,
		}
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			// Use a fresh socket per broadcast to avoid send/recv
			// collision on the same fd.
			bc, err := net.DialUDP("udp4", nil, broadcastAddr)
			if err != nil {
				continue
			}
			pinAuxUDPSocket(bc) // keep LAN discovery off the VPN routes
			enableBroadcast(bc)
			bc.SetDeadline(time.Now().Add(time.Second))
			bc.Write([]byte(beacon))
			bc.Close()
			// Also send to each interface's subnet-directed broadcast
			// (e.g. 10.202.2.255). Some APs/switches drop the limited
			// 255.255.255.255 broadcast but pass subnet-directed ones.
			for _, ba := range subnetBroadcastAddrs() {
				sc, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: ba, Port: discPort})
				if err != nil {
					continue
				}
				pinAuxUDPSocket(sc) // keep LAN discovery off the VPN routes
				enableBroadcast(sc)
				sc.SetDeadline(time.Now().Add(time.Second))
				sc.Write([]byte(beacon))
				sc.Close()
			}
		}
	}()

	// Unicast sweep goroutine — reaches peers that can't hear broadcast at
	// all. iOS 14+ blocks sending AND receiving UDP broadcast unless the app
	// holds Apple's restricted multicast entitlement, and some APs filter
	// broadcast frames ("AP/client isolation" light). While we have no
	// established LAN peer, probe every host on our directly-attached
	// /24-or-smaller subnets with the same beacon as plain unicast, which is
	// never filtered by iOS. A phone that hears it connects back exactly as
	// it would for a broadcast beacon. Paced, and only while no LAN peer is
	// up — negligible traffic.
	go func() {
		// Two paced passes per sweep: Wi-Fi (especially phone radios in
		// power-save) drops bursts of small UDP, so a single probe per host
		// per sweep made discovery hit-or-miss.
		sweep := func() {
			targets := sweepTargets()
			if len(targets) == 0 {
				return
			}
			// One throwaway socket per sweep, pinned like the broadcaster so
			// probes never get routed into our own (or any) VPN tunnel.
			sc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
			if err != nil {
				return
			}
			pinAuxUDPSocket(sc) // keep LAN discovery off the VPN routes
			for pass := 0; pass < 2; pass++ {
				for _, dst := range targets {
					_, _ = sc.WriteToUDP([]byte(beacon), &net.UDPAddr{IP: dst, Port: discPort})
					time.Sleep(2 * time.Millisecond) // pace: don't burst the AP
				}
				time.Sleep(time.Second)
			}
			sc.Close()
		}
		// Cadence: fast for the first minute (discovery races the network
		// coming up), then every 30s — ALWAYS, even when we already have LAN
		// peers. The old 2-minute "maintenance" relaxation made a NEW device
		// on the same Wi-Fi (an iPhone especially — iOS can't send or receive
		// broadcast, so the unicast sweep is the ONLY way it and a Mac find
		// each other) wait up to 2 minutes to be discovered whenever the
		// aggressive always-on nodes had already claimed the "LAN peer" slot.
		// A /24 sweep is ≤508 tiny datagrams — negligible every 30s.
		time.Sleep(2 * time.Second)
		sweepNo := 0
		for {
			sweepNo++
			sweep()
			wait := 30 * time.Second
			if sweepNo < 12 {
				wait = 5 * time.Second
			}
			time.Sleep(wait)
		}
	}()
}

// localIPv4Nets returns the IPv4 subnet of every up, non-virtual interface.
func localIPv4Nets() []*net.IPNet {
	var out []*net.IPNet
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || isVirtualInterface(iface.Name) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.IsLoopback() || ipnet.IP.To4() == nil {
				continue
			}
			out = append(out, ipnet)
		}
	}
	return out
}

// hasEstablishedLANPeer reports whether any established session's endpoint is
// on one of our directly-attached subnets (i.e. LAN discovery already worked).
func hasEstablishedLANPeer() bool {
	if GlobalSessions == nil {
		return false
	}
	nets := localIPv4Nets()
	if len(nets) == 0 {
		return false
	}
	for _, addr := range GlobalSessions.EstablishedAddrs() {
		ip := addr.IP.To4()
		if ip == nil {
			continue
		}
		for _, n := range nets {
			if n.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// sweepTargets returns every host address on our attached subnets that are
// /24 or smaller (≤254 hosts), excluding our own IPs and the network and
// broadcast addresses. Larger subnets are skipped — sweeping a /16 would be
// 65k packets.
func sweepTargets() []net.IP {
	self := map[string]bool{}
	for _, ip := range localInterfaceIPs() {
		self[ip] = true
	}
	var out []net.IP
	for _, n := range localIPv4Nets() {
		ones, bits := n.Mask.Size()
		if bits != 32 {
			continue
		}
		if ones < 24 {
			// Wide LAN (/16, /22, multi-VLAN Wi-Fi): sweeping 65k hosts is a
			// non-starter, but SKIPPING (the old behavior) meant no unicast
			// discovery at all — fatal for iOS, which can't send or receive
			// broadcast, so a phone and a Mac on a wide subnet could NEVER
			// find each other (the tracker path can't help: same-site public
			// endpoints are hairpin traps and are deliberately not dialed).
			// Sweep the /24 slice around our own address instead — devices
			// on the same AP almost always land in the same DHCP range.
			ones = 24
		}
		ip4 := n.IP.To4()
		if ip4 == nil {
			continue
		}
		base := uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
		base &= ^uint32(0) << (32 - ones)
		size := uint32(1) << (32 - ones)
		for i := uint32(1); i < size-1; i++ {
			v := base + i
			ip := net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).To4()
			if self[ip.String()] {
				continue
			}
			out = append(out, ip)
		}
	}
	return out
}

// localInterfaceIPs returns all non-loopback IPv4 addresses on this machine.
func localInterfaceIPs() []string {
	var out []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				out = append(out, ip4.String())
			}
		}
	}
	return out
}

// isVirtualInterface reports whether an interface is a virtual/overlay device
// we must NOT use for LAN discovery or as a transport candidate — ZeroTier,
// Tailscale, WireGuard, Docker/bridges, and our own tun. Broadcasting or
// advertising on these makes APGO recursively discover itself across another
// overlay (e.g. ZeroTier), which we never want.
func isVirtualInterface(name string) bool {
	n := strings.ToLower(name)
	prefixes := []string{
		"zt",        // ZeroTier (Linux)
		"feth",      // ZeroTier (macOS)
		"tailscale", // Tailscale
		"utun",      // macOS tun (our overlay + other VPNs)
		"tun", "tap", // generic tun/tap
		"ovl", // our overlay interface
		"wg",  // WireGuard
		"docker", "br-", "veth", "virbr", "cni", "flannel", "cali", // containers/bridges
		"ppp", "ipsec", "gpd0", "tap-",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// subnetBroadcastAddrs returns the directed broadcast address of every
// non-loopback physical IPv4 interface (e.g. 10.202.2.255 for 10.202.2.203/24).
// Used as a fallback for LAN peer discovery on networks that drop
// 255.255.255.255. Virtual/overlay interfaces are excluded.
func subnetBroadcastAddrs() []net.IP {
	var out []net.IP
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagBroadcast == 0 {
			continue
		}
		if isVirtualInterface(iface.Name) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.IsLoopback() {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil {
				continue
			}
			mask := ipnet.Mask
			if len(mask) != 4 {
				continue
			}
			bc := make(net.IP, 4)
			for i := 0; i < 4; i++ {
				bc[i] = ip4[i] | ^mask[i]
			}
			out = append(out, bc)
		}
	}
	return out
}

func main() {
	// Optional file logging: when LOG_FILE is set (the admin dashboard tails
	// this shared file), mirror all log output to it in addition to stderr so
	// `docker logs` still works.
	if lf := os.Getenv("LOG_FILE"); lf != "" {
		if f, ferr := os.OpenFile(lf, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); ferr == nil {
			log.SetOutput(io.MultiWriter(os.Stderr, f))
		} else {
			log.Printf("[log] cannot open LOG_FILE %s: %v", lf, ferr)
		}
	}

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	// If the node has no network identity (no config file, no env/secret), fall
	// back to persisted web-setup, and if still unconfigured, serve the setup API
	// and wait for the admin dashboard to configure it (parity with the macOS app).
	applySetupFile(cfg)
	// An admin-signed network-name/PSK rotation (compromise recovery) overrides
	// the base config; applied before we decide whether we're configured.
	applyNetConfigFile(cfg)
	if needsSetup(cfg) {
		runSetupServerAndWait(os.Getenv("CONTROL_SOCKET")) // persists config + exits to restart configured
	}
	// Used by the admin control server to derive a peer's overlay IP from its
	// static key when no announced mapping is known yet.
	overlayCIDR = cfg.OverlayCIDR
	// Join details, exposed on the local control socket so an authenticated admin
	// panel can render a "join QR" for phones. Never leaves the localhost socket.
	gNetworkName = cfg.NetworkName
	gPSKString = cfg.PSK
	gRendezvous = cfg.RendezvousServers
	// Tracker management (admin UI add/remove): the managed file, when present, is
	// authoritative over the config list.
	gConfigTrackers = cfg.Trackers
	gTrackerFile = cfg.TrackerListFile
	if gTrackerFile == "" {
		gTrackerFile = trackerFilePath()
	}
	// Hybrid post-quantum layer (ON by default — quantum-safe by default).
	pqEnabled = cfg.PostQuantum
	if v := os.Getenv("POST_QUANTUM"); v != "" {
		pqEnabled = v == "1" || v == "true" || v == "yes"
	}
	// Quantum-resistant handshake auth (XXpsk0). ON by default; must match on
	// every node — disable only for fleets with builds that predate it.
	pqAuth = cfg.PQAuth
	if v := os.Getenv("PQ_AUTH"); v != "" {
		pqAuth = v == "1" || v == "true" || v == "yes"
	}
	if pqAuth {
		log.Printf("[handshake] quantum-resistant PSK authentication ENABLED (XXpsk0) — all nodes must match")
	}
	// Dual-stack IPv6 transport (on by default). Must be set BEFORE udpListener.
	ipv6Enabled = cfg.IPv6
	if v := os.Getenv("IPV6"); v != "" {
		ipv6Enabled = v == "1" || v == "true" || v == "yes"
	}
	// A panel-set persisted override (NODE_SETTINGS_FILE) is authoritative and
	// wins over config/env, so a toggle in any admin panel survives restarts.
	applyNodeSettings()
	if ipv6Enabled {
		log.Printf("[transport] IPv6 dual-stack ENABLED (direct v6 where available; overlay stays IPv4)")
	} else {
		log.Printf("[transport] IPv6 disabled — transport is IPv4 only")
	}

	// An admin-signed network policy (set from any admin panel) overrides the
	// local post_quantum default, so PQ can be toggled network-wide.
	applyPolicyFile()
	if pqEnabled {
		log.Printf("[pq] hybrid post-quantum layer ENABLED (ML-KEM-768 over classical Noise)")
	}

	// Optional factory reset: wipe any persisted admin key/password state BEFORE
	// loading it, so a node can be started truly fresh even when its Docker
	// volume survived a `compose down`. Trigger with APGO_RESET_ADMIN=1 or by
	// dropping a file named RESET_ADMIN next to the sealed key. NOTE: to start
	// the whole NETWORK over, reset every node together (or rotate network_name)
	// — otherwise a peer that still holds the key will re-seed it via TOFU.
	factoryResetAdminIfRequested()

	// Load the trusted admin public key, then any persisted network-wide
	// revocations (re-verified against that key) before traffic starts.
	loadAdminPublicKey()
	if rf := os.Getenv("REVOCATIONS_FILE"); rf != "" {
		revocations.load(rf)
	}
	if pf := os.Getenv("PROVISIONS_FILE"); pf != "" {
		provisions.load(pf)
	}
	// Admission approvals persist alongside revocations; default to the state dir
	// so admission control survives restarts even without explicit config.
	approvalsFile := os.Getenv("APPROVALS_FILE")
	if approvalsFile == "" {
		approvalsFile = "/state/approvals.json"
	}
	approvals.load(approvalsFile)
	// Adopt a previously-received sealed (password-encrypted) admin key so any
	// node's admin panel can sign with the admin password.
	loadSealedAdminKey()
	// Friendly name: config or FRIENDLY_NAME env (a signed provision can override
	// it below and at runtime).
	myFriendlyName = sanitizeName(cfg.FriendlyName)
	if env := strings.TrimSpace(os.Getenv("FRIENDLY_NAME")); env != "" {
		myFriendlyName = sanitizeName(env)
	}

	// Key must be loaded BEFORE the TUN is created: when no explicit
	// tun.address_cidr is configured, this node's overlay IP is derived
	// from its public key inside overlay_cidr.
	kp, err := loadOrCreateKey(cfg.NodePrivateKey)
	if err != nil {
		log.Fatalf("key: %v", err)
	}
	psk, err := parsePSK(cfg.PSK)
	if err != nil {
		log.Fatalf("psk: %v", err)
	}
	// Publish key + PSK for the control-frame handlers (coordinated connect).
	gKP = kp
	gPSK = psk

	// Now that our static key is known, apply any persisted per-node PQ policy
	// that targets this node.
	recomputeSelfPolicy()

	// Apply any persisted admin-assigned overlay address / friendly name for this
	// node before the TUN address is chosen.
	adoptSelfProvisionAtStartup(cfg, kp.pub)
	if cfg.FriendlyName != "" {
		myFriendlyName = sanitizeName(cfg.FriendlyName)
	}

	if cfg.Tun.AddressCIDR == "" {
		if cfg.OverlayCIDR == "" {
			log.Fatalf("config: set overlay_cidr (or an explicit tun.address_cidr / OVERLAY_ADDRESS)")
		}
		derived, err := deriveOverlayIP(cfg.OverlayCIDR, kp.pub)
		if err != nil {
			log.Fatalf("derive overlay IP: %v", err)
		}
		cfg.Tun.AddressCIDR = derived
		addrAutoDerived = true // eligible for conflict self-healing (address hop)
		log.Printf("[overlay] TUN address %s (auto-derived from node key)", cfg.Tun.AddressCIDR)
	} else {
		// Static assignment. Allow a bare IP by inheriting the mask from
		// overlay_cidr (default /24) so operators can write just
		// OVERLAY_ADDRESS=10.28.55.2.
		if !strings.Contains(cfg.Tun.AddressCIDR, "/") {
			ones := 24
			if cfg.OverlayCIDR != "" {
				if _, ipnet, err := net.ParseCIDR(cfg.OverlayCIDR); err == nil {
					ones, _ = ipnet.Mask.Size()
				}
			}
			cfg.Tun.AddressCIDR = fmt.Sprintf("%s/%d", cfg.Tun.AddressCIDR, ones)
		}
		log.Printf("[overlay] TUN address %s (static)", cfg.Tun.AddressCIDR)
	}

	if err := createAndConfigureTUN(cfg); err != nil {
		log.Fatalf("create TUN: %v", err)
	}
	tunIF = globalTunIF

	// This node's own overlay IP (package-level, set before any traffic
	// goroutine starts). Used to (a) tag keepalives and announces, (b)
	// filter inbound packets so only traffic addressed to us reaches the
	// TUN, and (c) detect address conflicts.
	if ip, _, err := net.ParseCIDR(cfg.Tun.AddressCIDR); err == nil && ip.To4() != nil {
		myOverlayIP = ip.To4().String()
	}

	udpConn, port, err := udpListener(cfg.UDPListenPort)
	if err != nil {
		log.Fatalf("udp listen: %v", err)
	}
	defer udpConn.Close()
	myUDPPort = port

	GlobalSessions = NewSessionTable(udpConn)
	sessions = GlobalSessions
	GlobalConn = udpConn

	// Admin control socket (a unix socket on the shared volume) — lets the
	// separate overlay-admin container list and revoke sessions. Disabled
	// unless CONTROL_SOCKET is set; the compose file sets it.
	if sock := os.Getenv("CONTROL_SOCKET"); sock != "" {
		go startControlServer(sock)
	}

	// Exit-node / full-VPN outproxy setup (NAT if we're an exit; selection loop
	// if we route our traffic through one). A panel-set exit pin persisted in
	// node settings overrides the file/env config, like the IPv6 toggle.
	if s := loadNodeSettings(); s.ExitPeer != nil {
		cfg.ExitPeer = *s.ExitPeer
	}
	initExit(cfg)
	go exitSelectionLoop()

	// Full-VPN mode on macOS/Windows: pin the transport socket to the physical
	// interface (so encrypted UDP to peers never loops back into the TUN), then
	// steer all internet-bound traffic into the TUN with two half-default
	// routes. On Linux this is a no-op (container/host routing handles it).
	if useExit {
		if err := pinTransportToPhysicalInterface(udpConn); err != nil {
			log.Printf("[exit] could not pin transport to the physical interface: %v", err)
		}
		if err := enableFullTunnelRoutes(); err != nil {
			log.Printf("[exit] could not install full-tunnel routes: %v", err)
		}
	}

	// When an admin assigns this node a new overlay IP, apply it live and
	// silently — the client already holds the interface, so no restart, prompt,
	// or privilege re-elevation is needed.
	onPendingAddress = applyAddressLive

	log.Printf("[config] compression=%v", compressionCfg.Enabled)

	passive := cfg.TrackerMode == "passive"
	if passive {
		log.Printf("[config] tracker_mode=passive (announcing port=0, polling every %ds)", cfg.MinAnnounceIntervalSeconds)
	} else {
		log.Printf("[config] tracker_mode=bootstrap (announcing port=%d)", port)
	}

	// Decrypt path (UDP -> TUN)
	go func() {
		buf := make([]byte, 65535)
		var readErrs int
		for {
			n, raddr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				// Intentional shutdown closed the socket — exit cleanly.
				if errors.Is(err, net.ErrClosed) {
					return
				}
				// Transient error: an ICMP port-unreachable surfacing on recv,
				// or the socket hiccuping across a sleep/wake or network change.
				// Do NOT kill the loop — that would leave the client permanently
				// deaf until a process restart (the classic "lost the network
				// after my laptop woke up"). Keep reading; a short backoff avoids
				// a busy-spin if the condition persists, and the announce/keepalive
				// loops re-punch sessions once packets flow again.
				readErrs++
				if readErrs <= 3 || readErrs%2000 == 0 {
					log.Printf("[transport] UDP read error (recovering, not fatal): %v", err)
				}
				time.Sleep(50 * time.Millisecond)
				continue
			}
			readErrs = 0
			if n < 1 {
				// Empty datagram. Some NATs send these as keep-alives;
				// ignore.
				continue
			}

			// Demux: run dispatchSTUN on every packet first — even if
			// byte[0] overlaps with overlay types (0x01 is both PktMsg1
			// and the high byte of STUN 0x0101), dispatchSTUN verifies
			// the magic cookie at bytes 4-7 before claiming a packet.
			// If dispatchSTUN says "not STUN", fall through to overlay
			// type check.
			if dispatchSTUN(buf[:n]) {
				continue
			}
			if !IsOverlayPacket(buf[0]) {
				continue
			}

			typ := buf[0]
			body := buf[1:n]

			delivered := GlobalSessions.Deliver(raddr, typ, body, kp, psk)
			if delivered {
				continue
			}

			// Not consumed by the handshake layer → it's data destined
			// for an established session.
			s := GlobalSessions.GetByAddr(raddr)
			if s == nil || !s.Established() {
				// Endpoint roaming (PEX): if this frame authenticates against a
				// known session, that peer moved to a new address — adopt it for
				// an instant reconnect, no tracker round-trip.
				if typ == PktData && GlobalSessions.RoamData(raddr, body) {
					s = GlobalSessions.GetByAddr(raddr)
				}
				if s == nil || !s.Established() {
					continue
				}
			}
			pt, err := recvPacket(s, body)
			if err != nil {
				// A failed decrypt is usually garbage, forgery, or a replay,
				// so a single failure must never evict the session (a third
				// party that can spoof this peer's address could tear the
				// tunnel down). But when EVERYTHING fails for multiple
				// keepalive intervals the session keys are desynced —
				// NoteDecryptFailure tears down only in that case, forcing a
				// clean re-handshake instead of a minute-long blackhole.
				logDecryptError(raddr.String(), err)
				GlobalSessions.NoteDecryptFailure(raddr)
				continue
			}
			// Successful decrypt is also liveness; refresh idle timer.
			GlobalSessions.TouchLastSeen(raddr)
			// Post-quantum: peel the ML-KEM AEAD layer FIRST (once it's up we wrap
			// EVERYTHING on a direct session — data, relayed/exit packets, and the
			// control frames that gossip the admin key), so both control and data
			// dispatch correctly below.
			if isPQPacket(pt) {
				if s := GlobalSessions.GetByAddr(raddr); s != nil {
					if inner, ok := pqUnwrap(s.peerStatic, pt); ok {
						pt = inner
					} else {
						continue // can't open — drop
					}
				} else {
					continue
				}
			}
			// Control frames (addr announces, relay requests, key gossip) ride
			// inside the tunnel with a magic prefix no IPv4 packet can have.
			if bytes.HasPrefix(pt, ctlMagic) {
				handleControl(pt[len(ctlMagic):], raddr)
				continue
			}
			// Keepalive carrying the sender's overlay IP: [0x00][4-byte IPv4].
			// Learn the mapping so overlay-IP routing stays current even when
			// no data traffic flows (bare 1-byte noops from old versions fall
			// through to the non-IPv4 drop below).
			if len(pt) == 5 && pt[0] == 0x00 {
				srcIP := net.IPv4(pt[1], pt[2], pt[3], pt[4]).String()
				if srcIP == myOverlayIP {
					handleAddrConflict(raddr, srcIP)
					continue
				}
				ipLearning.Learn(srcIP, raddr)
				if s := GlobalSessions.GetByAddr(raddr); s != nil {
					setPeerOverlayIP(s.peerStatic, srcIP)
				}
				continue
			}
			if !isIPv4Packet(pt) {
				// Drop noops and any other non-IP plaintext silently.
				continue
			}
			if ifIP := extractIPv4Src(pt); ifIP != "" {
				ipLearning.Learn(ifIP, raddr)
			}
			// We are an endpoint, not a router. When the sender doesn't yet
			// know which peer owns a destination IP it broadcasts to all
			// established sessions; without this filter every non-addressee
			// writes the packet to its TUN, and any host with IP forwarding
			// enabled re-injects it into the overlay — packets then loop
			// between nodes until TTL expiry (duplicate pings with stepped-
			// down TTLs, ICMP redirects).
			if myOverlayIP != "" {
				if dst := extractIPv4Dst(pt); dst != "" && dst != myOverlayIP {
					// As an exit node, forward internet-bound packets to the TUN so
					// the kernel routes + NATs them out (return traffic comes back
					// via the overlay). Otherwise it's not for us — drop it.
					if amExit && isInternetDst(dst) {
						tunIF.Write(pt)
						continue
					}
					// Relay transit for the RETURN path. When we relay an 'R'
					// frame, the destination learns "reach the sender via us"
					// and sends its replies back here as ORDINARY data frames
					// — but this branch used to just drop them, so relayed
					// connections passed exactly one packet and then went
					// dark. Forward one hop over a direct established
					// session, same rules as the 'R' handler: never to/from a
					// revoked node, and never back out the session it arrived
					// on (split horizon — no loops).
					if !isInternetDst(dst) &&
						!isOverlayIPRevoked(dst) && !isOverlayIPRevoked(extractIPv4Src(pt)) {
						if a := ipLearning.Lookup(dst); a != nil && a.String() != raddr.String() {
							if s := GlobalSessions.GetByAddr(a); s != nil && s.Established() {
								_ = sendPacket(GlobalConn, a, s, pt)
							}
						}
					}
					continue
				}
			}
			tunIF.Write(pt)
		}
	}()

	// Encrypt path (TUN -> UDP)
	go func() {
		pkt := make([]byte, 65535)
		for {
			n, err := tunIF.Read(pkt)
			if err != nil {
				return
			}
			ip := pkt[:n]

			// The overlay carries IPv4 only — drop IPv6 immediately instead of
			// letting it fall through to the relay-flood path (pure waste).
			if n > 0 && ip[0]>>4 == 6 {
				continue
			}
			dst := extractIPv4Dst(ip)

			// Revoked peer: drop everything destined for its overlay IP so a
			// revoked node is fully cut off (no direct path, no relay path) —
			// you can't even ping it.
			if dst != "" && isOverlayIPRevoked(dst) {
				continue
			}

			// Full-VPN mode: internet-bound packets go to the selected exit node.
			if useExit && isInternetDst(dst) {
				if ea, es := currentExit(); ea != nil {
					_ = sendPacket(udpConn, ea, es, ip)
				}
				// No exit available (or still selecting) — drop rather than leak
				// onto the overlay broadcast path.
				continue
			}

			// Fast path: we know which endpoint owns dst and have a live
			// session — unicast directly.
			if dst != "" {
				if a := ipLearning.Lookup(dst); a != nil {
					if s := GlobalSessions.GetByAddr(a); s != nil && s.Established() {
						// PQ wrapping (if enabled + ready) happens inside sendPacket.
						_ = sendPacket(udpConn, a, s, ip)
						continue
					}
					// Stale mapping (peer's NAT endpoint changed and the
					// old session died). Forget it and fall through to
					// discovery below.
					ipLearning.ForgetAddr(a)
				}
			}

			// Unknown or unreachable destination. Two-pronged discovery:
			//  1. RAW to every direct peer — if one of them IS the
			//     destination, it accepts (others filter on dst != self).
			//  2. RELAY-wrapped to every direct peer — if one of them has
			//     a direct session to the destination (which we can't
			//     reach, e.g. CGNAT-to-CGNAT), it forwards ONE hop.
			// Whichever copy arrives first teaches the destination our
			// return path, and its reply teaches us the forward path — so
			// the mesh converges on the fastest working route (direct if
			// possible, else via the most responsive relay) automatically.
			relayFrame := append(append(append([]byte{}, ctlMagic...), 'R'), ip...)

			// Coordinated-connect: while relaying keeps traffic flowing,
			// also try to UPGRADE to a direct path. Emit a connect-request
			// toward dst (throttled) carrying our public endpoint; the
			// relay forwards it, dst punches back, and a direct session
			// forms — after which the fast path above takes over and the
			// relay falls silent.
			var connectReq []byte
			if dst != "" && dst != myOverlayIP {
				if myCands := myConnectCandidates(); myCands != "" && shouldTryConnect(dst) {
					connectReq = buildConnectFrame('C', dst, myOverlayIP, myCands)
				}
			}

			for _, addr := range GlobalSessions.EstablishedAddrs() {
				if s := GlobalSessions.GetByAddr(addr); s != nil && s.Established() {
					_ = sendPacket(udpConn, addr, s, ip)
					_ = sendPacket(udpConn, addr, s, relayFrame)
					if connectReq != nil {
						_ = sendPacket(udpConn, addr, s, connectReq)
					}
				}
			}
		}
	}()

	infoHash := deriveInfoHash(cfg.NetworkName)
	peerID := buildPeerID()
	log.Printf("info_hash=%x peer_id=%s udp_port=%d", infoHash, peerID, port)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	pub, err := fetchPublicEndpoint(udpConn, cfg.STUNServers, 10*time.Second)
	if err == nil {
		lastPublicIP = pub
		log.Printf("Public endpoint: %s", pub)
	} else {
		log.Printf("STUN failed: %v (will announce with local port %d as fallback)", err, port)
		// If the router granted us a NAT-PMP/PCP mapping, announce that instead
		// of a useless local port.
		if me := getMappedEndpoint(); me != "" {
			lastPublicIP = me
			log.Printf("Using router-mapped endpoint for announce: %s", me)
		}
	}

	// Symmetric-NAT port prediction (opt-in). When enabled, probe the NAT's
	// port-allocation pattern in the background so connect signaling can
	// advertise predicted ports.
	portPredictionOn = cfg.PortPrediction
	if portPredictionOn {
		log.Printf("[config] port_prediction=on")
		startNATProbing(udpConn, cfg.STUNServers)
	}

	mu.Lock()
	lastAnnounceTime = time.Now().Add(-time.Duration(cfg.MinAnnounceIntervalSeconds) * time.Second)
	mu.Unlock()

	controllerURL := os.Getenv("CONTROLLER_BASE_URL")
	if controllerURL == "" {
		controllerURL = cfg.ControllerURL
	}
	go controllerHeartbeatLoop(controllerURL, peerID)

	// Start LAN broadcast discovery — handles same-NAT peers that the
	// tracker path cannot reach due to hairpin limitations.
	startLocalDiscovery(infoHash, port, kp, psk)

	// Serverless reachability: ask our own router (NAT-PMP/PCP) to open an
	// inbound pinhole for our listen port. On a home node this makes us
	// dialable with no port-forward, no static IP, and no VPS — roaming/CGNAT
	// peers then reach us outbound and the relay heals the rest. Best-effort:
	// silently falls back to hole punching + relay if the router says no.
	go startPortMapping(port)

	// Attempt any static peers from config immediately. They also join the
	// known-peer registry so the retry loop keeps dialing them.
	for _, p := range cfg.StaticPeers {
		peer := p
		addKnownPeer(peer)
		go connectToPeer(peer, kp, psk)
	}

	// Persistent hole-punch retries: without this, a peer discovered while
	// the other side wasn't simultaneously dialing gets exactly one 8s
	// attempt and is then forgotten until the next tracker announce.
	go holePunchRetryLoop(kp, psk)

	// On session loss: always drop overlay-IP mappings that point at the
	// dead endpoint (stale mappings blackhole the send path after the peer
	// reconnects from a new address). In passive mode, additionally re-poll
	// all trackers immediately rather than waiting for the next tick.
	GlobalSessions.SetSessionLostCallback(func(addr *net.UDPAddr) {
		ipLearning.ForgetAddr(addr)
		if !passive {
			return
		}
		log.Printf("session to bootstrap %s lost, re-polling trackers immediately", addr)
		go func() {
			pubNow, _ := fetchPublicEndpoint(udpConn, cfg.STUNServers, 8*time.Second)
			if pubNow == "" {
				mu.Lock()
				pubNow = lastPublicIP
				mu.Unlock()
			}
			announceAndConnect(loadTrackerList(cfg), infoHash, peerID, port, pubNow, kp, psk, true)
			for _, p := range cfg.StaticPeers {
				peer := p
				go connectToPeer(peer, kp, psk)
			}
		}()
	})

	// NAT keep-alive every gKeepaliveInterval (default 10s, configurable via
	// keepalive_seconds / KEEPALIVE_SECONDS), encrypted under the session's
	// send state. Payload is [0x00][our 4-byte overlay IPv4] so the receiver
	// can keep its overlay-IP -> endpoint mapping fresh even with no data
	// traffic — critical for recovering cleanly after a NAT endpoint change,
	// and for keeping short-timeout consumer/carrier NAT mappings open.
	go func() {
		ticker := time.NewTicker(gKeepaliveInterval)
		defer ticker.Stop()
		// The heavy admin-state frames (admin-key seed/blob and the ML-DSA-signed
		// records — sigs are ~3 KB each) are re-flooded roughly once a minute
		// instead of every keepalive tick. New peers converge instantly
		// (syncAdminStateTo on connect) and admin actions broadcast on change;
		// this periodic pass is a safety refresh that also catches a peer that
		// missed a packet, kept short enough that name/IP changes propagate
		// promptly.
		slowGossipEvery := int(time.Minute / gKeepaliveInterval)
		if slowGossipEvery < 1 {
			slowGossipEvery = 1
		}
		tickN := 0
		for {
			<-ticker.C
			tickN++
			heavy := tickN%slowGossipEvery == 1 // first tick + every ~5 min
			// Rebuild the keepalive payload each tick so a live address change
			// (admin provision) is reflected immediately.
			keepalive := []byte{0x00}
			if ip := net.ParseIP(myOverlayIP); ip != nil && ip.To4() != nil {
				keepalive = append(keepalive, ip.To4()...)
			}
			targets := GlobalSessions.EstablishedAddrs()
			exitAd := buildExitAnnounce() // nil unless we're an exit node

			var seed, sealed []byte
			if heavy {
				seed = buildAdminSeed()        // nil unless we trust an admin key
				sealed = buildSealedKeyFrame() // nil unless we hold the sealed blob
			}
			for _, addr := range targets {
				s := GlobalSessions.GetByAddr(addr)
				if s == nil || !s.Established() {
					continue
				}
				// Noop through the normal (nonce-framed, locked) send path.
				_ = sendPacket(GlobalConn, addr, s, keepalive)
				if seed != nil {
					_ = sendPacket(GlobalConn, addr, s, seed)
				}
				if sealed != nil {
					_ = sendPacket(GlobalConn, addr, s, sealed)
				}
				if exitAd != nil {
					_ = sendPacket(GlobalConn, addr, s, exitAd)
				}
				// PEX is per-recipient: same-site peers also get LAN endpoints.
				if pex := buildPeerExchangeFor(addr); pex != nil {
					_ = sendPacket(GlobalConn, addr, s, pex)
				}
				// Post-quantum: the initiator offers an ML-KEM public key until the
				// hybrid layer is established for this peer.
				if pqEnabled && pqInitiator(s.peerStatic) && !pqReady(s.peerStatic) {
					if offer := buildPQOffer(s.peerStatic); offer != nil {
						_ = sendPacket(GlobalConn, addr, s, offer)
					}
				}
				// Advertise our live PQ state so admin panels can show a per-node box.
				_ = sendPacket(GlobalConn, addr, s, buildPQStatus())
			}
			if heavy {
				// Periodic safety refresh of the signed records (seq-deduped on
				// receipt); the primary delivery is on-connect + on-change.
				gossipNameAndProvisions()
				gossipRevocations()
				gossipApprovals()
				gossipNetConfig()
				gossipPolicy()
			}
		}
	}()

	// Fast post-quantum negotiation. The keepalive loop only re-offers every
	// ~10s, so a single dropped (large) ML-KEM handshake packet meant the
	// quantum-safe lock took tens of seconds to appear. Re-offer every ~1.5s
	// until PQ is up (idempotent offers don't race with in-flight replies),
	// then go quiet. Only runs while a peer isn't yet PQ-ready.
	go func() {
		if !pqEnabled {
			return
		}
		t := time.NewTicker(1500 * time.Millisecond)
		defer t.Stop()
		for range t.C {
			for _, addr := range GlobalSessions.EstablishedAddrs() {
				s := GlobalSessions.GetByAddr(addr)
				if s == nil || !s.Established() || !pqInitiator(s.peerStatic) || pqReady(s.peerStatic) {
					continue
				}
				if offer := buildPQOffer(s.peerStatic); offer != nil {
					_ = sendPacket(GlobalConn, addr, s, offer)
				}
			}
		}
	}()

	// Initial announce — registers this node with every tracker (in
	// parallel) and kicks off handshake attempts to every peer returned. Also
	// announce to any HTTP(S) rendezvous servers (works where BitTorrent is
	// blocked).
	announceAndConnect(loadTrackerList(cfg), infoHash, peerID, port, pub, kp, psk, passive)
	announceRendezvous(cfg.RendezvousServers, infoHash, peerID, pub, kp, psk)
	mu.Lock()
	lastAnnounceTime = time.Now()
	mu.Unlock()

	// Re-poll scheduling. The old code waited for the tracker-reported
	// interval (~300-1800s) before polling AGAIN — but hole punching needs
	// both sides to learn about each other within a few seconds of each
	// other. A node that announced before its peer existed would not see
	// the peer for up to 30 minutes.
	//
	// New scheme: every MinAnnounceIntervalSeconds (e.g. 30s), announce to
	// a small ROTATING subset of trackers. Each individual tracker is only
	// hit every (list_len / subset) * tick ≈ 20+ minutes, which respects
	// per-tracker intervals, while this node discovers newly-announced
	// peers within one or two ticks. A full re-announce to every tracker
	// happens when our public IP changes or every 25 minutes (registration
	// refresh, since swarm entries expire after ~30-45 min).
	const trackersPerTick = 3
	baseTick := time.Duration(cfg.MinAnnounceIntervalSeconds) * time.Second
	// Self-heal cadence: while this node has ZERO established peers it is an
	// island — nothing can relay to it and nobody roams to it — so waiting out
	// a long configured tick (default 15 min) means staying invisible for up
	// to half an hour after a restart/port change. Poll fast (30s, rotating
	// subset) until the first session forms, then relax to the base tick.
	isolationTick := 30 * time.Second
	if baseTick < isolationTick {
		isolationTick = baseTick
	}

	// Wake/resume detector. A laptop that sleeps freezes the process, and the
	// monotonic clock pauses with it (on macOS AND Linux suspend), so the only
	// reliable "we just resumed" signal is a WALL-clock jump far larger than the
	// probe interval. On resume, every NAT mapping and session is stale, so we
	// signal wakeCh to interrupt the announce wait, drop stale sessions, and
	// re-announce immediately. Pure Go, no cgo — macOS, Windows and Linux.
	wakeCh := make(chan struct{}, 1)
	go func() {
		const probe = 15 * time.Second
		for {
			before := time.Now().Round(0) // .Round(0) strips monotonic → wall clock
			select {
			case <-stop:
				return
			case <-time.After(probe):
			}
			if gap := time.Now().Round(0).Sub(before); gap > probe+20*time.Second {
				log.Printf("[wake] resumed after ~%v suspended — forcing reconnect", gap.Round(time.Second))
				select {
				case wakeCh <- struct{}{}:
				default:
				}
			}
		}
	}()

	for {
		wait := baseTick
		if len(GlobalSessions.EstablishedAddrs()) == 0 {
			wait = isolationTick
		}
		select {
		case <-stop:
			log.Println("shutdown requested")
			GlobalSessions.Close()
			return
		case <-wakeCh:
			// Resume from sleep: drop every (now-stale) session so their dead
			// endpoints don't linger, then loop straight back — with zero peers
			// the node is "isolated", so it re-announces on the fast tick and
			// re-punches within seconds. Evict (not Revoke) just forgets the
			// session; it does NOT ban the peer, so we reconnect to them freely.
			addrs := GlobalSessions.EstablishedAddrs()
			log.Printf("[wake] dropping %d stale session(s) and re-announcing", len(addrs))
			for _, addr := range addrs {
				GlobalSessions.Evict(addr)
				ipLearning.ForgetAddr(addr)
			}
			continue
		case <-time.After(wait):
			pubNow, err := fetchPublicEndpoint(udpConn, cfg.STUNServers, 8*time.Second)
			if err != nil {
				// STUN couldn't reach any server. Don't break the
				// announce loop over it — fall back to the previous
				// pub (or empty), which will at least keep us using
				// the local port for tracker announces.
				mu.Lock()
				pubNow = lastPublicIP
				mu.Unlock()
			}
			isolated := len(GlobalSessions.EstablishedAddrs()) == 0
			mu.Lock()
			changed := pubNow != "" && pubNow != lastPublicIP
			staleRegistration := time.Since(lastAnnounceTime) > 25*time.Minute
			// Islanded node: refresh our registration on EVERY tracker every
			// couple of minutes (not just every 25) so peers whose entries for
			// us are stale re-learn the current endpoint quickly.
			needHeal := isolated && time.Since(lastAnnounceTime) > 2*time.Minute
			mu.Unlock()

			if changed {
				// Our public endpoint moved. Immediately blast a keepalive to
				// every live peer from the NEW source address so they roam our
				// session onto it instantly (PEX) — no tracker round-trip.
				ka := []byte{0x00}
				if ip := net.ParseIP(myOverlayIP); ip != nil && ip.To4() != nil {
					ka = append(ka, ip.To4()...)
				}
				peers := GlobalSessions.EstablishedAddrs()
				for _, addr := range peers {
					if s := GlobalSessions.GetByAddr(addr); s != nil && s.Established() {
						_ = sendPacket(GlobalConn, addr, s, ka)
					}
				}
				log.Printf("[roam] public endpoint -> %s; notified %d peer(s) directly for instant roam", pubNow, len(peers))
			}

			trackers := loadTrackerList(cfg)
			var subset []string
			fullAnnounce := changed || staleRegistration || needHeal
			if fullAnnounce {
				subset = trackers
			} else {
				trackerOffsetMu.Lock()
				off := trackerOffset % len(trackers)
				trackerOffset += trackersPerTick
				trackerOffsetMu.Unlock()
				for i := 0; i < trackersPerTick && i < len(trackers); i++ {
					subset = append(subset, trackers[(off+i)%len(trackers)])
				}
			}

			announceAndConnect(subset, infoHash, peerID, port, pubNow, kp, psk, passive)
			announceRendezvous(cfg.RendezvousServers, infoHash, peerID, pubNow, kp, psk)

			mu.Lock()
			if fullAnnounce {
				lastAnnounceTime = time.Now()
			}
			lastPublicIP = pubNow
			mu.Unlock()
		}
	}
}
