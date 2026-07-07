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
	ControllerURL              string    `yaml:"controller_url"`
	MinAnnounceIntervalSeconds int       `yaml:"min_announce_interval_seconds"`
	Compression                bool      `yaml:"compression"`
	TrackEncryption            bool      `yaml:"track_encryption"`
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
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cfg ClientConfig
	if err := yaml.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, err
	}

	if env := os.Getenv("OVERLAY_CIDR"); env != "" {
		cfg.OverlayCIDR = env
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

	h := sha256.Sum256(append([]byte("OVLY-ip-v1:"), pub[:]...))
	hostNum := binary.BigEndian.Uint32(h[:4])%usable + 1 // 1 .. usable

	base := binary.BigEndian.Uint32(ip4)
	out := make(net.IP, 4)
	binary.BigEndian.PutUint32(out, base|hostNum)
	return fmt.Sprintf("%s/%d", out.String(), ones), nil
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
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return TrackerResponse{}, err
	}
	defer conn.Close()
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
	if _, err := conn.Write(buf); err != nil {
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

	if _, err := conn.Write(pkt); err != nil {
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
	addr := &net.UDPAddr{IP: net.IPv4zero, Port: listenPort}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, 0, err
	}
	la := conn.LocalAddr().(*net.UDPAddr)
	return conn, la.Port, nil
}

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

	w := lz4.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		return nil, fmt.Errorf("lz4 compress: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("lz4 compress close: %w", err)
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
	reader := lz4.NewReader(bytes.NewReader(data[8:]))
	actualLen, err := io.Copy(&buf, reader)
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
	var toEncrypt []byte
	if compressionCfg.Enabled {
		compressed, err := compressAndFrame(payload)
		if err != nil {
			toEncrypt = payload
		} else {
			toEncrypt = compressed
		}
	} else {
		toEncrypt = payload
	}

	// Serialize nonce allocation + encryption: the TUN reader and the
	// keepalive ticker share this cipher state.
	s.sendMu.Lock()
	nonce := s.sendNonce
	s.sendNonce++
	s.send.SetNonce(nonce)
	ct, err := s.send.Encrypt(nil, nil, toEncrypt)
	s.sendMu.Unlock()
	if err != nil {
		return err
	}

	frame := make([]byte, 1+8+2+len(ct))
	frame[0] = PktData
	binary.BigEndian.PutUint64(frame[1:9], nonce)
	binary.BigEndian.PutUint16(frame[9:11], uint16(len(ct)))
	copy(frame[11:], ct)
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
	pt, err := s.recv.Decrypt(nil, nil, body[10:10+n])
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
	list := make([]string, 0, len(cfg.Trackers))
	list = append(list, cfg.Trackers...)
	if cfg.TrackerListFile != "" {
		if b, err := os.ReadFile(cfg.TrackerListFile); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				s := strings.TrimSpace(line)
				if s == "" {
					continue
				}
				list = append(list, s)
			}
		}
	}
	if len(list) == 0 {
		list = []string{
			"udp://tracker.opentrackr.org:1337/announce",
			"udp://tracker.openbittorrent.com:6969/announce",
			"udp://exodus.desync.com:6969/announce",
			"udp://tracker.torrent.eu.org:451/announce",
			"udp://tracker.leechers-paradise.org:6969/announce",
			"udp://tracker.pomeranian.cc:6969/announce",
		}
	}
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
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() {
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
	if GlobalSessions.ShouldSkip(addr) {
		return
	}
	if s := GlobalSessions.GetByAddr(addr); s != nil && s.Established() {
		return
	}
	_, err := GlobalSessions.EnsureSession(addr, kp, psk)
	if err == nil {
		log.Printf("handshake to %s established", annPeer)
		GlobalSessions.RecordSuccess(addr)
		return
	}
	// Lost a race to another goroutine: not our problem, not a real
	// failure. Stay silent and don't increment back-off.
	if errors.Is(err, ErrHandshakeInProgress) {
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
			log.Printf("[local-discovery] found LAN peer %s", peerAddr)
			addKnownPeer(peerAddr)
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
			bc.SetDeadline(time.Now().Add(time.Second))
			bc.Write([]byte(beacon))
			bc.Close()
		}
	}()
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

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("load config: %v", err)
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

	if cfg.Tun.AddressCIDR == "" {
		if cfg.OverlayCIDR == "" {
			log.Fatalf("config: set overlay_cidr (or an explicit tun.address_cidr / OVERLAY_ADDRESS)")
		}
		derived, err := deriveOverlayIP(cfg.OverlayCIDR, kp.pub)
		if err != nil {
			log.Fatalf("derive overlay IP: %v", err)
		}
		cfg.Tun.AddressCIDR = derived
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

	udpConn, port, err := udpListener(cfg.UDPListenPort)
	if err != nil {
		log.Fatalf("udp listen: %v", err)
	}
	defer udpConn.Close()

	GlobalSessions = NewSessionTable(udpConn)
	sessions = GlobalSessions
	GlobalConn = udpConn

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
		for {
			n, raddr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
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
			continue
		}
		pt, err := recvPacket(s, body)
		if err != nil {
			// With explicit nonces, a failed decrypt means garbage,
			// forgery, or a replay — never legitimate desync. Do NOT
			// evict the session; that would let any third party that
			// can spoof this peer's address tear the tunnel down.
			log.Printf("decrypt/decode error from %s: %v", raddr, err)
			continue
		}
		// Successful decrypt is also liveness; refresh idle timer.
		GlobalSessions.TouchLastSeen(raddr)
		if !isIPv4Packet(pt) {
			// Drop noops and any other non-IP plaintext silently.
			continue
		}
		if ifIP := extractIPv4Src(pt); ifIP != "" {
			ipLearning.Learn(ifIP, raddr)
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
			dst := extractIPv4Dst(ip)
			targets := GlobalSessions.EstablishedAddrs()
			if dst != "" {
				if a := ipLearning.Lookup(dst); a != nil {
					targets = []*net.UDPAddr{a}
				}
			}
			for _, addr := range targets {
				if s := GlobalSessions.GetByAddr(addr); s != nil && s.Established() {
					_ = sendPacket(udpConn, addr, s, ip)
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

	// Passive mode: when a bootstrap session is lost due to idle timeout,
	// immediately re-poll all trackers to rediscover the bootstrap peer
	// rather than waiting up to MinAnnounceIntervalSeconds for the next tick.
	if passive {
		GlobalSessions.SetSessionLostCallback(func(addr *net.UDPAddr) {
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
	}

	// NAT keep-alive: 1-byte noop encrypted under the session's send state
	// every 20s. Receiver decrypts and drops non-IPv4 plaintexts.
	go func() {
		ticker := time.NewTicker(20 * time.Second)
		defer ticker.Stop()
		for {
			<-ticker.C
			targets := GlobalSessions.EstablishedAddrs()
			for _, addr := range targets {
				s := GlobalSessions.GetByAddr(addr)
				if s == nil || !s.Established() {
					continue
				}
				// 1-byte noop through the normal (nonce-framed, locked)
				// send path. Receiver decrypts and drops non-IPv4.
				_ = sendPacket(GlobalConn, addr, s, []byte{0x00})
			}
		}
	}()

	// Initial announce — registers this node with every tracker (in
	// parallel) and kicks off handshake attempts to every peer returned.
	announceAndConnect(loadTrackerList(cfg), infoHash, peerID, port, pub, kp, psk, passive)
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
	tick := time.Duration(cfg.MinAnnounceIntervalSeconds) * time.Second
	ticker := time.NewTicker(tick)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			log.Println("shutdown requested")
			GlobalSessions.Close()
			return
		case <-ticker.C:
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
			mu.Lock()
			changed := pubNow != "" && pubNow != lastPublicIP
			staleRegistration := time.Since(lastAnnounceTime) > 25*time.Minute
			mu.Unlock()

			trackers := loadTrackerList(cfg)
			var subset []string
			fullAnnounce := changed || staleRegistration
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

			mu.Lock()
			if fullAnnounce {
				lastAnnounceTime = time.Now()
			}
			lastPublicIP = pubNow
			mu.Unlock()
		}
	}
}
