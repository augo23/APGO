package main

// netshare.go — admin-signed "share this device into a network" records.
//
// Sharing a device into a secondary (e.g. guest) network means that device
// runs the network's profile. Rather than hand-configuring every device, the
// admin panel signs a NetShare record for the target device's static key and
// hands it to the local client, which floods it across the MAIN network's
// mesh like revocations/approvals. The target node applies it: it persists
// the network profile and its supervisor starts (or stops) the instance.
//
//	OVLYCTL1 S <json>   — SignedNetShare gossip
//
// The network PSK never travels in the clear, even inside the encrypted
// tunnel: it is sealed to the TARGET's X25519 static key (ephemeral-static
// ECDH + AES-256-GCM — see sealPSKTo for the exact construction, mirrored in
// the admin and desktop panels), so relaying nodes carry only ciphertext they
// cannot open. Everything else is integrity-bound by the admin's signature
// (ML-DSA, same trust root as revocations), replay-guarded by a
// per-target+network Seq.
//
// Records persist (NETSHARES_FILE, default /state/netshares.json) so a target
// that was offline picks the share up from any node that stored it. Only the
// MAIN instance handles share records — children ignore the frame, so a
// record can never recurse into a child of a child.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"

	"golang.org/x/crypto/curve25519"
)

// SignedNetShare instructs the target node to join ("share") or leave
// ("unshare") the named secondary network.
type SignedNetShare struct {
	Action      string `json:"action"` // "share" | "unshare"
	PubKey      string `json:"pubkey"` // base64 target 32-byte X25519 static key
	NetworkName string `json:"network_name"`
	// SealedPSK is base64(NaCl anonymous sealed box of the "base64:..." PSK
	// string), sealed to the target's static key. Empty for "unshare".
	SealedPSK   string `json:"sealed_psk,omitempty"`
	OverlayCIDR string `json:"overlay_cidr,omitempty"`
	// UDPListenPort etc. mirror SecondaryNetwork; zero values take defaults.
	UDPListenPort int      `json:"udp_listen_port,omitempty"`
	Cipher        string   `json:"cipher,omitempty"`
	PostQuantum   *bool    `json:"post_quantum,omitempty"`
	PQAuth        *bool    `json:"pq_auth,omitempty"`
	ExitNode      bool     `json:"exit_node,omitempty"` // target should BE an exit on that network
	StaticPeers   []string `json:"static_peers,omitempty"`
	Rendezvous    []string `json:"rendezvous_servers,omitempty"`
	Trackers      []string `json:"trackers,omitempty"`
	Seq           int64    `json:"seq"`
	Ts            int64    `json:"ts"`
	Sig           string   `json:"sig"`
}

// canonicalNetShare defines the exact signed bytes. The variable-length parts
// (peers/rendezvous/sealed PSK) are bound via a SHA-256 digest of their JSON,
// so signer and verifier only need to agree on this one function.
func canonicalNetShare(r SignedNetShare) string {
	aux, _ := json.Marshal(struct {
		SealedPSK   string   `json:"sealed_psk"`
		Cipher      string   `json:"cipher"`
		PostQuantum *bool    `json:"post_quantum"`
		PQAuth      *bool    `json:"pq_auth"`
		StaticPeers []string `json:"static_peers"`
		Rendezvous  []string `json:"rendezvous_servers"`
		Trackers    []string `json:"trackers"`
	}{r.SealedPSK, r.Cipher, r.PostQuantum, r.PQAuth, r.StaticPeers, r.Rendezvous, r.Trackers})
	digest := sha256.Sum256(aux)
	return fmt.Sprintf("OVLYNETSHARE1|%s|%s|%s|%s|%d|%t|%s|%d|%d",
		r.Action, r.PubKey, r.NetworkName, r.OverlayCIDR, r.UDPListenPort,
		r.ExitNode, hex.EncodeToString(digest[:]), r.Seq, r.Ts)
}

func verifyNetShare(r SignedNetShare) bool {
	if !adminKeySet() {
		return false
	}
	if r.Action != "share" && r.Action != "unshare" {
		return false
	}
	if raw, err := base64.StdEncoding.DecodeString(r.PubKey); err != nil || len(raw) != 32 {
		return false
	}
	if r.NetworkName == "" {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(r.Sig)
	if err != nil {
		return false
	}
	return adminVerify([]byte(canonicalNetShare(r)), sig)
}

// sealPSKTo seals a PSK string to a peer's X25519 static key.
//
// Construction (stdlib-only so the admin/desktop panels can mirror it without
// new dependencies): generate an ephemeral X25519 keypair; shared =
// X25519(ephPriv, targetPub); key = SHA-256("APGO-NETSHARE-SEAL-1|" || shared
// || ephPub || targetPub); blob = ephPub(32) || nonce(12) || AES-256-GCM(key,
// nonce, psk). Anonymous (nothing identifies the sealer) and non-malleable
// (GCM), with the key bound to both public keys.
func sealPSKTo(psk string, peerPub [32]byte) (string, error) {
	var ephPriv [32]byte
	if _, err := rand.Read(ephPriv[:]); err != nil {
		return "", err
	}
	ephPub, err := curve25519.X25519(ephPriv[:], curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	shared, err := curve25519.X25519(ephPriv[:], peerPub[:])
	if err != nil {
		return "", err
	}
	key := netShareSealKey(shared, ephPub, peerPub[:])
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	blob := append(append(append([]byte(nil), ephPub...), nonce...), gcm.Seal(nil, nonce, []byte(psk), nil)...)
	return base64.StdEncoding.EncodeToString(blob), nil
}

// openSealedPSK opens a sealed PSK with this node's static key.
func openSealedPSK(sealedB64 string) (string, bool) {
	blob, err := base64.StdEncoding.DecodeString(sealedB64)
	if err != nil || len(blob) < 32+12+16 {
		return "", false
	}
	ephPub, nonce, ct := blob[:32], blob[32:44], blob[44:]
	shared, err := curve25519.X25519(gKP.priv[:], ephPub)
	if err != nil {
		return "", false
	}
	key := netShareSealKey(shared, ephPub, gKP.pub[:])
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", false
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", false
	}
	out, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", false
	}
	return string(out), true
}

func netShareSealKey(shared, ephPub, targetPub []byte) []byte {
	h := sha256.New()
	h.Write([]byte("APGO-NETSHARE-SEAL-1|"))
	h.Write(shared)
	h.Write(ephPub)
	h.Write(targetPub)
	return h.Sum(nil)
}

// --- persistent store ------------------------------------------------------

type netShareStore struct {
	mu   sync.Mutex
	recs map[string]SignedNetShare // key: PubKey|NetworkName, latest Seq wins
	path string
}

var netShares = &netShareStore{recs: map[string]SignedNetShare{}}

func netShareKey(r SignedNetShare) string { return r.PubKey + "|" + r.NetworkName }

func netSharesFilePath() string {
	if p := os.Getenv("NETSHARES_FILE"); p != "" {
		return p
	}
	return "/state/netshares.json"
}

func (s *netShareStore) load() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.path = netSharesFilePath()
	data, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var recs []SignedNetShare
	if json.Unmarshal(data, &recs) != nil {
		return
	}
	n := 0
	for _, r := range recs {
		if verifyNetShare(r) { // re-verify: the file is only a cache
			s.recs[netShareKey(r)] = r
			n++
		}
	}
	if n > 0 {
		log.Printf("[netshare] loaded %d record(s) from %s", n, s.path)
	}
}

func (s *netShareStore) persistLocked() {
	if s.path == "" {
		s.path = netSharesFilePath()
	}
	var recs []SignedNetShare
	for _, r := range s.recs {
		recs = append(recs, r)
	}
	if data, err := json.Marshal(recs); err == nil {
		_ = os.WriteFile(s.path, data, 0o600)
	}
}

// apply stores a VERIFIED record (seq-deduped). Returns true if it superseded
// the stored state (i.e. is new information worth acting on / re-flooding).
func (s *netShareStore) apply(r SignedNetShare) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := netShareKey(r)
	if old, ok := s.recs[k]; ok && old.Seq >= r.Seq {
		return false
	}
	s.recs[k] = r
	s.persistLocked()
	return true
}

func (s *netShareStore) list() []SignedNetShare {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]SignedNetShare, 0, len(s.recs))
	for _, r := range s.recs {
		out = append(out, r)
	}
	return out
}

// --- gossip ----------------------------------------------------------------

func buildNetShareFrame(r SignedNetShare) []byte {
	b, err := json.Marshal(r)
	if err != nil {
		return nil
	}
	out := append([]byte(nil), ctlMagic...)
	out = append(out, 'S')
	return append(out, b...)
}

// handleNetShareGossip verifies + stores a gossiped record and applies it if
// it targets this node. Children ignore share records entirely — the MAIN
// instance owns device membership.
func handleNetShareGossip(payload []byte) {
	if isNetChild() {
		return
	}
	var r SignedNetShare
	if json.Unmarshal(payload, &r) != nil {
		return
	}
	if !verifyNetShare(r) {
		return
	}
	if !netShares.apply(r) {
		return
	}
	applyNetShareSelf(r)
}

// applyNetShareSelf acts on a stored record that targets THIS node.
func applyNetShareSelf(r SignedNetShare) {
	if r.PubKey != selfPubB64() {
		return
	}
	switch r.Action {
	case "share":
		psk, ok := openSealedPSK(r.SealedPSK)
		if !ok {
			log.Printf("[netshare] share for %q targets us but the sealed PSK will not open — ignoring", r.NetworkName)
			return
		}
		n := SecondaryNetwork{
			NetworkName:       r.NetworkName,
			PSK:               psk,
			OverlayCIDR:       r.OverlayCIDR,
			UDPListenPort:     r.UDPListenPort,
			Cipher:            r.Cipher,
			PostQuantum:       r.PostQuantum,
			PQAuth:            r.PQAuth,
			ExitNode:          r.ExitNode,
			StaticPeers:       r.StaticPeers,
			RendezvousServers: r.Rendezvous,
			Trackers:          r.Trackers,
			Origin:            "shared",
		}
		if n.OverlayCIDR == "" {
			n.OverlayCIDR = "10.22.56.0/24"
		}
		if err := saveStoredNetwork(n); err != nil {
			log.Printf("[netshare] cannot persist shared network %q: %v", r.NetworkName, err)
			return
		}
		log.Printf("[netshare] this device was SHARED into network %q — starting it", r.NetworkName)
		reconcileNetworks()
	case "unshare":
		removeStoredNetwork(r.NetworkName)
		log.Printf("[netshare] this device was UNSHARED from network %q — stopping it", r.NetworkName)
		reconcileNetworks()
	}
}

// applyStoredNetSharesAtStartup re-applies any persisted record targeting this
// node (covers: record arrived while a previous run was already shared — the
// profile exists; or the profile dir was wiped but the record store survived).
func applyStoredNetSharesAtStartup() {
	if isNetChild() {
		return
	}
	for _, r := range netShares.list() {
		applyNetShareSelf(r)
	}
}

// gossipNetShares floods every stored record to direct peers (heavy tick).
func gossipNetShares() {
	if isNetChild() || GlobalSessions == nil || GlobalConn == nil {
		return
	}
	var frames [][]byte
	for _, r := range netShares.list() {
		if f := buildNetShareFrame(r); f != nil {
			frames = append(frames, f)
		}
	}
	if len(frames) == 0 {
		return
	}
	for _, addr := range GlobalSessions.EstablishedAddrs() {
		s := GlobalSessions.GetByAddr(addr)
		if s == nil || !s.Established() {
			continue
		}
		for _, f := range frames {
			_ = sendPacket(GlobalConn, addr, s, f)
		}
	}
}
