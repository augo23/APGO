package main

// networks.go — multi-network (guest network) support for the admin dashboard.
//
//   - proxies the client's multi-network management API (/api/networks,
//     network-add / network-remove / network-set / network-profile),
//   - reaches each secondary network's OWN control socket ("<socket>.<id>")
//     so sessions/approvals/revocations of a guest network are visible and
//     actionable from the same dashboard (?net=<id> on the proxied APIs),
//   - signs SHARE / UNSHARE records: "share device X into network Y". The
//     record is ML-DSA-signed like a revocation and the network PSK is sealed
//     to the target device's X25519 static key, so only the target can read
//     it. The client floods it across the mesh (see client/netshare.go).
//
// canonicalNetShare and the sealed-PSK construction MUST match the client
// byte-for-byte.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// SignedNetShare mirrors the client's struct; canonicalNetShare defines the
// signed bytes and must match the client character-for-character.
type SignedNetShare struct {
	Action        string   `json:"action"` // "share" | "unshare"
	PubKey        string   `json:"pubkey"` // base64 target 32-byte X25519 static key
	NetworkName   string   `json:"network_name"`
	SealedPSK     string   `json:"sealed_psk,omitempty"`
	OverlayCIDR   string   `json:"overlay_cidr,omitempty"`
	UDPListenPort int      `json:"udp_listen_port,omitempty"`
	Cipher        string   `json:"cipher,omitempty"`
	PostQuantum   *bool    `json:"post_quantum,omitempty"`
	PQAuth        *bool    `json:"pq_auth,omitempty"`
	ExitNode      bool     `json:"exit_node,omitempty"`
	StaticPeers   []string `json:"static_peers,omitempty"`
	Rendezvous    []string `json:"rendezvous_servers,omitempty"`
	Trackers      []string `json:"trackers,omitempty"`
	Seq           int64    `json:"seq"`
	Ts            int64    `json:"ts"`
	Sig           string   `json:"sig"`
}

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

// sealPSKToB64 seals a PSK to the target's X25519 static key. Construction
// (mirrors client/netshare.go): ephemeral X25519; key = SHA-256(
// "APGO-NETSHARE-SEAL-1|" || shared || ephPub || targetPub); blob =
// ephPub(32) || nonce(12) || AES-256-GCM ciphertext.
func sealPSKToB64(psk, targetPubB64 string) (string, error) {
	targetRaw, err := base64.StdEncoding.DecodeString(targetPubB64)
	if err != nil || len(targetRaw) != 32 {
		return "", errors.New("bad target public key")
	}
	x := ecdh.X25519()
	eph, err := x.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	targetKey, err := x.NewPublicKey(targetRaw)
	if err != nil {
		return "", err
	}
	shared, err := eph.ECDH(targetKey)
	if err != nil {
		return "", err
	}
	ephPub := eph.PublicKey().Bytes()
	h := sha256.New()
	h.Write([]byte("APGO-NETSHARE-SEAL-1|"))
	h.Write(shared)
	h.Write(ephPub)
	h.Write(targetRaw)
	key := h.Sum(nil)
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

// signNetShare decrypts the admin key with password and signs the record.
func signNetShare(password string, rec *SignedNetShare) error {
	adminKeyMu.Lock()
	defer adminKeyMu.Unlock()
	akf, ok := currentAdminKeyFile()
	if !ok {
		return errors.New("no admin key available on this node")
	}
	seed, err := decryptSeed(akf, password)
	if err != nil {
		return errWrongPassword
	}
	rec.Seq = time.Now().UnixNano()
	rec.Ts = time.Now().Unix()
	sig := adminSignWithSeed(seed, []byte(canonicalNetShare(*rec)))
	zero(seed)
	rec.Sig = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// --- per-network control-socket proxy --------------------------------------

var netIDRe = regexp.MustCompile(`^[0-9a-f]{8}$`)

// netSocketByID maps a network id ("", "main", or 8-hex id) to the matching
// control socket.
func netSocketByID(id string) (string, error) {
	if id == "" || id == "main" {
		return controlSocket, nil
	}
	if !netIDRe.MatchString(id) {
		return "", errors.New("bad net id")
	}
	return controlSocket + "." + id, nil
}

// netSocket returns the control socket for the request's ?net=<id> (or the
// main socket when absent/"main").
func netSocket(r *http.Request) (string, error) {
	return netSocketByID(r.URL.Query().Get("net"))
}

func ctlClientOn(socket string) *http.Client {
	return &http.Client{
		Timeout: 6 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		},
	}
}

func ctlGetOn(socket, path string) (int, []byte, error) {
	resp, err := ctlClientOn(socket).Get("http://unix" + path)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, b, nil
}

func ctlPostOn(socket, path string, body []byte) (int, []byte, error) {
	resp, err := ctlClientOn(socket).Post("http://unix"+path, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, b, nil
}

// --- handlers ---------------------------------------------------------------

func handleAPINetworks(w http.ResponseWriter, r *http.Request) {
	code, body, err := ctlGet("/api/networks")
	proxyJSON(w, code, body, err)
}

func handleAPINetworkAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	code, resp, err := ctlPost("/api/network-add", body)
	proxyJSON(w, code, resp, err)
}

func handleAPINetworkRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<10))
	code, resp, err := ctlPost("/api/network-remove", body)
	proxyJSON(w, code, resp, err)
}

func handleAPINetworkSet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 16<<10))
	code, resp, err := ctlPost("/api/network-set", body)
	proxyJSON(w, code, resp, err)
}

func handleAPINetworkProfile(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	code, body, err := ctlGet("/api/network-profile?name=" + strings.ReplaceAll(name, "&", ""))
	proxyJSON(w, code, body, err)
}

func handleAPINetShares(w http.ResponseWriter, r *http.Request) {
	code, body, err := ctlGet("/api/netshares")
	proxyJSON(w, code, body, err)
}

// handleAPINetSessions serves the session list of ANY network:
// /api/net-sessions?net=<id> (or net=main).
func handleAPINetSessions(w http.ResponseWriter, r *http.Request) {
	sock, err := netSocket(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	code, body, cerr := ctlGetOn(sock, "/api/sessions")
	proxyJSON(w, code, body, cerr)
}

// handleAPIShare signs and submits a share/unshare of a device into a
// secondary network. Request: {pubkey, network_name, action, exit_node,
// password}.
func handleAPIShare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("X-Requested-With") != "overlay-admin" {
		http.Error(w, "missing X-Requested-With header", http.StatusBadRequest)
		return
	}
	var req struct {
		PubKey      string `json:"pubkey"`
		NetworkName string `json:"network_name"`
		Action      string `json:"action"` // "share" | "unshare"
		ExitNode    bool   `json:"exit_node"`
		Password    string `json:"password"`
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 16<<10))
	if json.Unmarshal(body, &req) != nil || req.PubKey == "" || req.NetworkName == "" {
		http.Error(w, "bad request (pubkey and network_name required)", http.StatusBadRequest)
		return
	}
	if req.Action != "share" && req.Action != "unshare" {
		http.Error(w, `action must be "share" or "unshare"`, http.StatusBadRequest)
		return
	}

	rec := SignedNetShare{
		Action:      req.Action,
		PubKey:      req.PubKey,
		NetworkName: req.NetworkName,
		ExitNode:    req.ExitNode,
	}
	if req.Action == "share" {
		// Pull the network's full profile (incl. PSK) from the local client and
		// seal the PSK to the target device.
		code, prof, err := ctlGet("/api/network-profile?name=" + strings.ReplaceAll(req.NetworkName, "&", ""))
		if err != nil || code != http.StatusOK {
			http.Error(w, "cannot load network profile (is the network configured on this node?)", http.StatusBadGateway)
			return
		}
		var p struct {
			PSK           string   `json:"psk"`
			OverlayCIDR   string   `json:"overlay_cidr"`
			UDPListenPort int      `json:"udp_listen_port"`
			Cipher        string   `json:"cipher"`
			PostQuantum   *bool    `json:"post_quantum"`
			PQAuth        *bool    `json:"pq_auth"`
			StaticPeers   []string `json:"static_peers"`
			Rendezvous    []string `json:"rendezvous_servers"`
			Trackers      []string `json:"trackers"`
		}
		if json.Unmarshal(prof, &p) != nil || p.PSK == "" {
			http.Error(w, "network profile is incomplete", http.StatusBadGateway)
			return
		}
		sealed, err := sealPSKToB64(p.PSK, req.PubKey)
		if err != nil {
			http.Error(w, "seal: "+err.Error(), http.StatusBadRequest)
			return
		}
		rec.SealedPSK = sealed
		rec.OverlayCIDR = p.OverlayCIDR
		rec.UDPListenPort = p.UDPListenPort
		rec.Cipher = p.Cipher
		rec.PostQuantum = p.PostQuantum
		rec.PQAuth = p.PQAuth
		rec.StaticPeers = p.StaticPeers
		rec.Rendezvous = p.Rendezvous
		rec.Trackers = p.Trackers
	}

	if err := signNetShare(req.Password, &rec); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errWrongPassword) {
			status = http.StatusUnauthorized
		}
		http.Error(w, err.Error(), status)
		return
	}
	recBytes, _ := json.Marshal(rec)
	code, resp, err := ctlPost("/api/netshare-signed", recBytes)
	proxyJSON(w, code, resp, err)
}
