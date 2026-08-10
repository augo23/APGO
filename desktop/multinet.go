package main

// multinet.go — multi-network (guest network) support for the desktop panel.
// Mirrors admin/networks.go: proxies the client's multi-network API, reaches
// each secondary network's control socket ("<socket>.<id>"), and signs
// SHARE / UNSHARE records with the PSK sealed to the target device's key.
//
// canonicalNetShare and the sealed-PSK construction MUST match
// client/netshare.go byte-for-byte.

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

// SignedNetShare mirrors the client's struct.
type SignedNetShare struct {
	Action        string   `json:"action"`
	PubKey        string   `json:"pubkey"`
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

// sealPSKToB64 — same construction as client/netshare.go sealPSKTo.
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
		return errors.New("no admin key available on this device")
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

// --- per-network socket proxy ----------------------------------------------

var netIDRe = regexp.MustCompile(`^[0-9a-f]{8}$`)

func netSocketByID(id string) (string, error) {
	if id == "" || id == "main" {
		return controlSocket(), nil
	}
	if !netIDRe.MatchString(id) {
		return "", errors.New("bad net id")
	}
	return controlSocket() + "." + id, nil
}

func ctlDoOn(socket, method, path string, body []byte) (int, []byte, error) {
	cl := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		},
	}
	var req *http.Request
	var err error
	if method == "POST" {
		req, err = http.NewRequest("POST", "http://unix"+path, strings.NewReader(string(body)))
		if req != nil {
			req.Header.Set("Content-Type", "application/json")
		}
	} else {
		req, err = http.NewRequest("GET", "http://unix"+path, nil)
	}
	if err != nil {
		return 0, nil, err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, b, nil
}

func proxyCtlOn(w http.ResponseWriter, socket, method, path string, body []byte) {
	code, resp, err := ctlDoOn(socket, method, path, body)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":"network instance not running"}`))
		return
	}
	if code == 0 {
		code = http.StatusOK
	}
	w.WriteHeader(code)
	_, _ = w.Write(resp)
}

// --- handlers ---------------------------------------------------------------

// registerMultinetPanel adds the multi-network routes to the panel mux.
func registerMultinetPanel(mux *http.ServeMux) {
	mux.HandleFunc("/api/networks", apiAuth(func(w http.ResponseWriter, r *http.Request) {
		proxyCtl(w, "GET", "/api/networks", nil)
	}))
	mux.HandleFunc("/api/netshares", apiAuth(func(w http.ResponseWriter, r *http.Request) {
		proxyCtl(w, "GET", "/api/netshares", nil)
	}))
	mux.HandleFunc("/api/network-profile", apiAuth(func(w http.ResponseWriter, r *http.Request) {
		name := strings.ReplaceAll(r.URL.Query().Get("name"), "&", "")
		proxyCtl(w, "GET", "/api/network-profile?name="+name, nil)
	}))
	for _, ep := range []string{"/api/network-add", "/api/network-remove", "/api/network-set"} {
		ep := ep
		mux.HandleFunc(ep, apiAuth(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "POST only", http.StatusMethodNotAllowed)
				return
			}
			body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
			proxyCtl(w, "POST", ep, body)
		}))
	}
	mux.HandleFunc("/api/net-sessions", apiAuth(func(w http.ResponseWriter, r *http.Request) {
		sock, err := netSocketByID(r.URL.Query().Get("net"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		proxyCtlOn(w, sock, "GET", "/api/sessions", nil)
	}))
	mux.HandleFunc("/api/share", apiAuth(handlePanelShare))
}

// handlePanelShare signs and submits a share/unshare of a device into a
// secondary network (see admin/networks.go handleAPIShare).
func handlePanelShare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		PubKey      string `json:"pubkey"`
		NetworkName string `json:"network_name"`
		Action      string `json:"action"`
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
		code, prof, err := ctlDo("GET", "/api/network-profile?name="+strings.ReplaceAll(req.NetworkName, "&", ""), nil)
		if err != nil || code != http.StatusOK {
			http.Error(w, "cannot load network profile (is the network configured on this device?)", http.StatusBadGateway)
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
	if pub := adminPublicKeyB64(); pub != "" {
		pushAdminPubKey(pub)
	}
	recBytes, _ := json.Marshal(rec)
	proxyCtl(w, "POST", "/api/netshare-signed", recBytes)
}
