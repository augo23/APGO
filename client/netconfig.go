package main

// netconfig.go implements admin-signed rotation of the network NAME and PSK.
// This is the "the network was compromised — rotate everything" lever: an admin
// (with the password) signs a new {network_name, psk, epoch}; it floods the mesh
// inside the existing encrypted tunnel; every node persists it and restarts to
// reconnect under the new identity. Combined with admission control + revocation,
// a compromised/removed device does not receive the new config and is shut out.
//
// Offline nodes miss the change and must be reconfigured (or re-scan a new QR).

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"
)

// SignedNetworkConfig is the admin-signed network identity. canonicalNetConfig
// defines the signed bytes (must match the admin signer byte-for-byte).
type SignedNetworkConfig struct {
	NetworkName string `json:"network_name"`
	PSK         string `json:"psk"` // "base64:..."
	Epoch       int64  `json:"epoch"`
	Ts          int64  `json:"ts"`
	Sig         string `json:"sig"`
}

func canonicalNetConfig(name, psk string, epoch, ts int64) string {
	return fmt.Sprintf("OVLYNETCFG1|%s|%s|%d|%d", name, psk, epoch, ts)
}

// currentNetEpoch is the epoch of the applied/persisted network config (0 = the
// original file/env config). Guards against replaying older rotations.
var currentNetEpoch int64

func netConfigFilePath() string {
	if p := os.Getenv("NETCONFIG_FILE"); p != "" {
		return p
	}
	return "/state/netconfig.json"
}

// applyNetConfigFile overrides cfg.NetworkName/PSK with a persisted, previously
// admin-signed rotation. It runs at startup (before we connect), mirroring how
// applySetupFile works. The file lives in the node's protected state dir, so it
// is trusted here the same way the base config file is.
func applyNetConfigFile(cfg *ClientConfig) {
	data, err := os.ReadFile(netConfigFilePath())
	if err != nil {
		return
	}
	var nc SignedNetworkConfig
	if json.Unmarshal(data, &nc) != nil || nc.NetworkName == "" || nc.PSK == "" {
		return
	}
	cfg.NetworkName = nc.NetworkName
	cfg.PSK = nc.PSK
	currentNetEpoch = nc.Epoch
	log.Printf("[netconfig] applied rotated network config (epoch %d)", nc.Epoch)
}

func verifyNetConfig(nc SignedNetworkConfig) bool {
	if !adminKeySet() {
		return false
	}
	if nc.NetworkName == "" || nc.PSK == "" {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(nc.Sig)
	if err != nil {
		return false
	}
	return adminVerify([]byte(canonicalNetConfig(nc.NetworkName, nc.PSK, nc.Epoch, nc.Ts)), sig)
}

func buildNetConfigFrame(nc SignedNetworkConfig) []byte {
	b, err := json.Marshal(nc)
	if err != nil {
		return nil
	}
	out := append([]byte(nil), ctlMagic...)
	out = append(out, 'G')
	return append(out, b...)
}

// persistedNetConfig returns the currently-applied signed config (for gossip), or
// false if none.
func persistedNetConfig() (SignedNetworkConfig, bool) {
	data, err := os.ReadFile(netConfigFilePath())
	if err != nil {
		return SignedNetworkConfig{}, false
	}
	var nc SignedNetworkConfig
	if json.Unmarshal(data, &nc) != nil || nc.Sig == "" {
		return SignedNetworkConfig{}, false
	}
	return nc, true
}

// adoptNetConfig verifies + persists a newer signed network config, gossips it to
// peers, then restarts this node so it reconnects under the new name/PSK.
func adoptNetConfig(nc SignedNetworkConfig) {
	if !verifyNetConfig(nc) {
		return
	}
	if nc.Epoch <= currentNetEpoch {
		return // not newer — ignore (also de-dupes gossip storms)
	}
	data, err := json.MarshalIndent(nc, "", "  ")
	if err != nil {
		return
	}
	tmp := netConfigFilePath() + ".tmp"
	if os.WriteFile(tmp, data, 0o600) != nil || os.Rename(tmp, netConfigFilePath()) != nil {
		log.Printf("[netconfig] failed to persist rotated config")
		return
	}
	currentNetEpoch = nc.Epoch
	log.Printf("[netconfig] adopted rotated network config (epoch %d) — flooding + restarting to apply", nc.Epoch)

	// Flood to every peer NOW (over the still-valid old tunnel), then restart a
	// few seconds later so the change has time to propagate before we drop.
	if f := buildNetConfigFrame(nc); f != nil && GlobalSessions != nil && GlobalConn != nil {
		for _, addr := range GlobalSessions.EstablishedAddrs() {
			if s := GlobalSessions.GetByAddr(addr); s != nil && s.Established() {
				_ = sendPacket(GlobalConn, addr, s, f)
			}
		}
	}
	time.AfterFunc(4*time.Second, func() {
		log.Printf("[netconfig] restarting now to apply epoch %d", nc.Epoch)
		os.Exit(0) // supervisor (app / k8s / compose) restarts us with the new config
	})
}

func handleNetConfigGossip(payload []byte) {
	var nc SignedNetworkConfig
	if json.Unmarshal(payload, &nc) != nil {
		return
	}
	adoptNetConfig(nc)
}

// gossipNetConfig re-floods the current signed config on the keepalive tick so
// nodes that just came online converge.
func gossipNetConfig() {
	if GlobalSessions == nil || GlobalConn == nil {
		return
	}
	nc, ok := persistedNetConfig()
	if !ok {
		return
	}
	f := buildNetConfigFrame(nc)
	if f == nil {
		return
	}
	for _, addr := range GlobalSessions.EstablishedAddrs() {
		if s := GlobalSessions.GetByAddr(addr); s != nil && s.Established() {
			_ = sendPacket(GlobalConn, addr, s, f)
		}
	}
}
