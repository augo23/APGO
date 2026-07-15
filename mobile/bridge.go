// Package overlaymobile is the gomobile-bindable bridge shared by the iOS and
// Android apps. The platform VPN layer (NEPacketTunnelProvider on iOS,
// VpnService on Android) creates the tunnel and owns its file descriptor; it
// passes that fd (and the JSON config) here, and this package runs the APGO
// overlay over it.
//
// Build the bindings from this directory:
//
//	gomobile bind -target=ios     -o ../ios/OverlayMobile.xcframework  ./
//	gomobile bind -target=android -o ../android/app/libs/overlaymobile.aar -javapkg=org.apgo ./
//
// The overlay core (Noise handshake, sessions, tracker/STUN discovery, roaming)
// is the same code as client/. Because iOS/Android hand us a ready tun fd
// (instead of the client creating its own utun/Wintun/TUN), the core needs a
// small entry point that runs against an injected io.ReadWriteCloser. That
// function is overlayRun below — see mobile/README.md for wiring it to client/.
package overlaymobile

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
)

// Config is the platform-supplied network configuration (JSON from the app).
type Config struct {
	NetworkName   string   `json:"network_name"`
	PSK           string   `json:"psk"`
	OverlayCIDR   string   `json:"overlay_cidr"`
	OverlayIP     string   `json:"overlay_ip"`   // this device's overlay address (e.g. 10.28.55.30)
	UDPListenPort int      `json:"udp_listen_port"`
	Cipher        string   `json:"cipher"`
	STUNServers   []string `json:"stun_servers"`
	AdminPubKey   string   `json:"admin_public_key"`
}

var (
	mu      sync.Mutex
	running bool
	stopFn  func()
)

// Start runs the overlay over the tunnel file descriptor the platform provides.
// It returns immediately; the overlay runs on its own goroutines. configJSON is
// a Config marshalled to JSON. Safe to call once; call Stop before starting
// again. gomobile exposes this to Swift/Kotlin.
func Start(tunFD int, configJSON string) error {
	mu.Lock()
	defer mu.Unlock()
	if running {
		return errors.New("overlay already running")
	}
	var cfg Config
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return err
	}
	if cfg.NetworkName == "" || cfg.PSK == "" {
		return errors.New("network_name and psk are required")
	}
	// The platform passes a dup'd fd we own; wrap it as an io.ReadWriteCloser of
	// raw IP packets (both NEPacketTunnelFlow-backed fds and Android VpnService
	// fds deliver raw L3 packets, so no header handling is needed).
	tun := os.NewFile(uintptr(tunFD), "tun")
	if tun == nil {
		return errors.New("invalid tun fd")
	}
	stop, err := overlayRun(tun, cfg)
	if err != nil {
		_ = tun.Close()
		return err
	}
	stopFn = stop
	running = true
	return nil
}

// Stop tears the overlay down and closes the tunnel.
func Stop() {
	mu.Lock()
	defer mu.Unlock()
	if !running {
		return
	}
	if stopFn != nil {
		stopFn()
	}
	stopFn = nil
	running = false
}

// Running reports whether the overlay is active (for the app's status UI).
func Running() bool {
	mu.Lock()
	defer mu.Unlock()
	return running
}
