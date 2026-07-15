package overlaymobile

import (
	"errors"
	"io"
)

// overlayRun starts the APGO overlay against tun (which delivers/accepts raw IP
// packets) using cfg, and returns a stop function.
//
// This is the ONE integration point with the overlay core in client/. The core
// today runs from client/main.go and creates its own TUN per-OS. To reuse it on
// mobile — where the OS (NEPacketTunnelProvider / VpnService) owns the tunnel —
// the core needs a small refactor to expose a run function that accepts an
// injected io.ReadWriteCloser and a config, e.g. in a new package client/core:
//
//	func Run(tun io.ReadWriteCloser, cfg core.Config, stop <-chan struct{}) error
//
// Then this becomes:
//
//	func overlayRun(tun io.ReadWriteCloser, cfg Config) (func(), error) {
//	    stop := make(chan struct{})
//	    go core.Run(tun, toCore(cfg), stop)
//	    return func() { close(stop) }, nil
//	}
//
// See mobile/README.md for the exact refactor. Until it's wired, this returns an
// error so the gomobile bindings still build and the apps show a clear message.
func overlayRun(tun io.ReadWriteCloser, cfg Config) (func(), error) {
	_ = tun
	_ = cfg
	return nil, errors.New("overlay core not yet wired into the mobile bridge — see mobile/README.md")
}
