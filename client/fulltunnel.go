package main

// fulltunnel.go turns full-VPN mode (use_exit) on and off in a RUNNING client.
//
// Full VPN used to be read once, at startup: the desktop Settings page wrote
// use_exit / exit_peer to the config file and said "reconnect to apply", but
// the running client never looked at the file again, and Connect is a no-op
// while a client is already running. So turning Full VPN on from the Mac or
// Windows app did nothing at all — traffic kept leaving through the home
// connection — until the client happened to be restarted by hand.
//
// applyUseExit installs or removes the OS steering (the two half-default
// routes and the transport-socket pin, vpnroutes_*.go) and flips the egress
// switch, so the change takes effect within seconds.

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	fullTunnelMu     sync.Mutex
	fullTunnelActive bool // routes installed + transport pinned by us
)

// applyUseExit switches full-VPN mode. conn is the transport socket (nil =
// GlobalConn).
//
// Turning it on does NOT touch routing yet: the OS steering is installed by
// ensureFullTunnelSteering once an exit has actually been selected (the
// selection loop calls it). Installing it first made Full VPN a black hole
// whenever the chosen exit was not reachable yet — and on macOS the pinned
// transport could not reach peers at all, so the exit never became reachable.
// Once steering is in, it stays while Full VPN is on (a lost exit pauses
// internet traffic rather than silently leaking it).
func applyUseExit(on bool, conn *net.UDPConn) error {
	if conn == nil {
		conn = GlobalConn
	}
	if on {
		wasOn := useExitFlag.Swap(true)
		if !wasOn {
			if pin := currentExitPin(); pin != "" {
				log.Printf("[exit] full-VPN mode ON — routing internet traffic via pinned exit %q "+
					"(this device's own connection stays in use until that exit is reachable)", pin)
			} else {
				log.Printf("[exit] full-VPN mode ON — routing internet traffic via the fastest exit node " +
					"(this device's own connection stays in use until an exit is reachable)")
			}
		}
		if exitAvailable() {
			return ensureFullTunnelSteeringConn(conn)
		}
		nudgeExitSelection()
		return nil
	}

	fullTunnelMu.Lock()
	defer fullTunnelMu.Unlock()
	wasOn := useExitFlag.Swap(false)
	exitMu.Lock()
	selectedExit = nil
	exitMu.Unlock()
	var err error
	if fullTunnelActive {
		err = disableFullTunnelRoutes()
		if conn != nil {
			unpinTransport(conn)
		}
		fullTunnelActive = false
	}
	if wasOn {
		log.Printf("[exit] full-VPN mode OFF — internet traffic uses this device's own connection again")
	}
	return err
}

// ensureFullTunnelSteering installs the OS steering (transport pin + routes)
// once Full VPN is on and an exit is selected. Idempotent.
func ensureFullTunnelSteering() { _ = ensureFullTunnelSteeringConn(GlobalConn) }

func ensureFullTunnelSteeringConn(conn *net.UDPConn) error {
	fullTunnelMu.Lock()
	defer fullTunnelMu.Unlock()
	if !usingExit() || fullTunnelActive || !exitAvailable() {
		return nil
	}
	if !steeringFailedAt.IsZero() && time.Since(steeringFailedAt) < steeringRetryAfter {
		return nil
	}
	// Pin FIRST: the physical route is read before the /1 routes exist.
	if conn != nil {
		if err := pinTransportToPhysicalInterface(conn); err != nil {
			log.Printf("[exit] could not pin transport to the physical interface: %v — not steering "+
				"internet traffic into the tunnel (it would cut this device off from its peers)", err)
			return err
		}
	}
	if err := enableFullTunnelRoutes(); err != nil {
		log.Printf("[exit] could not install full-tunnel routes: %v", err)
		if conn != nil {
			unpinTransport(conn)
		}
		return err
	}
	// Safety net: the pinned transport must still reach every peer. If it
	// cannot, the exit becomes unreachable and the device is cut off — undo
	// the steering at once instead (and don't retry for a while).
	if bad := unreachablePeerAfterSteering(conn); bad != "" {
		_ = disableFullTunnelRoutes()
		if conn != nil {
			unpinTransport(conn)
		}
		steeringFailedAt = time.Now()
		log.Printf("[exit] Full VPN REVERTED: with internet traffic steered into the tunnel this device "+
			"could no longer reach its peers (%s). Internet traffic keeps using this device's own connection; "+
			"retrying in %v. Please report this log line.", bad, steeringRetryAfter)
		return fmt.Errorf("steering made peers unreachable: %s", bad)
	}
	fullTunnelActive = true
	if a, _ := currentExit(); a != nil {
		log.Printf("[exit] internet traffic now goes through the exit at %v", a)
	} else if pxActiveReady() {
		log.Printf("[exit] internet traffic now goes through a public exit node")
	}
	return nil
}

// exitAvailable reports whether any exit — internal or public — can carry
// internet traffic right now.
func exitAvailable() bool {
	if a, _ := currentExit(); a != nil {
		return true
	}
	return pxActiveReady()
}

var steeringFailedAt time.Time

const steeringRetryAfter = 2 * time.Minute

// unreachablePeerAfterSteering sends one keepalive to every established peer
// through the (now pinned) transport and reports the first send the OS
// refuses as unreachable.
func unreachablePeerAfterSteering(conn *net.UDPConn) string {
	if conn == nil || GlobalSessions == nil {
		return ""
	}
	ka := []byte{0x00}
	if ip := net.ParseIP(myOverlayIP()).To4(); ip != nil {
		ka = append([]byte{0x00}, ip...)
	}
	for _, addr := range GlobalSessions.EstablishedAddrs() {
		s := GlobalSessions.GetByAddr(addr)
		if s == nil || !s.Established() {
			continue
		}
		if err := sendPacket(conn, addr, s, ka); err != nil &&
			(errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH)) {
			return fmt.Sprintf("%v: %v", addr, err)
		}
	}
	return ""
}

func nudgeExitSelection() {
	select {
	case exitRepick <- struct{}{}:
	default:
	}
}

// applyUseExitRequest applies a use_exit (and optional exit pin) change from
// the control API or the main network's row in the network list.
func applyUseExitRequest(on bool, pin *string) error {
	if pin != nil {
		p := strings.TrimSpace(*pin)
		if p != currentExitPin() {
			setExitPin(p)
			_ = saveNodeExitPin(p) // persists only where NODE_SETTINGS_FILE is set
		}
	}
	if err := applyUseExit(on, nil); err != nil {
		return err
	}
	// Only one network may own the default route: keep the multi-network
	// supervisor's view of the main network in step.
	supMu.Lock()
	if supParent != nil {
		supParent.UseExit = on
		if pin != nil {
			supParent.ExitPeer = strings.TrimSpace(*pin)
		}
	}
	supMu.Unlock()
	reconcileNetworks()
	return nil
}
