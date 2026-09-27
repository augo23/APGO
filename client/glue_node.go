package main

import (
	"net"
	"strings"
)

// glue_node.go adapts the shared ipbinding.go / e2erelay.go code (kept
// identical between the desktop client and the mobile core) to this build.

// e2eSelfIP is this node's current overlay address.
func e2eSelfIP() string { return myOverlayIP() }

// e2eDeliver hands a verified, end-to-end-decrypted packet to the OS tunnel.
func e2eDeliver(pkt []byte) {
	statRxRelayed.Add(1)
	statRxDelivered.Add(1)
	tunIF.Write(pkt)
}

// --- public exit client hooks (pubexit_client.go) ---------------------------

func pxSelfIP() string      { return myOverlayIP() }
func pxConn() *net.UDPConn  { return GlobalConn }
func pxWriteTUN(pkt []byte) { statRxDelivered.Add(1); _, _ = tunIF.Write(pkt) }
func pxPinnedPublic() bool  { return strings.EqualFold(strings.TrimSpace(currentExitPin()), "public") }
func pxInternalExitReady() bool {
	a, _ := currentExit()
	return a != nil
}

// pxOnActive: a public exit just started carrying traffic — steer internet
// traffic into the tunnel now (fulltunnel.go waits for a usable exit).
var pxOnActive = func() { go ensureFullTunnelSteering() }

// pxDiscoverDHT looks the public-exit directory up in the DHT (desktop only).
func pxDiscoverDHT() []string {
	if gDHT == nil || !gDHT.enabled.Load() {
		return nil
	}
	return gDHT.lookupPeers(pxDirectoryKey(), 0)
}
