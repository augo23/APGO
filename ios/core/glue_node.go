package overlaymobile

import (
	"net"
	"strings"
)

// glue_node.go adapts the shared ipbinding.go / e2erelay.go code (kept
// identical to the desktop client's copies) to the mobile core.

// e2eSelfIP is this node's current overlay address.
func e2eSelfIP() string { return myOverlayIP }

// e2eDeliver hands a verified, end-to-end-decrypted packet to the OS tunnel.
func e2eDeliver(pkt []byte) {
	tunIF.Write(pkt)
}

// --- public exit client hooks (pubexit_client.go) ---------------------------
// A phone only ever USES public exits; it never serves one.

func pxSelfIP() string     { return myOverlayIP }
func pxConn() *net.UDPConn { return GlobalConn }
func pxWriteTUN(pkt []byte) {
	if tunIF != nil {
		_, _ = tunIF.Write(pkt)
	}
}

func pxPinnedPublic() bool {
	exitMu.Lock()
	defer exitMu.Unlock()
	return strings.EqualFold(strings.TrimSpace(exitPin), "public")
}

func pxInternalExitReady() bool {
	a, _ := currentExit()
	return a != nil
}

var pxOnActive = func() {}

// The DHT is optional on phones (Settings); trackers stay the main directory.
func pxDiscoverDHT() []string {
	if gDHT == nil || !gDHT.enabled.Load() {
		return nil
	}
	return gDHT.lookupPeers(pxDirectoryKey(), 0)
}

// handlePubExitPacket is the demux entry for PktPubExit datagrams: only the
// client half exists here.
func handlePubExitPacket(data []byte, raddr *net.UDPAddr) {
	c := gPxClient
	if c == nil || len(data) < 2 {
		return
	}
	switch data[1] {
	case pxData:
		if sid, ok := pxSessionID(data); ok {
			c.handleData(sid, data, raddr)
		}
	case pxHelloReply, pxDeny:
		c.handleHandshake(data, raddr)
	}
}
