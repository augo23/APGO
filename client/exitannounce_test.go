package main

import (
	"net"
	"testing"
)

// Exit announcements were one byte long and handleControl drops anything
// shorter than two, so no node ever learned of an exit and full-VPN mode had
// no internet. New builds send a payload byte; old one-byte frames are
// accepted too.
func TestExitAnnounceReachesHandler(t *testing.T) {
	self, peer := testKeypair(t), testKeypair(t)
	testNode(t, self, nil)
	oldAm := amExit
	amExit = true
	t.Cleanup(func() {
		amExit = oldAm
		exitMu.Lock()
		delete(exitCandidates, peer.pub)
		exitMu.Unlock()
	})
	f := buildExitAnnounce()
	if len(f)-len(ctlMagic) < 2 {
		t.Fatalf("exit announce too short for handleControl: %q", f)
	}
	if w := buildExitWithdraw(); len(w)-len(ctlMagic) < 2 {
		t.Fatalf("exit withdraw too short for handleControl: %q", w)
	}

	for _, body := range [][]byte{f[len(ctlMagic):], {'E'}} {
		exitMu.Lock()
		delete(exitCandidates, peer.pub)
		exitMu.Unlock()
		addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40111}
		GlobalSessions.set(addr, testPeerSession(t, gKP, peer, addr))
		handleControl(body, addr)
		exitMu.Lock()
		_, ok := exitCandidates[peer.pub]
		exitMu.Unlock()
		if !ok {
			t.Fatalf("exit announce %q was not recorded", body)
		}
	}
}
