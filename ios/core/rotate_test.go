package overlaymobile

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign"
	"github.com/flynn/noise"
)

func rotTestAdmin(t *testing.T) sign.PrivateKey {
	t.Helper()
	seed := make([]byte, adminSig.SeedSize())
	rand.Read(seed)
	pub, priv := adminSig.DeriveKey(seed)
	raw, _ := pub.MarshalBinary()
	oldPub, oldParsed := adminPub, adminPubParsed
	t.Cleanup(func() { adminPub, adminPubParsed = oldPub, oldParsed })
	if !setAdminPubBytes(raw) {
		t.Fatal("admin key not accepted")
	}
	return priv
}

func rotSign(sk sign.PrivateKey, node [32]byte, addr string, seq int64) []byte {
	pubB64 := base64.StdEncoding.EncodeToString(node[:])
	sig := adminSig.Sign(sk, []byte(canonicalProvision(pubB64, addr, "", seq, seq)), nil)
	b, _ := json.Marshal(SignedProvision{PubKey: pubB64, Address: addr, Seq: seq, Ts: seq, Sig: base64.StdEncoding.EncodeToString(sig)})
	return b
}

func rotSession(t *testing.T, self, peer keypair) *session {
	t.Helper()
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b)
	hi, _ := noise.NewHandshakeState(noise.Config{CipherSuite: cs, Pattern: noise.HandshakeXX, Initiator: true,
		StaticKeypair: noise.DHKey{Private: self.priv[:], Public: self.pub[:]}})
	hr, _ := noise.NewHandshakeState(noise.Config{CipherSuite: cs, Pattern: noise.HandshakeXX,
		StaticKeypair: noise.DHKey{Private: peer.priv[:], Public: peer.pub[:]}})
	m1, _, _, _ := hi.WriteMessage(nil, nil)
	hr.ReadMessage(nil, m1)
	m2, _, _, _ := hr.WriteMessage(nil, nil)
	hi.ReadMessage(nil, m2)
	_, c1, c2, _ := hi.WriteMessage(nil, nil)
	return &session{send: c1, recv: c2, established: true, peerStatic: peer.pub, lastSeen: time.Now()}
}

// A device sitting on an address the admin has just assigned to another key
// gives it up and stages a free derived address — even though its own address
// was set explicitly (not auto-derived).
func TestDeviceRotatesOffReassignedAddress(t *testing.T) {
	sk := rotTestAdmin(t)
	self, other := testKeypair(t), testKeypair(t)
	oldKP, oldIP, oldCIDR, oldNet, oldSess, oldAuto := gKP, myOverlayIP, overlayCIDR, overlayNet, GlobalSessions, addrAutoDerived
	oldProv, oldCB := provisions, onPendingAddress
	t.Cleanup(func() {
		gKP, myOverlayIP, overlayCIDR, overlayNet, GlobalSessions, addrAutoDerived = oldKP, oldIP, oldCIDR, oldNet, oldSess, oldAuto
		provisions, onPendingAddress = oldProv, oldCB
		pendingAddrMu.Lock()
		pendingAddress = ""
		pendingAddrMu.Unlock()
		ipConflictMu.Lock()
		ipConflictLast = nil
		ipConflictMu.Unlock()
	})
	gKP = self
	overlayCIDR = "10.22.22.0/24"
	_, overlayNet, _ = net.ParseCIDR(overlayCIDR)
	myOverlayIP = "10.22.22.30"
	addrAutoDerived = false // typed in by the person
	provisions = &provStore{recs: map[[32]byte]SignedProvision{}, addrSeq: map[string]int64{}}
	GlobalSessions = NewSessionTable(nil)
	peerAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5}
	sess := rotSession(t, self, other)
	sess.addr = peerAddr
	GlobalSessions.set(peerAddr, sess)
	lastCollisionCheck.Lock()
	lastCollisionCheck.at = time.Time{}
	lastCollisionCheck.Unlock()
	moved := make(chan string, 1)
	onPendingAddress = func(a string) { moved <- a }

	// This device also held an OLDER assignment of .30.
	handleProvision(rotSign(sk, self.pub, "10.22.22.30", 100))
	// The admin now assigns .30 to the iPad.
	handleProvision(rotSign(sk, other.pub, "10.22.22.30", 200))

	select {
	case a := <-moved:
		ip := stripMask(a)
		if ip == "10.22.22.30" || !ipBindings.derives(overlayCIDR, self.pub, ip) {
			t.Fatalf("moved to %s, want a free derived address", a)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("device did not move off the reassigned address")
	}
	if c := getIPConflict(); c == nil || !c.Resolved || c.OldIP != "10.22.22.30" {
		t.Fatalf("conflict record: %+v", c)
	}
	if _, ok := provisions.get(self.pub); ok {
		t.Fatal("the device's own older assignment was not retired")
	}
}
