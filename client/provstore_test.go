package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudflare/circl/sign"
)

// testAdminKey installs a fresh admin key for the test and returns its
// private half.
func testAdminKey(t *testing.T) sign.PrivateKey {
	t.Helper()
	seed := make([]byte, adminSig.SeedSize())
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	pub, priv := adminSig.DeriveKey(seed)
	raw, err := pub.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	adminPubMu.Lock()
	oldPub, oldParsed := adminPub, adminPubParsed
	adminPubMu.Unlock()
	t.Cleanup(func() {
		adminPubMu.Lock()
		adminPub, adminPubParsed = oldPub, oldParsed
		adminPubMu.Unlock()
	})
	if !setAdminPubBytes(raw) {
		t.Fatal("admin key not accepted")
	}
	return priv
}

func testSignProv(t *testing.T, sk sign.PrivateKey, node [32]byte, addr, name string, seq int64) SignedProvision {
	t.Helper()
	pubB64 := base64.StdEncoding.EncodeToString(node[:])
	msg := canonicalProvision(pubB64, addr, name, seq, seq)
	sig := adminSig.Sign(sk, []byte(msg), nil)
	return SignedProvision{PubKey: pubB64, Address: addr, Name: name, Seq: seq, Ts: seq, Sig: base64.StdEncoding.EncodeToString(sig)}
}

func freshStore() *provStore {
	return &provStore{recs: map[[32]byte]SignedProvision{}, addrSeq: map[string]int64{}}
}

func testKey(b byte) [32]byte { var k [32]byte; k[0] = b; return k }

// The field report: the Mac's current key holds 10.22.22.115 (newest), and two
// earlier installs' records for the same address keep being gossiped back.
func TestProvStoreRejectsResurrectedClaims(t *testing.T) {
	sk := testAdminKey(t)
	s := freshStore()
	mac, old1, old2 := testKey(1), testKey(2), testKey(3)
	if !s.put(mac, testSignProv(t, sk, mac, "10.22.22.115", "mac", 300)) {
		t.Fatal("current assignment refused")
	}
	for i := 0; i < 3; i++ { // regossiped again and again
		if s.put(old1, testSignProv(t, sk, old1, "10.22.22.115", "mac", 100)) ||
			s.put(old2, testSignProv(t, sk, old2, "10.22.22.115/24", "mac", 200)) {
			t.Fatal("an older assignment of the same address was stored")
		}
	}
	if n := len(s.list()); n != 1 {
		t.Fatalf("store holds %d records, want 1", n)
	}
	if !s.ownsAddress(mac, "10.22.22.115") || s.ownsAddress(old1, "10.22.22.115") {
		t.Fatal("ownership wrong")
	}

	// Arrival in the other order: the newer record retires the older one.
	s2 := freshStore()
	s2.put(old2, testSignProv(t, sk, old2, "10.22.22.115", "mac", 200))
	s2.put(mac, testSignProv(t, sk, mac, "10.22.22.115", "mac", 300))
	if _, ok := s2.get(old2); ok {
		t.Fatal("older claim not retired by the newer one")
	}

	// The winner moves on: the address stays closed to the old records...
	if !s.put(mac, testSignProv(t, sk, mac, "10.22.22.116", "mac", 400)) {
		t.Fatal("re-address refused")
	}
	if s.put(old1, testSignProv(t, sk, old1, "10.22.22.115", "mac", 100)) {
		t.Fatal("a retired claim came back after the winner moved away")
	}
	// ...but a NEW assignment of it is accepted.
	other := testKey(9)
	if !s.put(other, testSignProv(t, sk, other, "10.22.22.115", "nas", 500)) {
		t.Fatal("a newer assignment of a freed address was refused")
	}
	// Name-only records are unaffected by address rules.
	if !s.put(old1, testSignProv(t, sk, old1, "", "renamed", 150)) {
		t.Fatal("name-only record refused")
	}
}

// A store written by an older build (all three claims present) is repaired on
// load, the repair survives a restart, and records must carry a valid
// signature.
func TestProvStoreLoadRepairsAndPersists(t *testing.T) {
	sk := testAdminKey(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "provisions.json")
	mac, old1, old2 := testKey(1), testKey(2), testKey(3)
	forged := testSignProv(t, sk, testKey(4), "10.22.22.50", "x", 900)
	forged.Address = "10.22.22.51" // signature no longer matches
	list := []SignedProvision{
		testSignProv(t, sk, old1, "10.22.22.115", "mac", 100),
		testSignProv(t, sk, mac, "10.22.22.115", "mac", 300),
		testSignProv(t, sk, old2, "10.22.22.115", "mac", 200),
		forged,
	}
	data, _ := json.Marshal(list)
	os.WriteFile(path, data, 0o600)

	s := freshStore()
	s.load(path)
	if got := s.list(); len(got) != 1 || got[0].Seq != 300 {
		t.Fatalf("after load: %+v", got)
	}
	// Restart: the ledger file keeps the old claims out even if the winner is
	// gone from the store file.
	os.WriteFile(path, []byte("[]"), 0o600)
	s2 := freshStore()
	s2.load(path)
	if s2.put(old2, testSignProv(t, sk, old2, "10.22.22.115", "mac", 200)) {
		t.Fatal("retired claim accepted after restart")
	}
}

// With the store fixed, the node holding the newest assignment sees no
// competing claimants, so the DUPLICATE CLAIM warning has nothing to report.
func TestNoDuplicateClaimAfterRegossip(t *testing.T) {
	sk := testAdminKey(t)
	self := testKeypair(t)
	testNode(t, self, nil)
	oldProv := provisions
	provisions = freshStore()
	t.Cleanup(func() { provisions = oldProv })
	setMyOverlayIP("10.22.22.115")
	old1 := testKey(2)
	provisions.put(self.pub, testSignProv(t, sk, self.pub, "10.22.22.115", "mac", 300))
	handleProvision(mustJSON(t, testSignProv(t, sk, old1, "10.22.22.115", "mac", 100)))
	if c := overlayIPClaimants("10.22.22.115"); len(c) != 0 {
		t.Fatalf("stale claimants still present: %v", c)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
