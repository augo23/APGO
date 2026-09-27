package overlaymobile

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign"
)

// newTestAdminKey returns a fresh ML-DSA admin keypair and its marshaled public key.
func newTestAdminKey(t *testing.T) (sign.PrivateKey, []byte) {
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
	return priv, raw
}

// resetAdminState clears every piece of admin-trust state these tests touch.
func resetAdminState(t *testing.T) {
	t.Helper()
	clear := func() {
		adminPub, adminPubParsed = nil, nil
		adminPinMu.Lock()
		adminPin = ""
		adminPinMu.Unlock()
		sealedMu.Lock()
		sealedBlob, sealedEpoch, sealedSigned, sealedKeyFile = nil, 0, false, ""
		sealedMu.Unlock()
		adminPubFile = ""
	}
	clear()
	t.Setenv("ADMIN_TOFU", "")
	t.Setenv("REVOCATIONS_FILE", "")
	t.Cleanup(clear)
}

func makeBlob(t *testing.T, priv sign.PrivateKey, raw []byte, epoch int64, signIt bool, sealed string) []byte {
	t.Helper()
	f := sealedBlobFields{
		Version: 1, PublicKey: base64.StdEncoding.EncodeToString(raw),
		Salt: "c2FsdA==", Iter: 600000, Nonce: "bm9uY2U=", Sealed: sealed, Epoch: epoch,
	}
	if signIt {
		f.Sig = base64.StdEncoding.EncodeToString(adminSig.Sign(priv, []byte(canonicalSealedBlob(f)), nil))
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func heldSealed() (string, bool) {
	sealedMu.Lock()
	defer sealedMu.Unlock()
	var f sealedBlobFields
	_ = json.Unmarshal(sealedBlob, &f)
	return f.Sealed, sealedSigned
}

func TestNormalizeAdminKeyFP(t *testing.T) {
	_, raw := newTestAdminKey(t)
	fp := adminKeyFingerprint(raw)
	bare := fp[len(adminKeyFPPrefix):]
	digest, _ := base64.RawURLEncoding.DecodeString(bare)
	for _, in := range []string{fp, bare, " " + fp + "\n", base64.StdEncoding.EncodeToString(digest), fmt.Sprintf("%x", digest)} {
		if got := normalizeAdminKeyFP(in); got != fp {
			t.Errorf("normalize(%q) = %q, want %q", in, got, fp)
		}
	}
	for _, bad := range []string{"", "sha256:", "nonsense", "sha256:AAAA"} {
		if got := normalizeAdminKeyFP(bad); got != "" {
			t.Errorf("normalize(%q) = %q, want empty", bad, got)
		}
	}
}

// The core fix: a pinned node refuses a seeded admin key that doesn't match.
func TestSeededAdminKeyRespectsPin(t *testing.T) {
	resetAdminState(t)
	_, real := newTestAdminKey(t)
	_, rogue := newTestAdminKey(t)
	t.Setenv("ADMIN_KEY_FP", adminKeyFingerprint(real))
	applyAdminKeyPin("")

	adoptSeededAdminPub(base64.StdEncoding.EncodeToString(rogue), "test-rogue")
	if adminKeySet() {
		t.Fatal("pinned node adopted a rogue admin key")
	}
	adoptSeededAdminPub(base64.StdEncoding.EncodeToString(real), "test-real")
	if !adminSameKey(real) {
		t.Fatal("pinned node refused the matching admin key")
	}
}

func TestSeededAdminKeyTOFUDisabled(t *testing.T) {
	resetAdminState(t)
	t.Setenv("ADMIN_TOFU", "0")
	_, k := newTestAdminKey(t)
	adoptSeededAdminPub(base64.StdEncoding.EncodeToString(k), "test")
	if adminKeySet() {
		t.Fatal("ADMIN_TOFU=0 node adopted an unpinned seeded key")
	}
}

func TestSeededAdminKeyTOFUCompat(t *testing.T) {
	resetAdminState(t)
	_, k := newTestAdminKey(t)
	adoptSeededAdminPub(base64.StdEncoding.EncodeToString(k), "test")
	if !adminSameKey(k) {
		t.Fatal("unpinned node should keep legacy trust-on-first-use")
	}
}

// A sealed blob is also a way to seed the admin key; the pin must hold there too.
func TestSealedBlobRespectsPin(t *testing.T) {
	resetAdminState(t)
	realPriv, real := newTestAdminKey(t)
	roguePriv, rogue := newTestAdminKey(t)
	applyAdminKeyPin(adminKeyFingerprint(real))
	now := time.Now().UnixNano()
	if storeSealedAdminKey(makeBlob(t, roguePriv, rogue, now, true, "rogue"), false) || adminKeySet() {
		t.Fatal("pinned node adopted a rogue key from a sealed blob")
	}
	if !storeSealedAdminKey(makeBlob(t, realPriv, real, now, true, "real"), false) || !adminSameKey(real) {
		t.Fatal("pinned node refused the matching sealed blob")
	}
}

// The lockout attack: an unsigned max-epoch garbage blob must not replace a
// real one, and a signed blob must replace an unsigned legacy one.
func TestSealedBlobSupersession(t *testing.T) {
	resetAdminState(t)
	priv, raw := newTestAdminKey(t)
	now := time.Now().UnixNano()

	// Legacy network: an unsigned blob is accepted when nothing is held.
	if !storeSealedAdminKey(makeBlob(t, nil, raw, now-10, false, "legacy"), false) {
		t.Fatal("first unsigned blob refused")
	}
	// A garbage unsigned blob with a newer epoch must NOT replace it.
	if storeSealedAdminKey(makeBlob(t, nil, raw, now, false, "garbage"), false) {
		t.Fatal("unsigned blob replaced the held blob via gossip")
	}
	// A signed blob replaces the unsigned one even at an older epoch.
	if !storeSealedAdminKey(makeBlob(t, priv, raw, now-20, true, "signed-1"), false) {
		t.Fatal("signed blob did not supersede the unsigned legacy blob")
	}
	if s, signed := heldSealed(); s != "signed-1" || !signed {
		t.Fatalf("held = %q signed=%v", s, signed)
	}
	// Unsigned never replaces signed — not even from the local socket.
	if storeSealedAdminKey(makeBlob(t, nil, raw, now, false, "garbage"), false) ||
		storeSealedAdminKeyForce(makeBlob(t, nil, raw, now, false, "garbage"), false, true) {
		t.Fatal("unsigned blob replaced a signed one")
	}
	// Older signed replays are refused; newer signed blobs (password change) win.
	if storeSealedAdminKey(makeBlob(t, priv, raw, now-30, true, "old"), false) {
		t.Fatal("older signed blob accepted")
	}
	if !storeSealedAdminKey(makeBlob(t, priv, raw, now, true, "signed-2"), false) {
		t.Fatal("newer signed blob refused")
	}
	// A far-future epoch (which could never be superseded) is refused.
	if storeSealedAdminKey(makeBlob(t, priv, raw, math.MaxInt64, true, "wedge"), false) {
		t.Fatal("far-future epoch accepted")
	}
	// A tampered signed blob is refused.
	var f sealedBlobFields
	_ = json.Unmarshal(makeBlob(t, priv, raw, now+1, true, "orig"), &f)
	f.Sealed = "tampered"
	tb, _ := json.Marshal(f)
	if storeSealedAdminKey(tb, false) {
		t.Fatal("tampered blob accepted")
	}
	if s, _ := heldSealed(); s != "signed-2" {
		t.Fatalf("held blob changed to %q", s)
	}
}

// A different admin key never arrives by gossip, and the local socket may only
// replace a STALE bare key — not one backed by a live sealed blob.
func TestSealedBlobKeySwitch(t *testing.T) {
	resetAdminState(t)
	aPriv, a := newTestAdminKey(t)
	bPriv, b := newTestAdminKey(t)
	now := time.Now().UnixNano()

	// Stale bare key (no blob): a local force may replace it.
	setAdminPubBytes(a)
	if !storeSealedAdminKeyForce(makeBlob(t, bPriv, b, now, true, "b"), false, true) || !adminSameKey(b) {
		t.Fatal("local operator could not replace a stale bare admin key")
	}
	// Now a live blob for b is held: neither gossip nor the socket may switch.
	if storeSealedAdminKey(makeBlob(t, aPriv, a, now+1, true, "a"), false) {
		t.Fatal("gossip switched the admin key")
	}
	if storeSealedAdminKeyForce(makeBlob(t, aPriv, a, now+1, true, "a"), false, true) {
		t.Fatal("control socket switched a live admin key")
	}
	if !adminSameKey(b) {
		t.Fatal("trusted key changed")
	}
}

func TestExitForwardAllowed(t *testing.T) {
	oldNet := overlayNet
	t.Cleanup(func() { overlayNet = oldNet })
	_, overlayNet, _ = net.ParseCIDR("10.44.0.0/16")
	t.Setenv("EXIT_ALLOW_LAN", "")
	for dst, want := range map[string]bool{
		"1.1.1.1": true, "10.44.0.9": false, "192.168.1.1": false,
		"169.254.169.254": false, "127.0.0.1": false, "": false,
	} {
		if got := exitForwardAllowed(dst); got != want {
			t.Errorf("exitForwardAllowed(%q) = %v, want %v", dst, got, want)
		}
	}
	t.Setenv("EXIT_ALLOW_LAN", "1")
	if !exitForwardAllowed("192.168.1.1") || exitForwardAllowed("10.44.0.9") {
		t.Error("EXIT_ALLOW_LAN should open private ranges but never the overlay")
	}
}

// The admin and desktop signers produce this exact string (admin/sealsig.go).
func TestCanonicalSealedBlobVector(t *testing.T) {
	f := sealedBlobFields{Version: 1, PublicKey: "PK", Salt: "S", Iter: 600000, Nonce: "N", Sealed: "C", Epoch: 42, Sig: "ignored"}
	if got, want := canonicalSealedBlob(f), "OVLYSEALED1|1|PK|S|600000|N|C|42"; got != want {
		t.Fatalf("canonicalSealedBlob = %q, want %q", got, want)
	}
}
