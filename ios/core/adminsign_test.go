package overlaymobile

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// sealTestKey builds a sealed admin-key blob the same way the admin module
// does, so these tests exercise the real unseal path rather than a shortcut.
func sealTestKey(t *testing.T, password string) (blob []byte, pubB64 string) {
	t.Helper()
	seed := make([]byte, adminSig.SeedSize())
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	pub, _ := adminSig.DeriveKey(seed)
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	// A low iteration count keeps the test fast; the production value (600k)
	// is carried in the blob's own Iter field, which is exactly why it is
	// stored per-blob rather than assumed.
	const testIter = 1000
	dk := pbkdf2SHA256([]byte(password), salt, testIter, 32)
	block, _ := aes.NewCipher(dk)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	sealed := gcm.Seal(nil, nonce, seed, nil)
	akf := adminKeyFile{
		Version:   1,
		PublicKey: base64.StdEncoding.EncodeToString(pubBytes),
		Salt:      base64.StdEncoding.EncodeToString(salt),
		Iter:      testIter,
		Nonce:     base64.StdEncoding.EncodeToString(nonce),
		Sealed:    base64.StdEncoding.EncodeToString(sealed),
		Epoch:     1,
	}
	b, err := json.Marshal(akf)
	if err != nil {
		t.Fatal(err)
	}
	return b, akf.PublicKey
}

func installTestAdminKey(t *testing.T, password string) {
	t.Helper()
	blob, pubB64 := sealTestKey(t, password)
	raw, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		t.Fatal(err)
	}
	if !setAdminPubBytes(raw) {
		t.Fatal("could not install the test admin public key")
	}
	sealedMu.Lock()
	sealedBlob = blob
	sealedMu.Unlock()
	t.Cleanup(func() {
		sealedMu.Lock()
		sealedBlob = nil
		sealedMu.Unlock()
	})
}

// The whole point of adminsign.go: a signature produced on a phone must verify
// under the same admin key everywhere else. If the canonical string, the seed
// derivation or the signature scheme drifts from the desktop signer, approvals
// from mobile are silently IGNORED by every peer rather than rejected loudly.
func TestMobileSignedApprovalVerifies(t *testing.T) {
	const pw = "correct horse battery staple"
	installTestAdminKey(t, pw)

	target := base64.StdEncoding.EncodeToString(make([]byte, 32))
	rec, err := signApproval(pw, target, "approve")
	if err != nil {
		t.Fatalf("signApproval: %v", err)
	}
	if rec.Action != "approve" || rec.PubKey != target {
		t.Errorf("record fields wrong: %+v", rec)
	}
	if rec.Seq == 0 || rec.Ts == 0 {
		t.Error("seq/ts must be set — peers dedupe on seq")
	}
	pub, ok := verifyApproval(rec)
	if !ok {
		t.Fatal("a freshly signed approval did not verify — the mobile signer has drifted from the verifier")
	}
	if base64.StdEncoding.EncodeToString(pub[:]) != target {
		t.Error("verified key does not match the target")
	}
}

func TestMobileSignRejectsWrongPassword(t *testing.T) {
	const pw = "correct horse battery staple"
	installTestAdminKey(t, pw)
	target := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if _, err := signApproval("wrong password", target, "approve"); err != errWrongPassword {
		t.Fatalf("expected errWrongPassword, got %v", err)
	}
}

func TestMobileSignRequiresSealedKey(t *testing.T) {
	// No sealed blob: the phone has not been told the admin key yet. This must
	// be a clear error, not a panic and not a silently unsigned record.
	sealedMu.Lock()
	sealedBlob = nil
	sealedMu.Unlock()
	if adminKeyAvailable() {
		t.Fatal("adminKeyAvailable must be false with no sealed blob")
	}
	if _, err := signApproval("anything", "x", "approve"); err == nil {
		t.Fatal("signing must fail without the sealed admin key")
	}
}

// A tampered record must not verify. Cheap to test and the property everything
// else rests on.
func TestTamperedApprovalRejected(t *testing.T) {
	const pw = "hunter2hunter2"
	installTestAdminKey(t, pw)
	target := base64.StdEncoding.EncodeToString(make([]byte, 32))
	rec, err := signApproval(pw, target, "approve")
	if err != nil {
		t.Fatal(err)
	}
	// Flip the action: an attacker turning a "deny" into an "approve" is the
	// exact attack the signature exists to stop.
	tampered := rec
	tampered.Action = "deny"
	if _, ok := verifyApproval(tampered); ok {
		t.Error("a record with a swapped action must not verify")
	}
	other := rec
	other.PubKey = base64.StdEncoding.EncodeToString(append(make([]byte, 31), 0x01))
	if _, ok := verifyApproval(other); ok {
		t.Error("a record retargeted at another key must not verify")
	}
}

func TestApproveDeviceValidatesInput(t *testing.T) {
	const pw = "hunter2hunter2"
	installTestAdminKey(t, pw)
	if err := ApproveDevice("", "somekey", "approve"); err == nil {
		t.Error("an empty password must be refused")
	}
	if err := ApproveDevice(pw, "", "approve"); err == nil {
		t.Error("an empty device key must be refused")
	}
}
