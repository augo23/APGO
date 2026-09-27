package overlaymobile

// adminpin.go pins the network admin key to a fingerprint distributed out of
// band (the join QR, the node config, or the ADMIN_KEY_FP environment
// variable), and signs the sealed admin-key blob.
//
// THE BUG THIS CLOSES
//
// A node with no admin key used to adopt the FIRST admin public key any peer
// seeded to it ('P' or 'Q' control frames). Those frames are deliberately
// exempt from admission control, so an unapproved device that knows the PSK —
// or a revoked one that still does — could race the real network to a freshly
// joined node and become its admin: sign approvals, provisions and policy for
// it, rotate it onto another network, and make the real admin's revocations
// fail verification there. Every node that joined by QR started in exactly
// that state, because the QR carried no admin key.
//
// A fingerprint pin fixes it. When a pin is configured, a seeded key is only
// adopted if SHA-256 of its marshaled bytes matches the pin, and a previously
// adopted key that does not match is discarded at startup. The join QR now
// carries the pin, so every device that joins by QR is protected from its
// first packet. With NO pin, the old trust-on-first-use behaviour remains for
// compatibility (logged loudly); ADMIN_TOFU=0 turns it off entirely.
//
// SEALED-BLOB SIGNATURES
//
// The sealed (password-encrypted) admin key blob used to be unsigned, and a
// node replaced its copy with ANY blob naming the same public key and a higher
// epoch — so a single peer could flood a garbage blob with the maximum epoch
// and permanently lock the admin password out network-wide. Blobs are now
// signed by the admin key they contain (see canonicalSealedBlob). A signed
// blob always supersedes an unsigned one; among signed blobs the newer epoch
// wins; an unsigned blob is only ever accepted when a node holds none at all
// (legacy networks), and never replaces anything.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// adminKeyFPPrefix labels the fingerprint format so it can evolve.
const adminKeyFPPrefix = "sha256:"

var (
	adminPinMu sync.RWMutex
	adminPin   string // normalized fingerprint, "" = no pin
)

// adminKeyFingerprint returns the full-length fingerprint of a marshaled admin
// public key: "sha256:" + unpadded base64url(SHA-256(raw)). Unlike
// peerKeyFingerprint (48 bits, for display), this is collision resistant and
// safe to pin.
func adminKeyFingerprint(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	h := sha256.Sum256(raw)
	return adminKeyFPPrefix + base64.RawURLEncoding.EncodeToString(h[:])
}

// normalizeAdminKeyFP accepts "sha256:<b64url>", a bare base64url/base64
// digest, or hex, and returns the canonical form ("" if unparseable).
func normalizeAdminKeyFP(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	v = strings.TrimPrefix(v, adminKeyFPPrefix)
	var digest []byte
	for _, dec := range []func(string) ([]byte, error){
		base64.RawURLEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.StdEncoding.DecodeString,
	} {
		if b, err := dec(v); err == nil && len(b) == sha256.Size {
			digest = b
			break
		}
	}
	if digest == nil && len(v) == 2*sha256.Size {
		if b, err := hex.DecodeString(v); err == nil {
			digest = b
		}
	}
	if digest == nil {
		return ""
	}
	return adminKeyFPPrefix + base64.RawURLEncoding.EncodeToString(digest)
}

// applyAdminKeyPin sets the pin from config, overridden by ADMIN_KEY_FP.
func applyAdminKeyPin(fromConfig string) {
	v := fromConfig
	if e := os.Getenv("ADMIN_KEY_FP"); strings.TrimSpace(e) != "" {
		v = e
	}
	if strings.TrimSpace(v) == "" {
		adminPinMu.Lock()
		adminPin = "" // a restarted core (mobile) must not keep a previous network's pin
		adminPinMu.Unlock()
		return
	}
	n := normalizeAdminKeyFP(v)
	if n == "" {
		log.Printf("[adminkey] admin_key_fp / ADMIN_KEY_FP %q is not a valid SHA-256 fingerprint — IGNORED", v)
		adminPinMu.Lock()
		adminPin = ""
		adminPinMu.Unlock()
		return
	}
	adminPinMu.Lock()
	adminPin = n
	adminPinMu.Unlock()
	log.Printf("[adminkey] admin key pinned to %s — seeded keys that don't match are refused", n)
}

// adminKeyPinned returns the configured pin ("" if none).
func adminKeyPinned() string {
	adminPinMu.RLock()
	defer adminPinMu.RUnlock()
	return adminPin
}

// adminTOFUAllowed reports whether an UNPINNED node may adopt a seeded key.
func adminTOFUAllowed() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ADMIN_TOFU"))) {
	case "0", "false", "no", "off":
		return false
	}
	return true
}

// adminKeyPinAllows reports whether raw may become this node's trusted admin
// key through gossip or persisted TOFU state. It does not consider explicit
// local configuration (ADMIN_PUBLIC_KEY), which always wins.
func adminKeyPinAllows(raw []byte) bool {
	pin := adminKeyPinned()
	if pin == "" {
		return adminTOFUAllowed()
	}
	return adminKeyFingerprint(raw) == pin
}

// trustedAdminKeyFP is the fingerprint of the currently trusted key ("" none).
func trustedAdminKeyFP() string {
	return adminKeyFingerprint(adminPubBytes())
}

var (
	tofuWarnMu   sync.Mutex
	tofuWarnLast time.Time
)

// noteAdminSeedRefused logs a refused seed, damped to once a minute.
func noteAdminSeedRefused(raw []byte, source string) {
	tofuWarnMu.Lock()
	defer tofuWarnMu.Unlock()
	if time.Since(tofuWarnLast) < time.Minute {
		return
	}
	tofuWarnLast = time.Now()
	if pin := adminKeyPinned(); pin != "" {
		log.Printf("[adminkey] REFUSED admin key %s from %s: does not match pinned fingerprint %s",
			adminKeyFingerprint(raw), source, pin)
	} else {
		log.Printf("[adminkey] REFUSED admin key %s from %s: trust-on-first-use disabled (ADMIN_TOFU=0) and no admin_key_fp pinned",
			adminKeyFingerprint(raw), source)
	}
}

// --- sealed-blob signatures ------------------------------------------------

// sealedBlobFields are the signed fields of the admin app's adminKeyFile.
type sealedBlobFields struct {
	Version   int    `json:"version"`
	PublicKey string `json:"public_key"`
	Salt      string `json:"salt"`
	Iter      int    `json:"iter"`
	Nonce     string `json:"nonce"`
	Sealed    string `json:"sealed"`
	Epoch     int64  `json:"epoch"`
	Sig       string `json:"sig"`
}

// canonicalSealedBlob is the exact byte string the admin key signs over a
// sealed blob. It MUST match the admin/desktop signers character for
// character. Every field that affects decryption or supersession is covered.
func canonicalSealedBlob(f sealedBlobFields) string {
	return fmt.Sprintf("OVLYSEALED1|%d|%s|%s|%d|%s|%s|%d",
		f.Version, f.PublicKey, f.Salt, f.Iter, f.Nonce, f.Sealed, f.Epoch)
}

// sealedBlobSigValid verifies f.Sig with the admin key named inside the blob
// (raw). The caller separately checks that raw is the key it trusts or may
// adopt; this proves the blob was produced by that key's holder.
func sealedBlobSigValid(f sealedBlobFields, raw []byte) bool {
	if f.Sig == "" {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(f.Sig)
	if err != nil {
		return false
	}
	pk, err := adminSig.UnmarshalBinaryPublicKey(raw)
	if err != nil {
		return false
	}
	return adminSig.Verify(pk, []byte(canonicalSealedBlob(f)), sig, nil)
}

// maxSealedEpochSkew bounds how far in the future a blob's epoch (wall-clock
// nanoseconds at signing) may be. A far-future epoch can never be superseded,
// so it is refused outright rather than allowed to wedge the network.
const maxSealedEpochSkew = 48 * time.Hour

func sealedEpochPlausible(epoch int64) bool {
	return epoch <= time.Now().Add(maxSealedEpochSkew).UnixNano()
}

// adminPubBytes returns the marshaled trusted admin key, or nil.
func adminPubBytes() []byte { return adminPub }
