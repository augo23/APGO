package overlaymobile

// adminkeyseal.go distributes the PASSWORD-ENCRYPTED admin key across the mesh
// so any node's admin panel can sign revocations/provisions — given the admin
// password — without the private key ever being stored or sent unencrypted.
//
// The blob is exactly the admin app's adminKeyFile JSON (PBKDF2 + AES-256-GCM
// sealed Ed25519 seed). The client only ever holds the ciphertext; decryption
// happens transiently in the admin panel when the operator types the password.
//
// It rides the same overlay gossip as the admin public key (control frame 'Q'),
// superseded by a monotonic epoch so a password change (which re-encrypts the
// same key under a new password, bumping the epoch) propagates network-wide.

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"sync"
)

var (
	sealedMu      sync.Mutex
	sealedBlob    []byte
	sealedEpoch   int64
	sealedSigned  bool // the held blob carries a valid admin signature
	sealedKeyFile string
)

func loadSealedAdminKey() {
	sealedKeyFile = os.Getenv("SEALED_ADMIN_KEY_FILE")
	if sealedKeyFile == "" {
		return
	}
	if data, err := os.ReadFile(sealedKeyFile); err == nil {
		storeSealedAdminKey(data, false)
	}
}

// storeSealedAdminKey adopts blob if its epoch is newer than what we hold and it
// belongs to the admin key we already trust (or we trust none yet). It sets the
// trusted admin public key and optionally persists. Returns true if adopted.
func storeSealedAdminKey(blob []byte, persist bool) bool {
	return storeSealedAdminKeyForce(blob, persist, false)
}

// storeSealedAdminKeyForce is like storeSealedAdminKey but, when force is true
// (a LOCAL admin action over the control socket, not gossip), it may replace
// the blob without the epoch ordering and — only while this node holds a bare
// trusted public key with NO sealed blob for it (a stale key left on a state
// volume) — establish a different admin key. A node that holds a live sealed
// blob never switches admin keys through this path; that takes a deliberate
// factory reset (APGO_RESET_ADMIN / the RESET_ADMIN sentinel), which needs
// write access to the node's state, not just the control socket.
//
// Acceptance rules (see adminpin.go for why):
//   - the blob's key must be the trusted key, or — if none is trusted — one the
//     admin_key_fp pin (or TOFU policy) allows;
//   - a blob with an implausibly far-future epoch is refused;
//   - a SIGNED blob (signed by the key it contains) supersedes an unsigned one
//     regardless of epoch, and an older signed blob by newer epoch;
//   - an UNSIGNED blob is only accepted when no blob is held (legacy
//     networks); it never replaces anything, so no peer can wedge the admin
//     password with a garbage max-epoch blob.
func storeSealedAdminKeyForce(blob []byte, persist, force bool) bool {
	var f sealedBlobFields
	if json.Unmarshal(blob, &f) != nil || f.PublicKey == "" {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(f.PublicKey)
	if err != nil || !adminPubValid(raw) {
		return false
	}
	if !sealedEpochPlausible(f.Epoch) {
		log.Printf("[adminkey] refused sealed admin key blob with a far-future epoch (%d)", f.Epoch)
		return false
	}
	signed := sealedBlobSigValid(f, raw)
	if f.Sig != "" && !signed {
		log.Printf("[adminkey] refused sealed admin key blob with an INVALID signature")
		return false
	}

	// Decide and store under one lock so two concurrent deliveries can't
	// both pass the supersession check.
	trusted := adminKeySet()
	sameKey := trusted && adminSameKey(raw)
	sealedMu.Lock()
	accept := func() bool {
		haveBlob, haveSigned, haveEpoch := sealedBlob != nil, sealedSigned, sealedEpoch
		switch {
		case sameKey:
			// Same admin key: a password change, a signature upgrade, or a replay.
		case !trusted:
			if !adminKeyPinAllows(raw) {
				noteAdminSeedRefused(raw, "sealed-key blob")
				return false
			}
		default:
			// A DIFFERENT key than the one trusted. Never via gossip (first key
			// wins); locally only to replace a stale bare public key.
			if !force || haveBlob {
				return false
			}
			if pin := adminKeyPinned(); pin != "" && adminKeyFingerprint(raw) != pin {
				noteAdminSeedRefused(raw, "local control socket")
				return false
			}
		}
		if haveBlob && sameKey {
			switch {
			case signed && !haveSigned:
				// Signature upgrade: always wins over an unsigned blob.
			case signed && haveSigned:
				if f.Epoch < haveEpoch || (f.Epoch == haveEpoch && !force) {
					return false
				}
			case !signed && haveSigned:
				return false // unsigned never replaces signed
			default: // both unsigned (legacy)
				if !force || f.Epoch < haveEpoch {
					return false
				}
			}
		}
		return true
	}()
	if !accept {
		sealedMu.Unlock()
		return false
	}
	sealedBlob = append([]byte(nil), blob...)
	sealedEpoch = f.Epoch
	sealedSigned = signed
	path := sealedKeyFile
	sealedMu.Unlock()

	changedKey := trusted && !sameKey
	setAdminPub(raw, true)
	if changedKey {
		// A local operator replaced a stale trusted key — re-verify persisted
		// signed records against the new key so stale ones drop.
		if rf := os.Getenv("REVOCATIONS_FILE"); rf != "" {
			revocations.load(rf)
		}
		log.Printf("[adminkey] stale trusted admin key replaced by local operator (epoch %d)", f.Epoch)
	}
	if persist && path != "" {
		tmp := path + ".tmp"
		if os.WriteFile(tmp, blob, 0o600) == nil {
			_ = os.Rename(tmp, path)
		}
	}
	state := "UNSIGNED legacy blob"
	if signed {
		state = "signed"
	}
	log.Printf("[adminkey] adopted sealed admin key %s (epoch %d, %s)", adminKeyFingerprint(raw), f.Epoch, state)
	return true
}

func getSealedAdminKey() []byte {
	sealedMu.Lock()
	defer sealedMu.Unlock()
	return sealedBlob
}

// buildSealedKeyFrame returns an "OVLYCTL1Q<blob>" gossip payload, or nil.
func buildSealedKeyFrame() []byte {
	blob := getSealedAdminKey()
	if blob == nil {
		return nil
	}
	out := append([]byte(nil), ctlMagic...)
	out = append(out, 'Q')
	return append(out, blob...)
}
