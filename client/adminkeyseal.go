package main

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
	"path/filepath"
	"strings"
	"sync"
)

var (
	sealedMu      sync.Mutex
	sealedBlob    []byte
	sealedEpoch   int64
	sealedKeyFile string
)


// sealedMeta is the subset of the blob the client needs to read: the public key
// (to set the trusted admin key) and the epoch (for supersession).
type sealedMeta struct {
	PublicKey string `json:"public_key"`
	Epoch     int64  `json:"epoch"`
}

// factoryResetAdminIfRequested wipes persisted admin-key state (sealed key +
// trusted public key) when APGO_RESET_ADMIN is set to a truthy value, or when a
// sentinel file named RESET_ADMIN exists beside the sealed key. This lets an
// operator clear the "network admin password" from a node whose Docker volume
// outlived a `compose down`. The sentinel file is removed after use so the wipe
// happens exactly once, not on every subsequent boot.
func factoryResetAdminIfRequested() {
	sealed := os.Getenv("SEALED_ADMIN_KEY_FILE")
	pub := os.Getenv("ADMIN_PUBKEY_FILE")

	reset := false
	switch strings.ToLower(strings.TrimSpace(os.Getenv("APGO_RESET_ADMIN"))) {
	case "1", "true", "yes", "on":
		reset = true
	}
	var sentinel string
	if sealed != "" {
		sentinel = filepath.Join(filepath.Dir(sealed), "RESET_ADMIN")
		if _, err := os.Stat(sentinel); err == nil {
			reset = true
		}
	}
	if !reset {
		return
	}

	for _, f := range []string{sealed, pub} {
		if f == "" {
			continue
		}
		if err := os.Remove(f); err == nil {
			log.Printf("[reset] removed admin-key state file %s", f)
		}
	}
	// Clear anything already loaded into memory this process.
	adminPub = nil
	adminPubParsed = nil
	if sentinel != "" {
		_ = os.Remove(sentinel)
	}
	log.Printf("[reset] admin key/password wiped on this node. NOTE: reset every node together (or rotate network_name) or a peer will re-seed the old key via TOFU.")
}

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
// (an authenticated LOCAL admin action, not gossip), it may replace a previously
// trusted admin public key — e.g. to establish/reset the key on a fresh network
// where a stale public key was left on the state volume.
func storeSealedAdminKeyForce(blob []byte, persist, force bool) bool {
	var m sealedMeta
	if json.Unmarshal(blob, &m) != nil || m.PublicKey == "" {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(m.PublicKey)
	if err != nil || !adminPubValid(raw) {
		return false
	}
	// First-come-first-served (trust-on-first-use). Via GOSSIP we adopt an admin
	// key only if we don't already trust one (first key we hear wins), OR it's the
	// SAME key with a newer epoch — i.e. a password change (which re-encrypts the
	// same key). A DIFFERENT key arriving by gossip is refused: we keep the first
	// key we saw, so no peer can silently swap in another admin key. Only a LOCAL
	// operator (force: they typed the network admin password on THIS node) may
	// replace a trusted key with a different one — a deliberate reset/rotation.
	sameKey := !adminKeySet() || adminSameKey(raw)
	if !force && !sameKey {
		return false
	}

	sealedMu.Lock()
	if sealedBlob != nil && m.Epoch <= sealedEpoch && !force {
		sealedMu.Unlock()
		return false
	}
	sealedBlob = append([]byte(nil), blob...)
	sealedEpoch = m.Epoch
	path := sealedKeyFile
	sealedMu.Unlock()

	changedKey := adminKeySet() && !adminSameKey(raw)
	setAdminPub(raw, true)
	if changedKey {
		// A local operator replaced the trusted key — re-verify persisted signed
		// records against the new key so stale ones (signed by the old key) drop.
		if rf := os.Getenv("REVOCATIONS_FILE"); rf != "" {
			revocations.load(rf)
		}
		log.Printf("[adminkey] trusted admin key replaced by local operator (epoch %d)", m.Epoch)
	}
	if persist && path != "" {
		tmp := path + ".tmp"
		if os.WriteFile(tmp, blob, 0o600) == nil {
			_ = os.Rename(tmp, path)
		}
	}
	log.Printf("[adminkey] adopted sealed admin key (epoch %d)", m.Epoch)
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
