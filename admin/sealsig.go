package main

// sealsig.go signs the sealed (password-encrypted) admin key blob with the
// admin key it contains. Nodes only let a SIGNED blob replace the one they
// hold (client adminpin.go), which stops any peer from flooding a garbage,
// maximum-epoch blob that would lock the admin password out network-wide.
// Blobs made before this existed are signed the next time an operator unlocks
// the key with the password (decryptSeed below), and re-distributed.

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
)

// minAdminPasswordLen is the minimum length of the NETWORK ADMIN password.
// The sealed key it protects is copied to every admitted node, so a leaked
// node's copy can be attacked offline; length is the defence that matters.
// (Existing passwords keep working; this applies when one is set or changed.)
const minAdminPasswordLen = 12

// canonicalSealedBlob is the exact byte string the admin key signs over a
// sealed blob. It MUST match the client's copy character for character.
func canonicalSealedBlob(akf adminKeyFile) string {
	return fmt.Sprintf("OVLYSEALED1|%d|%s|%s|%d|%s|%s|%d",
		akf.Version, akf.PublicKey, akf.Salt, akf.Iter, akf.Nonce, akf.Sealed, akf.Epoch)
}

// signSealedBlob sets akf.Sig using the admin key derived from seed.
func signSealedBlob(akf *adminKeyFile, seed []byte) {
	akf.Sig = base64.StdEncoding.EncodeToString(adminSignWithSeed(seed, []byte(canonicalSealedBlob(*akf))))
}

// decryptSeed opens the sealed seed with password. On success, a blob that
// predates signing is signed and re-distributed so the network upgrades.
// The caller MUST zero the returned seed after use.
func decryptSeed(akf adminKeyFile, password string) ([]byte, error) {
	seed, err := openSeed(akf, password)
	if err != nil {
		return nil, err
	}
	if akf.Sig == "" {
		up := akf
		signSealedBlob(&up, seed)
		if adminKeyConfigured() {
			if err := saveAdminKeyFile(up); err != nil {
				log.Printf("[adminkey] could not save signed admin key file: %v", err)
			}
		}
		distributeSealedKey(up)
		log.Printf("[adminkey] signed the sealed admin key (it predated blob signatures) and re-distributed it")
	}
	return seed, nil
}

// adminKeyFingerprintB64 returns the pinnable fingerprint of a base64 admin
// public key: "sha256:" + unpadded base64url(SHA-256(raw)) — the same format
// nodes accept as admin_key_fp / ADMIN_KEY_FP and the join QR carries.
func adminKeyFingerprintB64(pubB64 string) string {
	raw, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(raw) == 0 {
		return ""
	}
	h := sha256.Sum256(raw)
	return "sha256:" + base64.RawURLEncoding.EncodeToString(h[:])
}
