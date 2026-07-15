package main

// crypto.go: the admin signing key is an Ed25519 keypair whose private seed is
// stored encrypted at rest. The encryption key is derived from the operator's
// password with PBKDF2-HMAC-SHA256 (stdlib only — no external modules) and the
// seed is sealed with AES-256-GCM. A wrong password fails GCM authentication,
// so the auth tag doubles as the password verifier (no separate hash stored).

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// pbkdfIter is the PBKDF2 iteration count. Deliberately high: the encrypted
// admin key is the crown jewel, and signing happens rarely (only on a revoke).
const pbkdfIter = 600000

var errWrongPassword = errors.New("incorrect admin password")

// SignedRevocation is one signed statement about a peer's Noise static key.
// The same struct is mirrored in the client, and the signed bytes are defined
// by canonicalRevocation so both sides agree byte-for-byte.
type SignedRevocation struct {
	Action string `json:"action"` // "revoke" | "restore"
	PubKey string `json:"pubkey"` // base64(std) of the peer's 32-byte X25519 static key
	Seq    int64  `json:"seq"`    // monotonic per-admin-key counter
	Ts     int64  `json:"ts"`     // unix seconds (informational)
	Sig    string `json:"sig"`    // base64(std) Ed25519 signature over the canonical bytes
}

// adminKeyFile is the on-disk (encrypted) admin key. Only public_key, salt,
// nonce and seq are cleartext; the Ed25519 seed inside `sealed` is unreadable
// without the password.
type adminKeyFile struct {
	Version   int    `json:"version"`
	PublicKey string `json:"public_key"` // base64(std) Ed25519 public key
	Salt      string `json:"salt"`       // base64(std) PBKDF2 salt
	Iter      int    `json:"iter"`       // PBKDF2 iterations
	Nonce     string `json:"nonce"`      // base64(std) AES-GCM nonce
	Sealed    string `json:"sealed"`     // base64(std) AES-GCM ciphertext of the 32-byte seed
	Seq       int64  `json:"seq"`        // legacy; signing now uses a wall-clock nanosecond seq
	Epoch     int64  `json:"epoch"`      // bumped on password change; newer epoch supersedes when gossiped
}

// canonicalRevocation is the exact byte string that is signed and verified. It
// MUST match the client's copy character-for-character.
func canonicalRevocation(action, pubB64 string, seq, ts int64) string {
	return fmt.Sprintf("OVLYREVOKE1|%s|%s|%d|%d", action, pubB64, seq, ts)
}

// SignedProvision assigns a node (by static key) a new overlay address and/or
// friendly name. Mirrored in the client; canonicalProvision defines the signed
// bytes.
type SignedProvision struct {
	PubKey  string `json:"pubkey"`  // base64(std) target node static key
	Address string `json:"address"` // new overlay address or "" to leave unchanged
	Name    string `json:"name"`    // friendly name or "" to leave unchanged
	Seq     int64  `json:"seq"`
	Ts      int64  `json:"ts"`
	Sig     string `json:"sig"`
}

// canonicalProvision MUST match the client's copy character-for-character.
func canonicalProvision(pubB64, address, name string, seq, ts int64) string {
	return fmt.Sprintf("OVLYPROV1|%s|%s|%s|%d|%d", pubB64, address, name, seq, ts)
}

// SignedApproval admits (or denies) a device by static key. Mirrored in the
// client; canonicalApproval defines the signed bytes.
type SignedApproval struct {
	Action string `json:"action"` // "approve" | "deny"
	PubKey string `json:"pubkey"`
	Seq    int64  `json:"seq"`
	Ts     int64  `json:"ts"`
	Sig    string `json:"sig"`
}

func canonicalApproval(action, pubB64 string, seq, ts int64) string {
	return fmt.Sprintf("OVLYAPPROVE1|%s|%s|%d|%d", action, pubB64, seq, ts)
}

// SignedNetworkConfig rotates the network name + PSK. Mirrored in the client.
type SignedNetworkConfig struct {
	NetworkName string `json:"network_name"`
	PSK         string `json:"psk"`
	Epoch       int64  `json:"epoch"`
	Ts          int64  `json:"ts"`
	Sig         string `json:"sig"`
}

func canonicalNetConfig(name, psk string, epoch, ts int64) string {
	return fmt.Sprintf("OVLYNETCFG1|%s|%s|%d|%d", name, psk, epoch, ts)
}

// SignedPolicy is admin policy (the post-quantum switch), per-node or network-wide.
type SignedPolicy struct {
	PubKey      string `json:"pubkey"` // "" = network-wide; else base64 target key
	PostQuantum bool   `json:"post_quantum"`
	Epoch       int64  `json:"epoch"`
	Ts          int64  `json:"ts"`
	Sig         string `json:"sig"`
}

func canonicalPolicy(pubB64 string, pq bool, epoch, ts int64) string {
	return fmt.Sprintf("OVLYPOLICY1|%s|%t|%d|%d", pubB64, pq, epoch, ts)
}

// pbkdf2SHA256 is a small stdlib PBKDF2-HMAC-SHA256 (RFC 8018) so the admin
// module needs no external dependencies.
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := func(data []byte) []byte {
		m := hmac.New(sha256.New, password)
		m.Write(data)
		return m.Sum(nil)
	}
	hLen := sha256.Size
	numBlocks := (keyLen + hLen - 1) / hLen
	var dk []byte
	idx := make([]byte, 4)
	for block := 1; block <= numBlocks; block++ {
		binary.BigEndian.PutUint32(idx, uint32(block))
		u := prf(append(append([]byte{}, salt...), idx...))
		t := make([]byte, len(u))
		copy(t, u)
		for n := 1; n < iter; n++ {
			u = prf(u)
			for i := range t {
				t[i] ^= u[i]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

func aesgcmSeal(key, plaintext []byte) (nonce, ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return nonce, gcm.Seal(nil, nonce, plaintext, nil), nil
}

func aesgcmOpen(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}
