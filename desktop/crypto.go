package main

// crypto.go mirrors the admin server's signing crypto so the Mac can issue the
// same admin-signed revocations. The Ed25519 signing seed is stored encrypted
// at rest (PBKDF2-HMAC-SHA256 + AES-256-GCM); a wrong password fails GCM auth,
// so no separate password hash is stored. Stdlib only.

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

const pbkdfIter = 600000

var errWrongPassword = errors.New("incorrect admin password")

// SignedRevocation must match the client's struct byte-for-byte over the wire.
type SignedRevocation struct {
	Action string `json:"action"` // "revoke" | "restore"
	PubKey string `json:"pubkey"` // base64(std) of the peer's 32-byte X25519 static key
	Seq    int64  `json:"seq"`
	Ts     int64  `json:"ts"`
	Sig    string `json:"sig"`
}

type adminKeyFile struct {
	Version   int    `json:"version"`
	PublicKey string `json:"public_key"`
	Salt      string `json:"salt"`
	Iter      int    `json:"iter"`
	Nonce     string `json:"nonce"`
	Sealed    string `json:"sealed"`
	Seq       int64  `json:"seq"`
	Epoch     int64  `json:"epoch"`
}

// canonicalRevocation is the exact byte string signed/verified. It MUST match
// the client's copy character-for-character.
func canonicalRevocation(action, pubB64 string, seq, ts int64) string {
	return fmt.Sprintf("OVLYREVOKE1|%s|%s|%d|%d", action, pubB64, seq, ts)
}

// SignedProvision assigns a node (by static key) a new overlay address and/or
// friendly name. Mirrored in the client; canonicalProvision defines the bytes.
type SignedProvision struct {
	PubKey  string `json:"pubkey"`
	Address string `json:"address"`
	Name    string `json:"name"`
	Seq     int64  `json:"seq"`
	Ts      int64  `json:"ts"`
	Sig     string `json:"sig"`
}

// canonicalProvision MUST match the client's copy character-for-character.
func canonicalProvision(pubB64, address, name string, seq, ts int64) string {
	return fmt.Sprintf("OVLYPROV1|%s|%s|%s|%d|%d", pubB64, address, name, seq, ts)
}

// SignedApproval admits (or denies) a device by static key.
type SignedApproval struct {
	Action string `json:"action"`
	PubKey string `json:"pubkey"`
	Seq    int64  `json:"seq"`
	Ts     int64  `json:"ts"`
	Sig    string `json:"sig"`
}

func canonicalApproval(action, pubB64 string, seq, ts int64) string {
	return fmt.Sprintf("OVLYAPPROVE1|%s|%s|%d|%d", action, pubB64, seq, ts)
}

// SignedNetworkConfig rotates the network name + PSK.
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

// SignedPolicy is admin policy (post-quantum switch), per-node or network-wide.
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
