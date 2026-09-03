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
	"strings"
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

// SignedNodeConfig mirrors the client's record (client/nodeconfig.go). The two
// definitions and the two canonical-string builders MUST stay byte-identical:
// the admin signs the string this file produces and the client verifies the
// string its own copy produces, so any divergence shows up as "invalid
// signature" on every node rather than as a compile error here.
type SignedNodeConfig struct {
	PubKey string `json:"pubkey"` // "" = network-wide; else base64 target static key

	DHT         *bool `json:"dht,omitempty"`
	UseRelays   *bool `json:"use_public_relays,omitempty"`
	PublicRelay *bool `json:"public_relay,omitempty"`
	ExitNode    *bool `json:"exit_node,omitempty"`

	Trackers   *[]string `json:"trackers,omitempty"`
	TrackersOn *bool     `json:"trackers_on,omitempty"`

	Rendezvous     *string `json:"rendezvous,omitempty"`
	RendezvousAuth *string `json:"rendezvous_auth,omitempty"`

	RelayUp    *int64 `json:"relay_up_bps,omitempty"`
	RelayDown  *int64 `json:"relay_down_bps,omitempty"`
	RelayQuota *int64 `json:"relay_quota_bytes,omitempty"`
	ExitUp     *int64 `json:"exit_up_bps,omitempty"`
	ExitDown   *int64 `json:"exit_down_bps,omitempty"`
	ExitQuota  *int64 `json:"exit_quota_bytes,omitempty"`

	Epoch int64  `json:"epoch"`
	Ts    int64  `json:"ts"`
	Sig   string `json:"sig"`
}

// canonicalNodeConfig must match client/nodeconfig.go exactly, including the
// "-" rendering of absent fields (which is what keeps "unset" and "false" from
// signing to the same string).
func canonicalNodeConfig(c SignedNodeConfig) string {
	b := func(p *bool) string {
		if p == nil {
			return "-"
		}
		return fmt.Sprintf("%t", *p)
	}
	i := func(p *int64) string {
		if p == nil {
			return "-"
		}
		return fmt.Sprintf("%d", *p)
	}
	str := func(p *string) string {
		if p == nil {
			return "-"
		}
		return *p
	}
	trackers := "-"
	if c.Trackers != nil {
		trackers = strings.Join(*c.Trackers, ",")
	}
	return fmt.Sprintf("OVLYNODECFG1|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%d|%d",
		c.PubKey, b(c.DHT), b(c.UseRelays), b(c.PublicRelay), b(c.ExitNode),
		trackers, b(c.TrackersOn), str(c.Rendezvous), str(c.RendezvousAuth),
		i(c.RelayUp), i(c.RelayDown), i(c.RelayQuota),
		i(c.ExitUp), i(c.ExitDown), i(c.ExitQuota),
		c.Epoch, c.Ts)
}
