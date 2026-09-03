package overlaymobile

// adminsign.go is the ADMIN SIGNING side on mobile — the half that used to
// live only in the admin and desktop modules.
//
// Until this file existed, a phone could verify admin-signed actions but never
// produce one, so iOS and Android could see a device sitting in "pending" and
// do nothing about it. On a network whose only always-on admin panel is a
// container in a cluster, that meant approving a new laptop required finding a
// computer first — the phone in your hand was the one device guaranteed to be
// on the overlay and the one device that could not help.
//
// Everything here is a port of desktop/adminkey.go + desktop/crypto.go, and it
// MUST stay byte-compatible with them: the same PBKDF2-SHA256 parameters, the
// same AES-256-GCM sealing, the same ML-DSA-65 seed derivation, and above all
// the same canonical signing strings (canonicalApproval, in approvals.go).
// A signature produced here is verified by every other node with no idea it
// came from a phone, so any divergence shows up as "approvals from mobile are
// silently ignored" rather than as a build error.
//
// The private key is never stored on the device in usable form: the phone
// holds only the password-sealed blob that gossips around the mesh, and the
// seed exists in memory for the duration of one signature before being zeroed.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"time"
)

// pbkdfIter must match the admin/desktop signers. Changing it here alone would
// derive a different key from the same password and read as "wrong password".
const pbkdfIter = 600000

var errWrongPassword = errors.New("incorrect admin password")

// adminKeyFile mirrors the sealed blob's JSON exactly as the admin module
// writes it.
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

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// adminSignWithSeed derives the ML-DSA-65 keypair from the seed and signs.
func adminSignWithSeed(seed, msg []byte) []byte {
	_, sk := adminSig.DeriveKey(seed)
	return adminSig.Sign(sk, msg, nil)
}

// currentAdminKeyFile parses the sealed blob this node holds. The blob arrives
// by mesh gossip (control frame 'Q'), so a phone that has talked to any peer
// generally has it without the user doing anything.
func currentAdminKeyFile() (adminKeyFile, bool) {
	blob := getSealedAdminKey()
	if len(blob) == 0 {
		return adminKeyFile{}, false
	}
	var akf adminKeyFile
	if json.Unmarshal(blob, &akf) != nil || akf.Sealed == "" {
		return adminKeyFile{}, false
	}
	return akf, true
}

// adminKeyAvailable reports whether this device can sign admin actions given
// the password — i.e. whether it holds the sealed key at all.
func adminKeyAvailable() bool {
	_, ok := currentAdminKeyFile()
	return ok
}

func decryptSeed(akf adminKeyFile, password string) ([]byte, error) {
	salt, _ := base64.StdEncoding.DecodeString(akf.Salt)
	nonce, _ := base64.StdEncoding.DecodeString(akf.Nonce)
	sealed, _ := base64.StdEncoding.DecodeString(akf.Sealed)
	iter := akf.Iter
	if iter <= 0 {
		iter = pbkdfIter
	}
	dk := pbkdf2SHA256([]byte(password), salt, iter, 32)
	out, err := aesgcmOpen(dk, nonce, sealed)
	zero(dk)
	if err != nil {
		return nil, errWrongPassword
	}
	return out, nil
}

// signApproval produces an admin-signed approval (or denial) for a device's
// static key. Byte-for-byte identical to the desktop signer.
func signApproval(password, targetPubB64, action string) (SignedApproval, error) {
	akf, ok := currentAdminKeyFile()
	if !ok {
		return SignedApproval{}, errors.New("this device does not hold the network admin key yet")
	}
	seed, err := decryptSeed(akf, password)
	if err != nil {
		return SignedApproval{}, errWrongPassword
	}
	seq := time.Now().UnixNano()
	ts := time.Now().Unix()
	sig := adminSignWithSeed(seed, []byte(canonicalApproval(action, targetPubB64, seq, ts)))
	zero(seed)
	return SignedApproval{
		Action: action, PubKey: targetPubB64, Seq: seq, Ts: ts,
		Sig: base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// applyAndGossipApproval applies a signed approval locally and floods it to
// every established session, which is exactly what the desktop panel's
// /api/approve-signed does. Approval gossip is admission-exempt, so it reaches
// peers even from a node that is not itself approved yet.
func applyAndGossipApproval(rec SignedApproval) error {
	pub, ok := verifyApproval(rec)
	if !ok {
		// Should be impossible for something we just signed; if it happens the
		// phone's trusted admin public key disagrees with the sealed key it
		// signed with, which is worth reporting rather than silently dropping.
		return errors.New("the signature did not verify against this network's admin key")
	}
	approvals.applySigned(rec, pub)
	frame := buildApprovalFrame(rec)
	if frame == nil || GlobalSessions == nil || GlobalConn == nil {
		return nil
	}
	for _, addr := range GlobalSessions.EstablishedAddrs() {
		if s := GlobalSessions.GetByAddr(addr); s != nil && s.Established() {
			_ = sendPacket(GlobalConn, addr, s, frame)
		}
	}
	return nil
}
