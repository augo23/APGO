package main

// adminkey.go creates and uses the password-encrypted admin key. The key is
// distributed across the mesh (as ciphertext) via the client, so ANY node's
// admin panel can sign — given the admin password — by fetching the sealed blob
// and decrypting it transiently in memory. The seed is never stored or sent
// unencrypted, and is zeroed after each signature.
//
// Signature ordering uses a wall-clock nanosecond "seq" so multiple admin panels
// can sign independently without a shared counter (latest change wins).

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"
)

var adminKeyMu sync.Mutex

// genAdminKey creates a new password-encrypted admin signing key and returns its
// public key (base64). Refuses if the network already has one.
func genAdminKey(password string) (string, error) {
	// Block only if a usable SIGNING key already exists here. A bare trusted
	// public key (e.g. a stale one left on the state volume of a fresh network)
	// must not block creating one, or you'd be permanently locked out.
	if adminKeyAvailable() {
		return "", errors.New("an admin key already exists for this network")
	}
	if len(password) < 8 {
		return "", errors.New("password must be at least 8 characters")
	}
	// Post-quantum admin key: a random seed, from which the ML-DSA-65 keypair is
	// derived deterministically. Only the 32-byte seed is encrypted at rest.
	seed := make([]byte, adminSignSeedSize())
	if _, err := rand.Read(seed); err != nil {
		return "", err
	}
	pubBytes, err := adminPubFromSeed(seed)
	if err != nil {
		return "", err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk := pbkdf2SHA256([]byte(password), salt, pbkdfIter, 32)
	nonce, sealed, err := aesgcmSeal(dk, seed)
	zero(seed)
	if err != nil {
		return "", err
	}
	akf := adminKeyFile{
		Version:   1,
		PublicKey: base64.StdEncoding.EncodeToString(pubBytes),
		Salt:      base64.StdEncoding.EncodeToString(salt),
		Iter:      pbkdfIter,
		Nonce:     base64.StdEncoding.EncodeToString(nonce),
		Sealed:    base64.StdEncoding.EncodeToString(sealed),
		Epoch:     time.Now().UnixNano(),
	}
	if err := saveAdminKeyFile(akf); err != nil {
		return "", err
	}
	distributeSealedKey(akf)
	// Turning on admission control: approve the current members so only NEW
	// devices need approval from here on.
	bootstrapApprovals(password)
	return akf.PublicKey, nil
}

func adminKeyPath() string { return env("ADMIN_KEY_FILE", "/adminkey/admin.key") }

// adminKeyConfigured reports whether THIS node holds the key file locally.
func adminKeyConfigured() bool {
	_, err := os.Stat(adminKeyPath())
	return err == nil
}

// adminKeyAvailable reports whether the network has an admin key this node can
// use to sign — either the local file, or the ciphertext gossiped to our client.
func adminKeyAvailable() bool {
	_, ok := currentAdminKeyFile()
	return ok
}

// networkHasAdminKey reports whether the NETWORK already has an admin key, even
// if the encrypted blob hasn't reached this node yet (the client trusts the
// admin public key). Used to refuse creating a second, conflicting key.
func networkHasAdminKey() bool {
	if adminKeyAvailable() {
		return true
	}
	if code, body, err := ctlGet("/api/info"); err == nil && code == 200 {
		var m struct {
			AdminTrusted bool `json:"admin_trusted"`
		}
		if json.Unmarshal(body, &m) == nil && m.AdminTrusted {
			return true
		}
	}
	return false
}

// currentAdminKeyFile returns the admin key blob, preferring the local file and
// falling back to the sealed blob gossiped to our client.
func currentAdminKeyFile() (adminKeyFile, bool) {
	if akf, err := loadAdminKeyFile(); err == nil && akf.PublicKey != "" {
		return akf, true
	}
	code, body, err := ctlGet("/api/admin-key-sealed")
	if err != nil || code != 200 {
		return adminKeyFile{}, false
	}
	var akf adminKeyFile
	if json.Unmarshal(body, &akf) != nil || akf.PublicKey == "" {
		return adminKeyFile{}, false
	}
	return akf, true
}

// distributeSealedKey hands the ciphertext blob to our client, which stores it
// and gossips it to every node.
func distributeSealedKey(akf adminKeyFile) {
	if blob, err := json.Marshal(akf); err == nil {
		_, _, _ = ctlPost("/api/admin-key-sealed", blob)
	}
}

func loadAdminKeyFile() (adminKeyFile, error) {
	var akf adminKeyFile
	data, err := os.ReadFile(adminKeyPath())
	if err != nil {
		return akf, err
	}
	return akf, json.Unmarshal(data, &akf)
}

func saveAdminKeyFile(akf adminKeyFile) error {
	data, err := json.MarshalIndent(akf, "", "  ")
	if err != nil {
		return err
	}
	tmp := adminKeyPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, adminKeyPath())
}

// decryptSeed derives the key-encryption key from password and opens the sealed
// Ed25519 seed. The caller MUST zero the returned seed after use.
func decryptSeed(akf adminKeyFile, password string) ([]byte, error) {
	salt, _ := base64.StdEncoding.DecodeString(akf.Salt)
	nonce, _ := base64.StdEncoding.DecodeString(akf.Nonce)
	sealed, _ := base64.StdEncoding.DecodeString(akf.Sealed)
	iter := akf.Iter
	if iter <= 0 {
		iter = pbkdfIter
	}
	dk := pbkdf2SHA256([]byte(password), salt, iter, 32)
	return aesgcmOpen(dk, nonce, sealed)
}

// changeAdminPassword re-encrypts the admin key under a new password (given the
// current one), bumps the epoch, and re-distributes it network-wide.
func changeAdminPassword(oldPw, newPw string) error {
	if len(newPw) < 8 {
		return errors.New("new password must be at least 8 characters")
	}
	adminKeyMu.Lock()
	defer adminKeyMu.Unlock()

	akf, ok := currentAdminKeyFile()
	if !ok {
		return errors.New("no admin key available on this node")
	}
	seed, err := decryptSeed(akf, oldPw)
	if err != nil {
		return errWrongPassword
	}
	defer zero(seed)

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	dk := pbkdf2SHA256([]byte(newPw), salt, pbkdfIter, 32)
	nonce, sealed, err := aesgcmSeal(dk, seed)
	if err != nil {
		return err
	}
	akf.Salt = base64.StdEncoding.EncodeToString(salt)
	akf.Nonce = base64.StdEncoding.EncodeToString(nonce)
	akf.Sealed = base64.StdEncoding.EncodeToString(sealed)
	akf.Iter = pbkdfIter
	akf.Epoch = time.Now().UnixNano()

	if adminKeyConfigured() {
		_ = saveAdminKeyFile(akf)
	}
	distributeSealedKey(akf)
	return nil
}

// signRevocation decrypts the admin key with password and signs a revoke/restore
// for targetPubB64. Uses a wall-clock nanosecond seq (distributed-safe).
func signRevocation(password, targetPubB64, action string) (SignedRevocation, error) {
	adminKeyMu.Lock()
	defer adminKeyMu.Unlock()

	akf, ok := currentAdminKeyFile()
	if !ok {
		return SignedRevocation{}, errors.New("no admin key available on this node")
	}
	seed, err := decryptSeed(akf, password)
	if err != nil {
		return SignedRevocation{}, errWrongPassword
	}
	seq := time.Now().UnixNano()
	ts := time.Now().Unix()
	sig := adminSignWithSeed(seed, []byte(canonicalRevocation(action, targetPubB64, seq, ts)))
	zero(seed)

	return SignedRevocation{
		Action: action,
		PubKey: targetPubB64,
		Seq:    seq,
		Ts:     ts,
		Sig:    base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// signProvision decrypts the admin key with password and signs an overlay-address
// / friendly-name assignment for targetPubB64.
func signProvision(password, targetPubB64, address, name string) (SignedProvision, error) {
	adminKeyMu.Lock()
	defer adminKeyMu.Unlock()

	akf, ok := currentAdminKeyFile()
	if !ok {
		return SignedProvision{}, errors.New("no admin key available on this node")
	}
	seed, err := decryptSeed(akf, password)
	if err != nil {
		return SignedProvision{}, errWrongPassword
	}
	seq := time.Now().UnixNano()
	ts := time.Now().Unix()
	sig := adminSignWithSeed(seed, []byte(canonicalProvision(targetPubB64, address, name, seq, ts)))
	zero(seed)

	return SignedProvision{
		PubKey:  targetPubB64,
		Address: address,
		Name:    name,
		Seq:     seq,
		Ts:      ts,
		Sig:     base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// signApproval signs an admission approve/deny for a device static key.
func signApproval(password, targetPubB64, action string) (SignedApproval, error) {
	adminKeyMu.Lock()
	defer adminKeyMu.Unlock()

	akf, ok := currentAdminKeyFile()
	if !ok {
		return SignedApproval{}, errors.New("no admin key available on this node")
	}
	seed, err := decryptSeed(akf, password)
	if err != nil {
		return SignedApproval{}, errWrongPassword
	}
	seq := time.Now().UnixNano()
	ts := time.Now().Unix()
	sig := adminSignWithSeed(seed, []byte(canonicalApproval(action, targetPubB64, seq, ts)))
	zero(seed)

	return SignedApproval{Action: action, PubKey: targetPubB64, Seq: seq, Ts: ts,
		Sig: base64.StdEncoding.EncodeToString(sig)}, nil
}

// signNetworkConfig signs a new network name + PSK rotation with a fresh epoch.
func signNetworkConfig(password, name, psk string) (SignedNetworkConfig, error) {
	adminKeyMu.Lock()
	defer adminKeyMu.Unlock()

	akf, ok := currentAdminKeyFile()
	if !ok {
		return SignedNetworkConfig{}, errors.New("no admin key available on this node")
	}
	seed, err := decryptSeed(akf, password)
	if err != nil {
		return SignedNetworkConfig{}, errWrongPassword
	}
	epoch := time.Now().UnixNano()
	ts := time.Now().Unix()
	sig := adminSignWithSeed(seed, []byte(canonicalNetConfig(name, psk, epoch, ts)))
	zero(seed)

	return SignedNetworkConfig{NetworkName: name, PSK: psk, Epoch: epoch, Ts: ts,
		Sig: base64.StdEncoding.EncodeToString(sig)}, nil
}

// signNetworkPolicy signs a post-quantum on/off policy for a specific node
// (targetPubB64) or the whole network (targetPubB64 == "").
func signNetworkPolicy(password, targetPubB64 string, postQuantum bool) (SignedPolicy, error) {
	adminKeyMu.Lock()
	defer adminKeyMu.Unlock()
	akf, ok := currentAdminKeyFile()
	if !ok {
		return SignedPolicy{}, errors.New("no admin key available on this node")
	}
	seed, err := decryptSeed(akf, password)
	if err != nil {
		return SignedPolicy{}, errWrongPassword
	}
	epoch := time.Now().UnixNano()
	ts := time.Now().Unix()
	sig := adminSignWithSeed(seed, []byte(canonicalPolicy(targetPubB64, postQuantum, epoch, ts)))
	zero(seed)
	return SignedPolicy{PubKey: targetPubB64, PostQuantum: postQuantum, Epoch: epoch, Ts: ts,
		Sig: base64.StdEncoding.EncodeToString(sig)}, nil
}

// bootstrapApprovals is called right after an admin key is created: it approves
// THIS node and every currently-connected peer, so admission control only gates
// devices that connect from now on (existing members aren't suddenly locked out).
func bootstrapApprovals(password string) {
	pubs := map[string]bool{}
	// Our own node key.
	if _, body, err := ctlGet("/api/info"); err == nil {
		var m struct {
			PubKey string `json:"public_key"`
		}
		if json.Unmarshal(body, &m) == nil && m.PubKey != "" {
			pubs[m.PubKey] = true
		}
	}
	// Every current session.
	if _, body, err := ctlGet("/api/sessions"); err == nil {
		var sess []struct {
			PubKey string `json:"pubkey"`
		}
		if json.Unmarshal(body, &sess) == nil {
			for _, s := range sess {
				if s.PubKey != "" {
					pubs[s.PubKey] = true
				}
			}
		}
	}
	for pub := range pubs {
		if rec, err := signApproval(password, pub, "approve"); err == nil {
			if blob, err := json.Marshal(rec); err == nil {
				_, _, _ = ctlPost("/api/approve-signed", blob)
			}
		}
	}
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
