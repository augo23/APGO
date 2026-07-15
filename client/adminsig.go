package main

// adminsig.go is the post-quantum ADMIN SIGNATURE layer (verification side).
//
// The network admin key is an ML-DSA-65 (Dilithium, NIST FIPS 204) signature
// keypair — a post-quantum scheme — so admin-signed actions (revoke, approve,
// assign IP/name, rotate network, set policy) cannot be forged even by a
// quantum-capable attacker. This replaces the earlier classical Ed25519 key.
//
// The trusted admin PUBLIC key is held here as its marshaled bytes (adminPub,
// declared in revocation.go) plus a parsed handle; verification goes through
// adminVerify. The signing side lives in the admin / desktop modules.

import (
	"bytes"

	"github.com/cloudflare/circl/sign"
	mldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// adminSig is the post-quantum signature scheme for the admin key. It MUST be
// identical on every node and in the admin/desktop signers.
var adminSig sign.Scheme = mldsa65.Scheme()

// adminPubParsed is the parsed form of adminPub (kept in sync by setAdminPubBytes).
var adminPubParsed sign.PublicKey

// adminKeySet reports whether this node trusts a network admin public key.
func adminKeySet() bool { return adminPubParsed != nil }

// adminPubValid reports whether raw is a well-formed admin (ML-DSA) public key.
func adminPubValid(raw []byte) bool {
	if len(raw) != adminSig.PublicKeySize() {
		return false
	}
	_, err := adminSig.UnmarshalBinaryPublicKey(raw)
	return err == nil
}

// setAdminPubBytes parses and stores the marshaled admin public key. Returns
// false if raw isn't a valid key (adminPub is left unchanged).
func setAdminPubBytes(raw []byte) bool {
	pk, err := adminSig.UnmarshalBinaryPublicKey(raw)
	if err != nil {
		return false
	}
	adminPub = append([]byte(nil), raw...)
	adminPubParsed = pk
	return true
}

// adminSameKey reports whether raw equals the currently-trusted admin key.
func adminSameKey(raw []byte) bool { return bytes.Equal(raw, adminPub) }

// adminVerify checks an ML-DSA signature over msg against the trusted admin key.
func adminVerify(msg, sig []byte) bool {
	if adminPubParsed == nil {
		return false
	}
	return adminSig.Verify(adminPubParsed, msg, sig, nil)
}
