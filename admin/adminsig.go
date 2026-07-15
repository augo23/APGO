package main

// adminsig.go is the post-quantum ADMIN SIGNATURE layer (signing side).
//
// The network admin key is an ML-DSA-65 (Dilithium, NIST FIPS 204) keypair, so
// admin-signed actions are unforgeable even by a quantum-capable attacker. The
// 32-byte seed is what's encrypted at rest (PBKDF2 + AES-256-GCM) and
// distributed; the keypair is derived deterministically from it. Must match the
// verifier scheme in the client core exactly.

import (
	"github.com/cloudflare/circl/sign"
	mldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

var adminSig sign.Scheme = mldsa65.Scheme()

// adminSignSeedSize is the length of the seed we generate + encrypt at rest.
func adminSignSeedSize() int { return adminSig.SeedSize() }

// adminPubFromSeed returns the marshaled public key for a seed.
func adminPubFromSeed(seed []byte) ([]byte, error) {
	pk, _ := adminSig.DeriveKey(seed)
	return pk.MarshalBinary()
}

// adminSignWithSeed derives the private key from seed and signs msg (ML-DSA).
func adminSignWithSeed(seed, msg []byte) []byte {
	_, sk := adminSig.DeriveKey(seed)
	return adminSig.Sign(sk, msg, nil)
}
