package main

import (
	"encoding/base64"
	"testing"
)

// The client verifies this exact string (client/adminpin.go canonicalSealedBlob).
func TestCanonicalSealedBlobMatchesClient(t *testing.T) {
	akf := adminKeyFile{Version: 1, PublicKey: "PK", Salt: "S", Iter: 600000, Nonce: "N", Sealed: "C", Seq: 99, Epoch: 42}
	if got, want := canonicalSealedBlob(akf), "OVLYSEALED1|1|PK|S|600000|N|C|42"; got != want {
		t.Fatalf("canonicalSealedBlob = %q, want %q", got, want)
	}
}

func TestSignSealedBlobVerifies(t *testing.T) {
	seed := make([]byte, adminSignSeedSize())
	for i := range seed {
		seed[i] = byte(i)
	}
	pubBytes, err := adminPubFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	akf := adminKeyFile{Version: 1, PublicKey: base64.StdEncoding.EncodeToString(pubBytes), Salt: "S", Iter: 1, Nonce: "N", Sealed: "C", Epoch: 7}
	signSealedBlob(&akf, seed)
	sig, _ := base64.StdEncoding.DecodeString(akf.Sig)
	pk, _ := adminSig.UnmarshalBinaryPublicKey(pubBytes)
	if !adminSig.Verify(pk, []byte(canonicalSealedBlob(akf)), sig, nil) {
		t.Fatal("sealed blob signature does not verify")
	}
	akf.Epoch++
	if adminSig.Verify(pk, []byte(canonicalSealedBlob(akf)), sig, nil) {
		t.Fatal("signature still verifies after changing the epoch")
	}
	if fp := adminKeyFingerprintB64(akf.PublicKey); len(fp) != len("sha256:")+43 {
		t.Fatalf("fingerprint %q has the wrong shape", fp)
	}
}
