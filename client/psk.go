package main

// psk.go holds the shared pre-shared-key generator, used by the web setup flow
// and the admin UI "Generate PSK" button (/api/gen-psk). Kept in its own file so
// it is available to both the client and the gomobile core.

import (
	"crypto/rand"
	"encoding/base64"
)

// generatePSK returns a fresh random pre-shared key in the "base64:<32 bytes>"
// format the client expects.
func generatePSK() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// A CSPRNG failure must never silently yield an all-zero network
		// membership secret. Nothing on this system is trustworthy anymore;
		// fail loudly instead of minting a guessable PSK.
		panic("crypto/rand failure while generating a PSK: " + err.Error())
	}
	return "base64:" + base64.StdEncoding.EncodeToString(b)
}
