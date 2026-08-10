package main

// creds.go stores the dashboard login (username + salted PBKDF2 password hash)
// in a file so it can be changed from the web UI and survive restarts. If no
// file exists yet, login falls back to the ADMIN_USER/ADMIN_PASSWORD bootstrap
// credentials from the environment (compose).

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"os"
)

type webCreds struct {
	Username string `json:"username"`
	Salt     string `json:"salt"`
	Hash     string `json:"hash"`
	Iter     int    `json:"iter"`
}

func credsPath() string { return env("ADMIN_CREDS_FILE", "/adminkey/credentials.json") }

func hashPw(pw string, salt []byte, iter int) string {
	if iter <= 0 {
		iter = pbkdfIter
	}
	return base64.StdEncoding.EncodeToString(pbkdf2SHA256([]byte(pw), salt, iter, 32))
}

func newCreds(username, pw string) (webCreds, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return webCreds{}, err
	}
	return webCreds{
		Username: username,
		Salt:     base64.StdEncoding.EncodeToString(salt),
		Hash:     hashPw(pw, salt, pbkdfIter),
		Iter:     pbkdfIter,
	}, nil
}

func loadCreds() (webCreds, bool) {
	data, err := os.ReadFile(credsPath())
	if err != nil {
		return webCreds{}, false
	}
	var c webCreds
	if json.Unmarshal(data, &c) != nil || c.Username == "" {
		return webCreds{}, false
	}
	return c, true
}

func saveCreds(c webCreds) error {
	data, _ := json.MarshalIndent(c, "", "  ")
	tmp := credsPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, credsPath())
}

func credsConfigured() bool {
	_, ok := loadCreds()
	return ok
}

// mustSetup is true when there is no real login yet (no saved creds and no env
// password). While true, /setup is open (unauthenticated) so the operator can
// create the login on first visit — the page disappears the moment credentials
// are saved.
func mustSetup() bool { return !credsConfigured() && adminPass == "" }

func (c webCreds) matches(username, pw string) bool {
	salt, _ := base64.StdEncoding.DecodeString(c.Salt)
	got := hashPw(pw, salt, c.Iter)
	return subtle.ConstantTimeCompare([]byte(username), []byte(c.Username)) == 1 &&
		subtle.ConstantTimeCompare([]byte(got), []byte(c.Hash)) == 1
}

// checkLogin verifies a username+password against the stored creds file, or the
// env (compose) credentials if none has been set yet.
func checkLogin(username, pw string) bool {
	if c, ok := loadCreds(); ok {
		return c.matches(username, pw)
	}
	if adminPass != "" {
		return subtle.ConstantTimeCompare([]byte(username), []byte(adminUser)) == 1 &&
			subtle.ConstantTimeCompare([]byte(pw), []byte(adminPass)) == 1
	}
	return false
}

// verifyCurrentPassword checks just the password (for the change-password flow)
// against the active creds (file or env).
func verifyCurrentPassword(pw string) bool {
	if c, ok := loadCreds(); ok {
		salt, _ := base64.StdEncoding.DecodeString(c.Salt)
		return subtle.ConstantTimeCompare([]byte(hashPw(pw, salt, c.Iter)), []byte(c.Hash)) == 1
	}
	return adminPass != "" && subtle.ConstantTimeCompare([]byte(pw), []byte(adminPass)) == 1
}

func currentUsername() string {
	if c, ok := loadCreds(); ok {
		return c.Username
	}
	return adminUser
}
