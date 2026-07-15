package main

// creds.go stores the local admin-panel login (username + salted PBKDF2 hash)
// in ~/.apgo/webui-credentials.json. There is no environment bootstrap on the
// Mac: on first use the panel prompts you to create the account.

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
)

type webCreds struct {
	Username string `json:"username"`
	Salt     string `json:"salt"`
	Hash     string `json:"hash"`
	Iter     int    `json:"iter"`
}

func credsPath() string { return filepath.Join(appDir(), "webui-credentials.json") }

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

func (c webCreds) matches(username, pw string) bool {
	salt, _ := base64.StdEncoding.DecodeString(c.Salt)
	got := hashPw(pw, salt, c.Iter)
	return subtle.ConstantTimeCompare([]byte(username), []byte(c.Username)) == 1 &&
		subtle.ConstantTimeCompare([]byte(got), []byte(c.Hash)) == 1
}

func verifyCurrentPassword(pw string) bool {
	c, ok := loadCreds()
	if !ok {
		return false
	}
	salt, _ := base64.StdEncoding.DecodeString(c.Salt)
	return subtle.ConstantTimeCompare([]byte(hashPw(pw, salt, c.Iter)), []byte(c.Hash)) == 1
}

func currentUsername() string {
	if c, ok := loadCreds(); ok {
		return c.Username
	}
	return ""
}
