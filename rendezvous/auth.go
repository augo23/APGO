package main

// auth.go gates the rendezvous API with a shared credential, so a server on the
// public internet is not an open relay for anyone who finds the URL.
//
// Two credential styles, both sent in the standard Authorization header, both
// configured the same way on the client (ONE field, auto-detected):
//
//	Bearer  — AUTH_TOKENS="s3cret,another"          client: "s3cret"
//	Basic   — AUTH_USERS="alice:pw1,bob:pw2"        client: "alice:pw1"
//
// Either may be set; both may be set. If NEITHER is set the server runs open
// (unchanged behaviour for existing deployments) and says so loudly at startup.
//
// What this does and does not protect: the rendezvous only ever exchanges
// endpoints, and overlay membership is gated by the Noise handshake + PSK. So
// auth here is not what keeps strangers out of your network — it keeps
// strangers from USING your server (resource abuse, and enumerating which
// endpoints are announcing). Treat the credential as a service password, not
// as network security, and always run it behind TLS: Basic and Bearer both
// send the secret in the clear otherwise.

import (
	"crypto/subtle"
	"encoding/base64"
	"log"
	"net/http"
	"os"
	"strings"
)

type authConfig struct {
	tokens []string          // accepted bearer tokens
	users  map[string]string // username -> password for Basic
}

func loadAuthConfig() *authConfig {
	ac := &authConfig{users: map[string]string{}}
	for _, t := range strings.Split(os.Getenv("AUTH_TOKENS"), ",") {
		if t = strings.TrimSpace(t); t != "" {
			ac.tokens = append(ac.tokens, t)
		}
	}
	for _, pair := range strings.Split(os.Getenv("AUTH_USERS"), ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		// SplitN so a password may itself contain ':'.
		if u, p, ok := strings.Cut(pair, ":"); ok {
			if u = strings.TrimSpace(u); u != "" && p != "" {
				ac.users[u] = p
			}
		}
	}
	return ac
}

func (a *authConfig) enabled() bool { return len(a.tokens) > 0 || len(a.users) > 0 }

// constantTimeMatch compares without leaking length/content via timing.
func constantTimeMatch(got, want string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// ok reports whether the request carries an accepted credential.
func (a *authConfig) ok(r *http.Request) bool {
	if !a.enabled() {
		return true // open server (no credentials configured)
	}
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if h == "" {
		return false
	}
	scheme, value, found := strings.Cut(h, " ")
	if !found {
		return false
	}
	value = strings.TrimSpace(value)

	switch strings.ToLower(scheme) {
	case "bearer":
		matched := false
		for _, t := range a.tokens {
			// No early break: keep the comparison count independent of which
			// token matched.
			if constantTimeMatch(value, t) {
				matched = true
			}
		}
		return matched
	case "basic":
		raw, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return false
		}
		user, pass, found := strings.Cut(string(raw), ":")
		if !found {
			return false
		}
		want, exists := a.users[user]
		if !exists {
			// Still run a comparison so a wrong USERNAME costs the same time
			// as a wrong password (no user enumeration by timing).
			constantTimeMatch(pass, "\x00nonexistent")
			return false
		}
		return constantTimeMatch(pass, want)
	}
	return false
}

// requireAuth wraps a handler with the credential check. On failure it returns
// 401 with a WWW-Authenticate hint, which is also what tells a client its
// configured credential is wrong (vs. the server being down).
func (a *authConfig) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.ok(r) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="apgo-rendezvous", charset="UTF-8"`)
			http.Error(w, "unauthorized — this rendezvous server requires a credential", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (a *authConfig) logStartupState() {
	switch {
	case len(a.tokens) > 0 && len(a.users) > 0:
		log.Printf("[auth] enabled — %d bearer token(s), %d user(s)", len(a.tokens), len(a.users))
	case len(a.tokens) > 0:
		log.Printf("[auth] enabled — %d bearer token(s)", len(a.tokens))
	case len(a.users) > 0:
		log.Printf("[auth] enabled — %d user(s) (HTTP Basic)", len(a.users))
	default:
		log.Printf("[auth] DISABLED — anyone who knows this URL can announce and " +
			"list endpoints. Set AUTH_TOKENS or AUTH_USERS to require a credential.")
	}
}
