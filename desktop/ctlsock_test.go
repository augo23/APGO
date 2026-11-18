package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMain points every test at a socket path nothing listens on, so a test
// that forgets isolateControlSocket still cannot reach the real client.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "apgo")
	if err == nil {
		testControlSocket = filepath.Join(dir, "none.sock")
	}
	code := m.Run()
	if dir != "" {
		_ = os.RemoveAll(dir)
	}
	os.Exit(code)
}

// isolateControlSocket points controlSocket() at a fresh, private path for the
// duration of the test, so nothing reaches (or removes) a real client's socket.
// The directory is short on purpose: unix socket paths are limited to ~104
// bytes on macOS, and t.TempDir() paths there can exceed that.
func isolateControlSocket(t *testing.T) {
	t.Helper()
	dir, err := os.MkdirTemp("", "apgo")
	if err != nil {
		t.Fatal(err)
	}
	prev := testControlSocket
	testControlSocket = filepath.Join(dir, "c.sock")
	t.Cleanup(func() { testControlSocket = prev; _ = os.RemoveAll(dir) })
}
