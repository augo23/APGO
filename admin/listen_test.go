package main

import (
	"net"
	"testing"
	"time"
)

// A port conflict must fail FAST (retrying hides it); a not-yet-present
// address must be waited for. Getting these backwards is how a container
// either crash-loops on a transient race or hangs on a real misconfiguration.
func TestListenWhenAddressAppears(t *testing.T) {
	// Normal case: binds immediately.
	ln, err := listenWhenAddressAppears("127.0.0.1:0", 5*time.Second)
	if err != nil { t.Fatalf("loopback bind should succeed: %v", err) }
	port := ln.Addr().(*net.TCPAddr).Port
	defer ln.Close()

	// Port already in use -> return at once, do NOT sit in the retry loop.
	start := time.Now()
	if _, err := listenWhenAddressAppears(ln.Addr().String(), 10*time.Second); err == nil {
		t.Error("binding an occupied port must fail")
	} else if d := time.Since(start); d > 2*time.Second {
		t.Errorf("occupied port took %v — it must fail fast, not retry", d)
	}
	_ = port

	// Address that does not exist on this host -> retried, then reported.
	start = time.Now()
	if _, err := listenWhenAddressAppears("10.255.255.254:8789", 2*time.Second); err == nil {
		t.Error("a non-existent address must eventually fail")
	} else if d := time.Since(start); d < 1500*time.Millisecond {
		t.Errorf("gave up after %v — it should have waited out the budget", d)
	}
}
