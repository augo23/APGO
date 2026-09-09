package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// fakeDialer returns a pipe endpoint, so the proxy can be exercised with no
// network at all.
type fakeDialer struct {
	target string
	err    error
	srv    net.Conn
}

func (f *fakeDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	f.target = address
	if f.err != nil {
		return nil, f.err
	}
	c, s := net.Pipe()
	f.srv = s
	return c, nil
}

func newTestServer(t *testing.T, user, pass string, overlayOnly bool) (*socks5Server, *fakeDialer, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	fd := &fakeDialer{}
	s := &socks5Server{ln: ln, dialer: fd, user: user, pass: pass, onlyOvl: overlayOnly}
	_, n, _ := net.ParseCIDR("10.22.22.0/24")
	s.overlay = n
	go s.serve()
	t.Cleanup(s.Close)
	return s, fd, ln.Addr().String()
}

func greet(t *testing.T, c net.Conn, method byte) {
	t.Helper()
	if _, err := c.Write([]byte{socks5Ver, 1, method}); err != nil {
		t.Fatalf("greet: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatalf("greet reply: %v", err)
	}
	if resp[0] != socks5Ver {
		t.Fatalf("bad version in greeting reply: %d", resp[0])
	}
}

func connectReq(host string, port uint16) []byte {
	out := []byte{socks5Ver, sCmdConnect, 0x00, sAtypDomain, byte(len(host))}
	out = append(out, host...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], port)
	return append(out, pb[:]...)
}

func TestSocks5ConnectPassesTargetThrough(t *testing.T) {
	_, fd, addr := newTestServer(t, "", "", false)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	greet(t, c, sAuthNone)
	if _, err := c.Write(connectReq("example.internal", 8080)); err != nil {
		t.Fatalf("request: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("reply: %v", err)
	}
	if reply[1] != sRepOK {
		t.Fatalf("reply code = %d, want success", reply[1])
	}
	// The DOMAIN form must reach the dialer UNRESOLVED. That is the whole
	// point of remote DNS: resolving here is what makes overlay hostnames work
	// and stops the client leaking names.
	if fd.target != "example.internal:8080" {
		t.Errorf("dialer target = %q, want %q", fd.target, "example.internal:8080")
	}
}

func TestSocks5RejectsWrongPassword(t *testing.T) {
	_, _, addr := newTestServer(t, "u", "correct", false)
	c, _ := net.Dial("tcp", addr)
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	greet(t, c, sAuthUserPass)
	req := []byte{0x01, 1, 'u', 5, 'w', 'r', 'o', 'n', 'g'}
	if _, err := c.Write(req); err != nil {
		t.Fatalf("auth: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatalf("auth reply: %v", err)
	}
	if resp[1] == 0x00 {
		t.Error("wrong password was ACCEPTED")
	}
}

func TestSocks5AcceptsRightPassword(t *testing.T) {
	_, _, addr := newTestServer(t, "u", "correct", false)
	c, _ := net.Dial("tcp", addr)
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	greet(t, c, sAuthUserPass)
	if _, err := c.Write([]byte{0x01, 1, 'u', 7, 'c', 'o', 'r', 'r', 'e', 'c', 't'}); err != nil {
		t.Fatalf("auth: %v", err)
	}
	resp := make([]byte, 2)
	io.ReadFull(c, resp)
	if resp[1] != 0x00 {
		t.Fatalf("correct password rejected (code %d)", resp[1])
	}
}

// Auth must be REQUIRED when configured: offering "no auth" cannot be a way
// around the password.
func TestSocks5NoAuthRefusedWhenPasswordSet(t *testing.T) {
	_, _, addr := newTestServer(t, "u", "p", false)
	c, _ := net.Dial("tcp", addr)
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := c.Write([]byte{socks5Ver, 1, sAuthNone}); err != nil {
		t.Fatalf("greet: %v", err)
	}
	resp := make([]byte, 2)
	io.ReadFull(c, resp)
	if resp[1] != sAuthNoAccept {
		t.Errorf("server accepted method %d when a password is configured", resp[1])
	}
}

func TestSocks5OverlayOnlyBlocksOutsideDestinations(t *testing.T) {
	_, _, addr := newTestServer(t, "", "", true)
	c, _ := net.Dial("tcp", addr)
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	greet(t, c, sAuthNone)
	// An IPv4 request for a public address.
	req := []byte{socks5Ver, sCmdConnect, 0x00, sAtypIPv4, 1, 1, 1, 1, 0x01, 0xbb}
	c.Write(req)
	reply := make([]byte, 10)
	io.ReadFull(c, reply)
	if reply[1] != sRepNotAllowed {
		t.Errorf("public destination allowed in overlay-only mode (code %d)", reply[1])
	}
}

func TestSocks5OverlayOnlyAllowsOverlayDestinations(t *testing.T) {
	_, fd, addr := newTestServer(t, "", "", true)
	c, _ := net.Dial("tcp", addr)
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	greet(t, c, sAuthNone)
	req := []byte{socks5Ver, sCmdConnect, 0x00, sAtypIPv4, 10, 22, 22, 22, 0x00, 0x50}
	c.Write(req)
	reply := make([]byte, 10)
	io.ReadFull(c, reply)
	if reply[1] != sRepOK {
		t.Fatalf("overlay destination refused (code %d)", reply[1])
	}
	if fd.target != "10.22.22.22:80" {
		t.Errorf("target = %q, want 10.22.22.22:80", fd.target)
	}
}

// BIND / UDP ASSOCIATE must be answered, not hung up on -- a client that asked
// for UDP should see "command not supported", not a dead socket.
func TestSocks5UnsupportedCommandIsAnswered(t *testing.T) {
	_, _, addr := newTestServer(t, "", "", false)
	c, _ := net.Dial("tcp", addr)
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	greet(t, c, sAuthNone)
	c.Write([]byte{socks5Ver, 0x03 /* UDP ASSOCIATE */, 0x00, sAtypIPv4, 0, 0, 0, 0, 0, 0})
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("no reply to unsupported command: %v", err)
	}
	if reply[1] != sRepCmdNotSup {
		t.Errorf("reply code = %d, want command-not-supported", reply[1])
	}
}

func TestSubtleEqual(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"", "", true},
		{"abc", "abc", true},
		{"abc", "abd", false},
		{"abc", "ab", false},
		{"", "x", false},
	}
	for _, c := range cases {
		if got := subtleEqual(c.a, c.b); got != c.want {
			t.Errorf("subtleEqual(%q,%q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestIsLoopbackHost(t *testing.T) {
	for _, c := range []struct {
		h    string
		want bool
	}{
		{"127.0.0.1", true}, {"::1", true}, {"localhost", true},
		{"0.0.0.0", false}, {"192.168.1.5", false}, {"", false},
	} {
		if got := isLoopbackHost(c.h); got != c.want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", c.h, got, c.want)
		}
	}
}
