package overlaymobile

// utunwrap.go adapts a raw iOS utun file descriptor to the raw-IP io.ReadWriteCloser
// the overlay core expects.
//
// iOS gives the packet-tunnel extension a utun device, and when you read/write
// that fd directly (as this app does — it scans for the utun fd WireGuard-style
// instead of using NEPacketTunnelFlow), every datagram carries a leading 4-byte
// protocol-family header (AF_INET / AF_INET6, big-endian) — identical to macOS
// utun. The overlay core speaks raw IP packets with no such header, so without
// this adapter the core mis-parses every outbound packet (4 junk bytes before
// the IP header) and writes headerless packets the kernel drops. The result is
// a tunnel that forms sessions (all UDP) but can't move data (ping/HTTP) — which
// is exactly the "shows as a peer but can't reach anything" failure.
//
// Android's VpnService fd delivers raw L3 with NO header, so this wrapper is
// applied ONLY when the app sets utun_header=true (iOS). See Start().

import (
	"encoding/binary"
	"io"
)

// afInet / afInet6 are the BSD address-family values the utun header carries.
// (unix.AF_INET is 2 everywhere; AF_INET6 is 30 on Darwin.)
const (
	afInet  = 2
	afInet6 = 30
)

// utunRW strips the 4-byte AF header on read and prepends it on write.
type utunRW struct {
	inner io.ReadWriteCloser
	rbuf  []byte
}

func newUtunRW(inner io.ReadWriteCloser) *utunRW {
	return &utunRW{inner: inner, rbuf: make([]byte, 65540)}
}

func (u *utunRW) Read(p []byte) (int, error) {
	n, err := u.inner.Read(u.rbuf)
	if err != nil {
		return 0, err
	}
	if n <= 4 {
		return 0, nil // header only / short — nothing to deliver
	}
	return copy(p, u.rbuf[4:n]), nil
}

func (u *utunRW) Write(p []byte) (int, error) {
	af := uint32(afInet)
	if len(p) > 0 && p[0]>>4 == 6 {
		af = afInet6
	}
	buf := make([]byte, 4+len(p))
	binary.BigEndian.PutUint32(buf[:4], af)
	copy(buf[4:], p)
	n, err := u.inner.Write(buf)
	if err != nil {
		return 0, err
	}
	if n >= 4 {
		return n - 4, nil
	}
	return 0, nil
}

func (u *utunRW) Close() error { return u.inner.Close() }
