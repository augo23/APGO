package main

// socks5.go exposes the overlay through a local SOCKS5 proxy (RFC 1928).
//
// WHY
//
// Every existing way onto this overlay needs a TUN device, which needs root or
// Administrator, kernel driver support, and per-platform route surgery -- 17
// files of it. That rules out the cases where a proxy is the natural fit:
// an unprivileged process, a container without NET_ADMIN, a locked-down
// laptop, or simply "send THIS browser through the overlay and nothing else".
// A SOCKS5 listener needs none of that.
//
// It is also per-application rather than all-or-nothing. Full-VPN mode today
// captures the default route, so everything on the machine goes through an exit
// node. A proxy is opt-in per client.
//
// WHAT THIS FILE DOES AND DOES NOT DO
//
// This is the PROTOCOL layer only, and it dials through a pluggable
// socksDialer. With the TUN up, the default dialer is the ordinary kernel
// dialer: the route to 10.22.22.0/24 already exists, so a connection to an
// overlay address just works, and the value here is per-app selection and
// remote DNS. TUN-less operation is a second dialer (a userspace TCP/IP stack)
// that slots in behind the same interface -- deliberately separated, because
// the protocol layer is simple and testable while the netstack layer is not.
//
// SECURITY
//
// A SOCKS5 proxy is an open door into whatever it can reach. This one binds
// 127.0.0.1 by default and REFUSES to bind a non-loopback address without a
// username and password, because an unauthenticated proxy on 0.0.0.0 is an
// open relay for the whole overlay -- exactly the thing admission control
// exists to prevent, handed out on a TCP port.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// socksDialer is how the proxy reaches a destination. Swapping it is what makes
// TUN-less mode possible without touching any of the protocol code below.
type socksDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type socks5Server struct {
	ln       net.Listener
	dialer   socksDialer
	user     string
	pass     string
	overlay  *net.IPNet // when set, only destinations INSIDE the overlay are allowed
	onlyOvl  bool
	conns    atomic.Int64
	total    atomic.Uint64
	rejected atomic.Uint64
	mu       sync.Mutex
	closed   bool
}

var gSocks5 *socks5Server

// SOCKS5 wire constants.
const (
	socks5Ver      = 0x05
	sAuthNone      = 0x00
	sAuthUserPass  = 0x02
	sAuthNoAccept  = 0xFF
	sCmdConnect    = 0x01
	sAtypIPv4      = 0x01
	sAtypDomain    = 0x03
	sAtypIPv6      = 0x04
	sRepOK         = 0x00
	sRepGeneralErr = 0x01
	sRepNotAllowed = 0x02
	sRepHostUnreach = 0x04
	sRepCmdNotSup  = 0x07
	sRepAtypNotSup = 0x08
)

// startSocks5 binds the proxy. Returns nil (and logs) when disabled, so the
// caller does not have to branch.
func startSocks5(cfg *ClientConfig) *socks5Server {
	addr := cfg.Socks5Listen
	if addr == "" {
		return nil
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		log.Printf("[socks5] invalid socks5_listen %q: %v — proxy NOT started", addr, err)
		return nil
	}
	// Refuse an unauthenticated proxy on anything but loopback. This is not
	// paranoia: a SOCKS5 port reachable from the LAN lets anyone on that LAN
	// dial any overlay address through this node, bypassing admission control
	// entirely -- they never join the mesh, they just use this node as a door.
	if !isLoopbackHost(host) && (cfg.Socks5User == "" || cfg.Socks5Pass == "") {
		log.Printf("[socks5] REFUSING to listen on %s without a username and password. "+
			"An unauthenticated proxy off loopback is an open door into the overlay for "+
			"anyone who can reach this port. Set socks5_user/socks5_pass, or bind 127.0.0.1.", addr)
		return nil
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[socks5] listen %s: %v — proxy NOT started", addr, err)
		return nil
	}
	s := &socks5Server{
		ln:      ln,
		dialer:  &net.Dialer{Timeout: 10 * time.Second},
		user:    cfg.Socks5User,
		pass:    cfg.Socks5Pass,
		onlyOvl: cfg.Socks5OverlayOnly,
	}
	if _, n, err := net.ParseCIDR(cfg.OverlayCIDR); err == nil {
		s.overlay = n
	}
	gSocks5 = s

	auth := "no auth (loopback only)"
	if s.user != "" {
		auth = "username/password"
	}
	scope := "any destination"
	if s.onlyOvl {
		scope = "overlay addresses only"
	}
	log.Printf("[socks5] listening on %s — %s, %s", addr, auth, scope)
	go s.serve()
	return s
}

func isLoopbackHost(h string) bool {
	if h == "" {
		return false // an empty host means "all interfaces"
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return h == "localhost"
}

func (s *socks5Server) Close() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	if s.ln != nil {
		_ = s.ln.Close()
	}
}

func (s *socks5Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *socks5Server) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			if s.isClosed() {
				return
			}
			// A transient accept error must not kill the listener: that would
			// leave the proxy silently dead until a restart, with the port
			// still looking bound to anyone testing it.
			log.Printf("[socks5] accept: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go s.handle(c)
	}
}

func (s *socks5Server) handle(c net.Conn) {
	s.conns.Add(1)
	defer func() {
		s.conns.Add(-1)
		_ = c.Close()
	}()

	// A client that connects and then says nothing must not hold a goroutine
	// and an fd forever. The deadline covers the whole negotiation; it is
	// cleared before the relay loop, which has its own idle behaviour.
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))

	if err := s.negotiateAuth(c); err != nil {
		s.rejected.Add(1)
		return
	}
	dstHost, dstPort, err := s.readRequest(c)
	if err != nil {
		s.rejected.Add(1)
		return
	}

	target := net.JoinHostPort(dstHost, strconv.Itoa(int(dstPort)))

	// Scope check, when the operator restricted the proxy to the overlay.
	// Done AFTER parsing so the client gets a proper SOCKS reply rather than a
	// dropped connection it cannot interpret.
	if s.onlyOvl && !s.destInOverlay(dstHost) {
		_ = s.reply(c, sRepNotAllowed, nil)
		s.rejected.Add(1)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	remote, err := s.dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		// Map the failure to a SOCKS reply code. Clients surface these
		// distinctly ("host unreachable" vs "connection refused"), and
		// collapsing everything to a generic error is what makes a proxy
		// undebuggable from the client side.
		code := byte(sRepGeneralErr)
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			code = sRepHostUnreach
		}
		_ = s.reply(c, code, nil)
		s.rejected.Add(1)
		return
	}
	defer remote.Close()

	// BND.ADDR/BND.PORT: the address the proxy used toward the target. Most
	// clients ignore it, but some validate that it parses.
	var bound net.Addr = remote.LocalAddr()
	if err := s.reply(c, sRepOK, bound); err != nil {
		return
	}

	s.total.Add(1)
	_ = c.SetDeadline(time.Time{}) // negotiation done; let the streams run
	relayStreams(c, remote)
}

// negotiateAuth performs the SOCKS5 greeting and, when configured, RFC 1929
// username/password authentication.
func (s *socks5Server) negotiateAuth(c net.Conn) error {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return err
	}
	if hdr[0] != socks5Ver {
		// SOCKS4 and HTTP proxies both land here when someone points the wrong
		// client at this port. Nothing useful to reply with in their dialect.
		return fmt.Errorf("unsupported version %d", hdr[0])
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}

	want := byte(sAuthNone)
	if s.user != "" {
		want = sAuthUserPass
	}
	ok := false
	for _, m := range methods {
		if m == want {
			ok = true
			break
		}
	}
	if !ok {
		_, _ = c.Write([]byte{socks5Ver, sAuthNoAccept})
		return errors.New("no acceptable auth method")
	}
	if _, err := c.Write([]byte{socks5Ver, want}); err != nil {
		return err
	}
	if want == sAuthNone {
		return nil
	}

	// RFC 1929: VER(1) ULEN(1) UNAME ULEN PLEN(1) PASSWD
	vb := make([]byte, 1)
	if _, err := io.ReadFull(c, vb); err != nil {
		return err
	}
	if vb[0] != 0x01 {
		return errors.New("bad auth subnegotiation version")
	}
	readStr := func() (string, error) {
		lb := make([]byte, 1)
		if _, err := io.ReadFull(c, lb); err != nil {
			return "", err
		}
		b := make([]byte, int(lb[0]))
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		return string(b), nil
	}
	u, err := readStr()
	if err != nil {
		return err
	}
	p, err := readStr()
	if err != nil {
		return err
	}
	// Constant-time-ish comparison: compare both halves regardless of the
	// first result, so a wrong username and a wrong password cost the same.
	okUser := subtleEqual(u, s.user)
	okPass := subtleEqual(p, s.pass)
	if !okUser || !okPass {
		_, _ = c.Write([]byte{0x01, 0x01}) // failure
		return errors.New("bad credentials")
	}
	_, err = c.Write([]byte{0x01, 0x00}) // success
	return err
}

// subtleEqual compares without early exit on length or content.
func subtleEqual(a, b string) bool {
	if len(a) != len(b) {
		// Still touch the data so a length mismatch is not measurably faster
		// than a content mismatch.
		var v byte
		for i := 0; i < len(a); i++ {
			v |= a[i]
		}
		_ = v
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// readRequest parses the CONNECT request and returns host and port.
func (s *socks5Server) readRequest(c net.Conn) (string, uint16, error) {
	hdr := make([]byte, 4) // VER CMD RSV ATYP
	if _, err := io.ReadFull(c, hdr); err != nil {
		return "", 0, err
	}
	if hdr[0] != socks5Ver {
		return "", 0, errors.New("bad version in request")
	}
	if hdr[1] != sCmdConnect {
		// BIND and UDP ASSOCIATE are not implemented. Answered properly rather
		// than by hanging up, so a client that asked for UDP (a DNS resolver,
		// say) reports "command not supported" instead of a mystery failure.
		_ = s.reply(c, sRepCmdNotSup, nil)
		return "", 0, errors.New("unsupported command")
	}

	var host string
	switch hdr[3] {
	case sAtypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", 0, err
		}
		host = net.IP(b).String()
	case sAtypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", 0, err
		}
		host = net.IP(b).String()
	case sAtypDomain:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(c, lb); err != nil {
			return "", 0, err
		}
		b := make([]byte, int(lb[0]))
		if _, err := io.ReadFull(c, b); err != nil {
			return "", 0, err
		}
		// A DOMAIN request means the client did NOT resolve locally
		// (socks5h). That is the desirable case: the name is resolved on this
		// side, so overlay hostnames work and the client leaks no DNS.
		host = string(b)
	default:
		_ = s.reply(c, sRepAtypNotSup, nil)
		return "", 0, errors.New("unsupported address type")
	}

	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return "", 0, err
	}
	return host, binary.BigEndian.Uint16(pb), nil
}

// reply writes a SOCKS5 response. A nil addr sends 0.0.0.0:0, which is legal
// and what most implementations send on failure.
func (s *socks5Server) reply(c net.Conn, code byte, addr net.Addr) error {
	out := []byte{socks5Ver, code, 0x00, sAtypIPv4, 0, 0, 0, 0, 0, 0}
	if ta, ok := addr.(*net.TCPAddr); ok && ta != nil {
		if ip4 := ta.IP.To4(); ip4 != nil {
			copy(out[4:8], ip4)
			binary.BigEndian.PutUint16(out[8:10], uint16(ta.Port))
		}
	}
	_, err := c.Write(out)
	return err
}

// destInOverlay reports whether a destination falls inside the overlay subnet.
// A hostname is NOT resolved here: resolving to decide policy would mean a
// DNS answer could steer the check, so a name is simply not treated as an
// overlay address in overlay-only mode.
func (s *socks5Server) destInOverlay(host string) bool {
	if s.overlay == nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return s.overlay.Contains(ip)
}

// relayStreams copies in both directions and returns once either side is done.
//
// Half-close matters: when the client stops sending, the target must see EOF
// rather than a live-but-silent socket, or protocols that end with a
// half-close (plain HTTP/1.0 responses, some shells) hang until a timeout.
func relayStreams(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.SetReadDeadline(time.Now())
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}

// socks5Status is the dashboard/API view.
func socks5Status() map[string]any {
	s := gSocks5
	if s == nil {
		return map[string]any{"enabled": false}
	}
	return map[string]any{
		"enabled":       true,
		"listen":        s.ln.Addr().String(),
		"auth":          s.user != "",
		"overlay_only":  s.onlyOvl,
		"open_conns":    s.conns.Load(),
		"total_conns":   s.total.Load(),
		"rejected":      s.rejected.Load(),
	}
}

// --- live reconfiguration ---------------------------------------------------

// socks5Cfg is the live proxy configuration, kept so a partial admin change
// (say, only the password) does not reset the fields it did not mention.
var (
	socks5Mu  sync.Mutex
	socks5Cur ClientConfig
)

// applySocks5Config restarts the proxy under a new admin-signed configuration.
// Returns true when something actually changed.
//
// A restart rather than an in-place edit: the listen address and the auth
// requirement are both decided at bind time, and re-deriving them on a live
// listener is how a proxy ends up bound to an address under rules that no
// longer apply.
func applySocks5Config(c SignedNodeConfig) bool {
	socks5Mu.Lock()
	defer socks5Mu.Unlock()

	next := socks5Cur
	dirty := false
	if c.Socks5Listen != nil && *c.Socks5Listen != next.Socks5Listen {
		next.Socks5Listen, dirty = *c.Socks5Listen, true
	}
	if c.Socks5User != nil && *c.Socks5User != next.Socks5User {
		next.Socks5User, dirty = *c.Socks5User, true
	}
	if c.Socks5Pass != nil && *c.Socks5Pass != next.Socks5Pass {
		next.Socks5Pass, dirty = *c.Socks5Pass, true
	}
	if c.Socks5OverlayOnly != nil && *c.Socks5OverlayOnly != next.Socks5OverlayOnly {
		next.Socks5OverlayOnly, dirty = *c.Socks5OverlayOnly, true
	}
	if !dirty {
		return false
	}

	if gSocks5 != nil {
		gSocks5.Close()
		gSocks5 = nil
	}
	socks5Cur = next
	if next.Socks5Listen != "" {
		// startSocks5 does its own validation and refuses an unauthenticated
		// non-loopback bind. A signed record is not a reason to skip that:
		// the door it opens is the same door either way.
		startSocks5(&next)
	} else {
		log.Printf("[socks5] proxy disabled by admin")
	}
	return true
}

// rememberSocks5Config records the startup configuration so later partial
// updates merge against it rather than against zero values.
func rememberSocks5Config(cfg *ClientConfig) {
	socks5Mu.Lock()
	socks5Cur.Socks5Listen = cfg.Socks5Listen
	socks5Cur.Socks5User = cfg.Socks5User
	socks5Cur.Socks5Pass = cfg.Socks5Pass
	socks5Cur.Socks5OverlayOnly = cfg.Socks5OverlayOnly
	socks5Mu.Unlock()
}

// socks5ListenDesc is a short description for the change log.
func socks5ListenDesc() string {
	socks5Mu.Lock()
	defer socks5Mu.Unlock()
	if socks5Cur.Socks5Listen == "" {
		return "off"
	}
	return socks5Cur.Socks5Listen
}
