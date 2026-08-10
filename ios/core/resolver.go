package overlaymobile

// resolver.go — DNS for the mobile core while FULL-VPN mode is active.
//
// THE DEADLOCK THIS BREAKS
//
// Full-VPN mode is fail-closed: until an exit is selected, internet-bound
// packets are dropped rather than leaked around the tunnel. To leave that
// state the core must find peers — which needs trackers, STUN or rendezvous,
// all of which are HOSTNAMES.
//
// It is tempting to assume our lookups are safe because a tunnel provider's
// own sockets bypass its own tunnel. They do — but on iOS a name lookup is not
// performed on our socket at all. It is handed to mDNSResponder, a separate
// system process, and mDNSResponder is NOT excluded from the tunnel. Full-VPN
// mode also points system DNS at public resolvers THROUGH the tunnel (to stop
// DNS leaking past the exit). So:
//
//	core -> mDNSResponder -> query -> into our own tunnel -> no exit -> dropped
//	     -> no peers -> no exit -> still no DNS ...
//
// A closed loop that cannot break by itself: the app sits "connected" with no
// peers and no way to find the exit that would fix it.
//
// WHAT THIS DOES
//
// Sets a resolver that uses Go's built-in DNS client (PreferGo) with our own
// Dial. That query travels on a socket THIS process opened, which genuinely
// does bypass the tunnel, so it works while the tunnel is up but exitless.
//
// Two lessons are baked in from an earlier, worse version of this file:
//
//   - It carries IPv4 AND IPv6 resolvers. The first attempt hardcoded IPv4
//     only, which breaks completely on IPv6-only mobile carriers (most of
//     them now) — no IPv4 connectivity means 1.1.1.1 is unreachable and every
//     lookup fails. Both families are tried, so whichever the network has
//     works.
//   - It is armed ONLY while full-VPN mode is on. With no tunnel-wide capture
//     there is no deadlock to break, and the stock resolver is better: it
//     honours the network's own DNS (split-horizon names, enterprise
//     resolvers, Pi-hole) instead of overriding it globally.

import (
	"context"
	"net"
	"time"
)

// bootstrapResolvers are queried in order. Public, well-known, and reachable
// over either address family — the point is only to break the chicken-and-egg,
// not to be anyone's permanent DNS.
var bootstrapResolvers = []string{
	"1.1.1.1:53",                  // Cloudflare v4
	"8.8.8.8:53",                  // Google v4
	"[2606:4700:4700::1111]:53",   // Cloudflare v6
	"[2001:4860:4860::8888]:53",   // Google v6
	"9.9.9.9:53",                  // Quad9 v4
}

// setupBootstrapResolver installs the tunnel-bypassing resolver. Call it only
// when full-VPN mode is enabled; it is a no-op otherwise so ordinary
// operation keeps the system resolver untouched.
func setupBootstrapResolver(fullVPN bool) {
	if !fullVPN {
		return
	}
	net.DefaultResolver = &net.Resolver{
		// PreferGo forces Go's own DNS client, so the query goes out on the
		// socket our Dial creates — the whole point. With cgo/getaddrinfo it
		// would go to mDNSResponder and back into the tunnel.
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			var firstErr error
			for _, s := range bootstrapResolvers {
				// Skip a v6 server on a v4-only network and vice versa —
				// dialling it would just burn the caller's timeout budget.
				if isIPv6Server(s) && !hasGlobalIPv6() {
					continue
				}
				c, err := d.DialContext(ctx, network, s)
				if err == nil {
					return c, nil
				}
				if firstErr == nil {
					firstErr = err
				}
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
			}
			if firstErr == nil {
				firstErr = &net.DNSError{Err: "no bootstrap resolver reachable", IsTemporary: true}
			}
			return nil, firstErr
		},
	}
}

// isIPv6Server reports whether a "host:port" string names an IPv6 literal.
func isIPv6Server(s string) bool {
	h, _, err := net.SplitHostPort(s)
	if err != nil {
		return false
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.To4() == nil
}
