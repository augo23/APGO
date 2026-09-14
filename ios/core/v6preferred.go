package overlaymobile

// v6preferred.go — advertising only the IPv6 addresses that still work.
//
// THE PROBLEM, FROM A REAL CANDIDATE LIST
//
// A phone that had been on cellular for hours was still advertising this:
//
//	candidates: 10.3.49.47:58186, 10.0.0.204:58186,
//	            [2600:381:9681:bbb7:cc6:7408:f774:aac]:58186,
//	            [2600:381:9681:bbb7:8c9b:2893:f23:ccda]:58186,
//	            [2600:381:9681:bbb7:5d8b:1b3:3a3a:d198]:58186,
//	            [2600:381:9681:bbb7:d9ac:3a9b:e7fc:2c55]:58186,
//	            107.122.246.1:26912
//
// Four addresses out of one /64 belonging to a Wi-Fi network it had left, and
// exactly one candidate that could possibly work. iOS keeps DEPRECATED
// temporary addresses (RFC 4941 privacy addresses, plus the SLAAC address)
// on the interface after the prefix goes away, and net.Interfaces() reports
// every one of them with no flag to say which are still valid — Go does not
// surface IFA_F_DEPRECATED at all.
//
// So maxV6Candidates, meant to cover "Ethernet and Wi-Fi each with a SLAAC
// and a privacy address", was instead spent entirely on four ghosts of a
// single dead interface. Every peer receiving that list punched all four.
//
// THE FIX: ASK THE KERNEL WHICH SOURCE IT WOULD USE
//
// A connected UDP socket performs a route lookup and source-address selection
// WITHOUT sending a packet. The address the kernel picks is by definition the
// one it considers preferred and routable right now — RFC 6724 source
// selection already excludes deprecated addresses. One socket open and close
// answers the question that the interface list cannot.
//
// The result orders the candidate list: the kernel's chosen source first,
// then other addresses that share its interface, then everything else. When
// the probe fails (no v6 route at all) the list is returned unchanged, since
// having no preference is not a reason to discard addresses.
//
// This is ordering, not filtering. A deprecated address is not always dead —
// a network can come back — and the budget still admits a few. What changes
// is that the address most likely to work is now tried FIRST instead of
// sitting behind three ghosts.

import (
	"net"
	"sync"
	"time"
)

// v6ProbeDest is a well-known public IPv6 address used only as the target of
// a route lookup. Nothing is ever sent to it: net.Dial on a UDP socket
// resolves the route and binds a source address, and we read that source
// address and close. Chosen because it is a stable, globally-routed anycast
// address (Google Public DNS) that every v6-capable network can route toward.
const v6ProbeDest = "[2001:4860:4860::8888]:53"

// v6PreferredCacheTTL bounds how often the probe runs. Source selection only
// changes when the network does, and the candidate list is rebuilt on every
// connect signal, so caching turns a per-punch syscall into a per-minute one.
const v6PreferredCacheTTL = 30 * time.Second

var (
	v6PrefMu   sync.Mutex
	v6PrefAt   time.Time
	v6PrefAddr string // the source address the kernel picks, "" if none
	v6PrefIf   string // the interface that address sits on
)

// preferredV6Source returns the IPv6 source address the OS would use for
// off-link traffic right now, and the interface carrying it. Both are "" when
// this host has no usable IPv6 route.
func preferredV6Source() (addr string, ifname string) {
	v6PrefMu.Lock()
	defer v6PrefMu.Unlock()
	if time.Since(v6PrefAt) < v6PreferredCacheTTL {
		return v6PrefAddr, v6PrefIf
	}
	v6PrefAt = time.Now()
	v6PrefAddr, v6PrefIf = "", ""

	// "udp6" + Dial performs the route lookup and source selection; no
	// datagram is transmitted. A host with no v6 default route fails here
	// immediately rather than blocking.
	c, err := net.Dial("udp6", v6ProbeDest)
	if err != nil {
		return "", ""
	}
	la, ok := c.LocalAddr().(*net.UDPAddr)
	_ = c.Close()
	if !ok || la == nil || la.IP == nil {
		return "", ""
	}
	if !isGlobalIPv6(la.IP) {
		// A ULA or link-local source means there is no globally routable v6
		// path, whatever the route table claims.
		return "", ""
	}
	v6PrefAddr = la.IP.String()

	// Find which interface owns it, so sibling addresses can be ranked behind
	// it and addresses on other (likely stale) interfaces behind those.
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, a := range addrs {
				if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.Equal(la.IP) {
					v6PrefIf = iface.Name
					break
				}
			}
			if v6PrefIf != "" {
				break
			}
		}
	}
	return v6PrefAddr, v6PrefIf
}

// rankV6Endpoints orders v6 candidates so the ones that can actually work
// come first: the kernel's preferred source, then its interface-mates, then
// the rest. eps are "[addr]:port" strings; ifOf maps each back to the
// interface it was collected from.
//
// Stable within each tier, so the interface enumeration order is preserved
// for addresses the probe cannot distinguish.
func rankV6Endpoints(eps []string, ifOf map[string]string) []string {
	if len(eps) < 2 {
		return eps
	}
	prefAddr, prefIf := preferredV6Source()
	if prefAddr == "" {
		return eps // no opinion; leave the caller's order alone
	}
	prefEP := ""
	for _, ep := range eps {
		if h, _, err := net.SplitHostPort(ep); err == nil && h == prefAddr {
			prefEP = ep
			break
		}
	}
	var first, sameIf, rest []string
	for _, ep := range eps {
		switch {
		case ep == prefEP:
			first = append(first, ep)
		case prefIf != "" && ifOf[ep] == prefIf:
			sameIf = append(sameIf, ep)
		default:
			rest = append(rest, ep)
		}
	}
	out := make([]string, 0, len(eps))
	out = append(out, first...)
	out = append(out, sameIf...)
	out = append(out, rest...)
	return out
}
