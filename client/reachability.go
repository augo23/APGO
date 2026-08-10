package main

// reachability.go answers "what stands between this node and the internet",
// so the dashboards can give advice that names the right device.
//
// The distinction matters more than it looks. "Open UDP 6970" is correct for a
// node with a public address and a host firewall, and actively misleading for
// a node on a LAN behind a router — there the host firewall is irrelevant and
// the port has to be forwarded on the ROUTER. Getting this wrong sends people
// to edit ufw rules on a machine whose packets never reach it.

import (
	"net"
	"strings"
)

// localIPv4Strings lists this host's own IPv4 addresses (physical interfaces
// only — the overlay TUN and other virtual devices are excluded, since an
// address on those says nothing about internet reachability).
func localIPv4Strings() []string {
	var out []string
	for _, n := range localIPv4Nets() {
		if ip := n.IP.To4(); ip != nil {
			out = append(out, ip.String())
		}
	}
	return out
}

// behindRouter reports whether our STUN-observed public address belongs to
// some device other than this host — i.e. a NAT we cannot configure locally.
//
// "" (unknown) is treated as NOT behind a router, so a node that simply has
// not completed STUN never produces confident advice about a device that may
// not exist.
func behindRouter() bool {
	pub := publicIPOnly()
	if pub == "" {
		return false
	}
	pubIP := net.ParseIP(pub)
	if pubIP == nil {
		return false
	}
	// A private "public" address means STUN itself was answered from inside a
	// NAT (double NAT / CGNAT); definitely not ours to configure.
	if pubIP.IsPrivate() {
		return true
	}
	for _, s := range localIPv4Strings() {
		if s == pub {
			return false // the public address IS on this host: no router in between
		}
	}
	return true
}

// natTraversalAdvice returns one sentence naming the device to change and the
// action to take, for a node that cannot be reached inbound. Empty when there
// is nothing useful to say.
func natTraversalAdvice(port int) string {
	if port <= 0 {
		return ""
	}
	p := itoaPort(port)
	if !behindRouter() {
		return "This host holds its public address directly, so open UDP " + p +
			" in its firewall (e.g. sudo ufw allow " + p + "/udp)."
	}
	local := strings.Join(localIPv4Strings(), ", ")
	if local == "" {
		local = "this host"
	}
	return "This host is behind a router (its public address is not on any local " +
		"interface), so a host firewall rule will not help: forward UDP " + p +
		" on the ROUTER to " + local + ", or enable UPnP/NAT-PMP there and the " +
		"client will request the mapping itself."
}

func itoaPort(p int) string {
	if p == 0 {
		return "0"
	}
	var b []byte
	for p > 0 {
		b = append([]byte{byte('0' + p%10)}, b...)
		p /= 10
	}
	return string(b)
}
