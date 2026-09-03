//go:build !windows

package main

// ensureFirewallRules is a no-op everywhere but Windows: Linux and macOS do
// not block inbound UDP by default, and on the platforms where an operator HAS
// configured a firewall, editing their rules from inside the client would be
// presumptuous. reachability.go tells them which rule to add instead.
func ensureFirewallRules(port int) {}
