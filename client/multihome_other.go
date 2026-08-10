//go:build !linux

package main

// setupOverlayCoexistence is a Linux-only concern: it is about two overlay
// clients sharing ONE network namespace, which is a container/hostNetwork
// scenario. On macOS and Windows a second client would create its own utun /
// Wintun adapter and the OS route table handles the pair without policy
// routing, so there is nothing to do here.
func setupOverlayCoexistence(addrCIDR string) {}
