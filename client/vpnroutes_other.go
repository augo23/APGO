//go:build !darwin && !windows

package main

import "net"

// On Linux (and other) hosts the client typically runs in a container or
// netns where the operator/compose stack controls the default route, so
// full-tunnel steering is not done in-process. use_exit still forwards every
// internet-bound packet that reaches the TUN to the selected exit.
func enableFullTunnelRoutes() error { return nil }

func pinTransportToPhysicalInterface(*net.UDPConn) error { return nil }

func pinAuxUDPSocket(*net.UDPConn) {}
