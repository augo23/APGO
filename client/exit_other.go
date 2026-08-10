//go:build !linux && !darwin && !windows

package main

import "errors"

// setupExitNAT is implemented on Linux (iptables), macOS (pf), and Windows
// (WinNAT). Other platforms can still USE an exit (route their traffic
// through one), just not BE one.
func setupExitNAT() error {
	return errors.New("exit-node mode is only supported on Linux, macOS, and Windows hosts")
}
