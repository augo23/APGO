//go:build !linux

package main

import "errors"

// setupExitNAT is only implemented on Linux. Other platforms can still USE an
// exit (route their traffic through one), just not BE one.
func setupExitNAT() error {
	return errors.New("exit-node mode is only supported on Linux hosts")
}
