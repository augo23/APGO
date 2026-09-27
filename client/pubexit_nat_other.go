//go:build !linux && !darwin && !windows && !freebsd

package main

import (
	"errors"
	"net"
)

func setupPublicExitNAT(*net.IPNet) error {
	return errors.New("public exit nodes are supported on Linux, macOS and Windows")
}
