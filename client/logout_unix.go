//go:build !windows

package main

import (
	"os/signal"
	"syscall"
)

// ignoreSIGPIPE makes a write to a broken stdout/stderr pipe fail with EPIPE
// instead of killing the process (see logout.go). Sockets are unaffected: Go
// already turns SIGPIPE on them into EPIPE.
func ignoreSIGPIPE() { signal.Ignore(syscall.SIGPIPE) }
