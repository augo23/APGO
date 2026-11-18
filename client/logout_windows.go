//go:build windows

package main

// ignoreSIGPIPE is a no-op on Windows, which has no SIGPIPE: a write to a
// closed pipe just returns an error.
func ignoreSIGPIPE() {}
