package main

import "sync"

// onceReset returns a fresh sync.Once, so tests can re-evaluate a value that
// production code computes exactly once at startup.
func onceReset() sync.Once { return sync.Once{} }
