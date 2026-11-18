package main

// testControlSocket, when set, replaces the client control socket path. Only
// tests set it: on macOS the real socket lives at a fixed system path, so
// without this a test's fake client either collides with (or deletes) the
// socket of the APGO client actually running on the developer's machine, and
// code under test can send live changes to that real client.
var testControlSocket string

// controlSocket is the running client's control socket.
func controlSocket() string {
	if testControlSocket != "" {
		return testControlSocket
	}
	return defaultControlSocket()
}
