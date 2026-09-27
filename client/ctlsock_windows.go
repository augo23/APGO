//go:build windows

package main

// secureControlSocket is a no-op on Windows: an AF_UNIX socket there is
// protected by the ACL it inherits from its directory (%USERPROFILE%\.apgo).
func secureControlSocket(path string) {}
