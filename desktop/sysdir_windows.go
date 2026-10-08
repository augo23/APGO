//go:build windows

package main

// Where the PRIVILEGED side of APGO lives on Windows.
//
// The overlay client runs elevated (Connect) or as SYSTEM (boot task). The
// batch file that launches it and the client binary it runs used to live in
// %USERPROFILE%\.apgo and the per-user install dir — both writable by any
// program running as the user, so editing boot-launch.cmd (or swapping
// overlay-client.exe) was a silent user → SYSTEM escalation at the next boot.
//
// %ProgramData%\APGO is created by an elevated step, owned by Administrators,
// and ACL'd so SYSTEM/Administrators have full control and Users can only read
// (the tray still reads the log). The launcher and a copy of the client +
// wintun.dll live there; nothing privileged executes from a user-writable path.

import (
	"os"
	"path/filepath"
)

func sysDir() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "APGO")
}
func sysBinDir() string           { return filepath.Join(sysDir(), "bin") }
func installedClient() string     { return filepath.Join(sysBinDir(), clientExeName) }
func logPath() string             { return filepath.Join(sysDir(), "overlay-client.log") }
func pidPath() string             { return filepath.Join(sysDir(), "client.pid") }
func connectLauncherPath() string { return filepath.Join(sysDir(), "launch.cmd") }
func bootLauncherPath() string    { return filepath.Join(sysDir(), "boot-launch.cmd") }

// controlSocket stays in the user's profile on Windows: an AF_UNIX socket
// needs write access to the socket file for the (unelevated) tray to connect,
// and the client does not chown/chmod it there (secureControlSocket is a
// no-op on Windows), so the socket path is never used to act on another file.
func controlSocket() string { return filepath.Join(appDir(), "control.sock") }
