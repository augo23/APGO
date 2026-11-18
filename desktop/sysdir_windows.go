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
	"path/filepath"

	"golang.org/x/sys/windows"
)

// sysDir asks Windows for the real ProgramData folder. It must NOT read the
// %ProgramData% environment variable: whatever launched this app controls
// that, so a program running as the user could point it at a folder it can
// write, and the elevated install would put the SYSTEM client there.
func sysDir() string {
	pd, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil || pd == "" {
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
func defaultControlSocket() string { return filepath.Join(appDir(), "control.sock") }

// system32 is the full path of a Windows system tool. Commands are never run
// by bare name: PATH (and %SystemRoot%) come from whatever launched this app,
// so a program running as the user could put its own "powershell.exe" first
// in PATH, and the UAC prompt the user approves would elevate that instead.
func system32(name string) string {
	d, err := windows.GetSystemDirectory()
	if err != nil || d == "" {
		d = `C:\Windows\System32`
	}
	return filepath.Join(d, name)
}

// psExe is Windows PowerShell's full path.
func psExe() string { return system32(`WindowsPowerShell\v1.0\powershell.exe`) }
