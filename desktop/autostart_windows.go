//go:build windows

package main

// Start-at-login on Windows via the per-user Run key
// (HKCU\Software\Microsoft\Windows\CurrentVersion\Run). We register THIS tray
// app to launch at login; it then auto-connects the overlay if autoConnect is
// set (see onReady), so the UAC elevation for the privileged client happens
// through the normal prompt rather than silently at boot. HKCU (not HKLM)
// means no admin rights are needed just to toggle the setting.

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
)

const runKeyPath = `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
const runKeyName = "APGO"

func loginStartSupported() bool { return true }

func loginStartEnabled() bool {
	cmd := exec.Command("reg", "query", runKeyPath, "/v", runKeyName)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run() == nil
}

func setLoginStart(enable bool) error {
	if !enable {
		cmd := exec.Command("reg", "delete", runKeyPath, "/v", runKeyName, "/f")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if out, err := cmd.CombinedOutput(); err != nil {
			// "delete" of a missing value is not an error we care about.
			if strings.Contains(strings.ToLower(string(out)), "unable to find") {
				return nil
			}
			return err
		}
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// Quote the path so spaces in Program Files are handled at launch.
	cmd := exec.Command("reg", "add", runKeyPath, "/v", runKeyName,
		"/t", "REG_SZ", "/d", `"`+exe+`"`, "/f")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}
