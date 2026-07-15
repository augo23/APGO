//go:build darwin

package main

// Start-at-login on macOS via a per-user LaunchAgent. We install a plist in
// ~/Library/LaunchAgents that launches THIS tray app at login (RunAtLoad). The
// tray then auto-connects the overlay if autoConnect is set (see onReady), so
// the one place that needs admin rights — starting the privileged client — is
// still gated by the normal osascript prompt rather than silently elevating at
// boot.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const launchAgentLabel = "com.apgo.desktop"

func launchAgentPath() string {
	h, _ := os.UserHomeDir()
	return filepath.Join(h, "Library", "LaunchAgents", launchAgentLabel+".plist")
}

// loginStartSupported reports whether we can manage a login item here.
func loginStartSupported() bool { return true }

// loginStartEnabled reports whether the login item is currently installed.
func loginStartEnabled() bool {
	_, err := os.Stat(launchAgentPath())
	return err == nil
}

// setLoginStart installs or removes the LaunchAgent. Installing also loads it
// into the current session so it's active immediately; both operations are
// best-effort on the launchctl side (the plist on disk is what matters at the
// next login).
func setLoginStart(enable bool) error {
	p := launchAgentPath()
	if !enable {
		_ = exec.Command("launchctl", "unload", p).Run()
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key>
  <array><string>%s</string></array>
  <key>RunAtLoad</key><true/>
  <key>ProcessType</key><string>Interactive</string>
</dict>
</plist>
`, launchAgentLabel, exe)
	if err := os.WriteFile(p, []byte(plist), 0o644); err != nil {
		return err
	}
	// Best-effort load so it's registered without requiring a re-login.
	_ = exec.Command("launchctl", "load", p).Run()
	return nil
}
