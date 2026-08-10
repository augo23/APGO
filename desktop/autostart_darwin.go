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
	"html"
	"os"
	"os/exec"
	"path/filepath"
)

const launchAgentLabel = "com.apgo.desktop"

// --- boot-time connection (LaunchDaemon, runs before login) ----------------

// The tray UI can't run before someone logs in, but the overlay client can: a
// system LaunchDaemon starts overlay-client as root at boot, so the network is
// up before (and independent of) any login. Installing it writes to
// /Library/LaunchDaemons, which needs root — hence the one admin prompt.

const bootDaemonLabel = "com.apgo.client"

func bootDaemonPath() string {
	return filepath.Join("/Library/LaunchDaemons", bootDaemonLabel+".plist")
}

func bootStartSupported() bool { return true }

// bootStartEnabled reports whether the boot daemon plist is installed. The plist
// is world-readable (0644), so this needs no privileges.
func bootStartEnabled() bool {
	_, err := os.Stat(bootDaemonPath())
	return err == nil
}

// bootEnvPlist renders the <EnvironmentVariables> dict the client needs, using
// the CURRENT user's absolute ~/.apgo paths (the daemon runs as root, whose HOME
// is not the user's).
func bootEnvPlist() string {
	env := map[string]string{
		"CLIENT_CONFIG":         configPath(),
		"CONTROL_SOCKET":        controlSocket(),
		"ADMIN_PUBKEY_FILE":     adminPubKeyPath(),
		"PROVISIONS_FILE":       provisionsPath(),
		"REVOCATIONS_FILE":      revocationsPath(),
		"SEALED_ADMIN_KEY_FILE": sealedKeyPath(),
		"APPROVALS_FILE":        approvalsPath(),
		"NETCONFIG_FILE":        netConfigPath(),
		"TRACKERS_FILE":         trackersPath(),
		"POLICY_FILE":           policyPath(),
	}
	if k := loadConfig().AdminPublicKey; k != "" {
		env["ADMIN_PUBLIC_KEY"] = k
	}
	out := "  <key>EnvironmentVariables</key>\n  <dict>\n"
	for k, v := range env {
		out += fmt.Sprintf("    <key>%s</key><string>%s</string>\n",
			html.EscapeString(k), html.EscapeString(v))
	}
	out += "  </dict>\n"
	return out
}

// setBootStart installs (enable) or removes (disable) the boot LaunchDaemon. It
// always runs through the admin prompt because /Library/LaunchDaemons is root
// territory. Installing also bootstraps it into the running system so the
// connection can come up without a reboot.
func setBootStart(enable bool) error {
	p := bootDaemonPath()
	if !enable {
		sh := fmt.Sprintf("launchctl bootout system %s 2>/dev/null; rm -f %s", q(p), q(p))
		return runAdmin(sh)
	}

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key>
  <array><string>%s</string></array>
%s  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>%s</string>
  <key>StandardErrorPath</key><string>%s</string>
</dict>
</plist>
`, bootDaemonLabel, html.EscapeString(clientBinary()), bootEnvPlist(),
		html.EscapeString(logPath()), html.EscapeString(logPath()))

	// Stage the plist in user space, then install it with one privileged step:
	// copy into /Library/LaunchDaemons, fix ownership/perms, and bootstrap.
	tmp := filepath.Join(appDir(), "boot-daemon.plist")
	if err := os.WriteFile(tmp, []byte(plist), 0o644); err != nil {
		return err
	}
	sh := fmt.Sprintf(
		"cp %s %s && chown root:wheel %s && chmod 644 %s && "+
			"launchctl bootout system %s 2>/dev/null; launchctl bootstrap system %s",
		q(tmp), q(p), q(p), q(p), q(p), q(p))
	return runAdmin(sh)
}

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
