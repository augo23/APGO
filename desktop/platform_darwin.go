//go:build darwin

package main

// macOS platform layer: elevation via osascript ("with administrator
// privileges"), native dialogs/notifications, and opening URLs with `open`.

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const clientExeName = "overlay-client"

func doConnect() {
	c := loadConfig()
	if c.NetworkName == "" || c.PSK == "" {
		notify("Set the network name and PSK in Settings first.")
		doSettings()
		return
	}
	applyDefaults(&c)
	_ = saveConfig(c)

	env := fmt.Sprintf("CLIENT_CONFIG=%s CONTROL_SOCKET=%s ADMIN_PUBKEY_FILE=%s PROVISIONS_FILE=%s REVOCATIONS_FILE=%s SEALED_ADMIN_KEY_FILE=%s APPROVALS_FILE=%s NETCONFIG_FILE=%s TRACKERS_FILE=%s POLICY_FILE=%s",
		q(configPath()), q(controlSocket()), q(adminPubKeyPath()), q(provisionsPath()), q(revocationsPath()), q(sealedKeyPath()), q(approvalsPath()), q(netConfigPath()), q(trackersPath()), q(policyPath()))
	if c.AdminPublicKey != "" {
		env += " ADMIN_PUBLIC_KEY=" + q(c.AdminPublicKey)
	}
	// Launch detached: redirect all std fds (no controlling terminal — no nohup,
	// which fails under privileged exec) and background it; the child reparents
	// to launchd and keeps running after the privileged shell returns.
	sh := fmt.Sprintf("%s %s >> %s 2>&1 </dev/null & echo $! > %s",
		env, q(clientBinary()), q(logPath()), q(pidPath()))
	if err := runAdmin(sh); err != nil {
		notify("Connect failed: " + err.Error())
		return
	}
	for i := 0; i < 12; i++ {
		time.Sleep(500 * time.Millisecond)
		if _, ok := fetchInfo(); ok {
			refreshStatus()
			notify("Connected.")
			return
		}
	}
	refreshStatus()
	notify("Client didn't come up — open the log to see why.")
}

func doDisconnect() {
	sh := fmt.Sprintf("kill $(cat %s) 2>/dev/null; rm -f %s", q(pidPath()), q(pidPath()))
	if err := runAdmin(sh); err != nil {
		notify("Disconnect failed: " + err.Error())
		return
	}
	time.Sleep(300 * time.Millisecond)
	refreshStatus()
}

// runAdmin runs a shell command as root via the macOS authentication prompt.
func runAdmin(cmd string) error {
	esc := strings.ReplaceAll(cmd, "\\", "\\\\")
	esc = strings.ReplaceAll(esc, "\"", "\\\"")
	script := "do shell script \"" + esc + "\" with administrator privileges"
	return exec.Command("osascript", "-e", script).Run()
}

func notify(msg string) {
	as := fmt.Sprintf(`display notification %q with title "APGO"`, msg)
	_ = exec.Command("osascript", "-e", as).Run()
}

// promptPassword shows a native hidden-answer dialog; "" if cancelled.
func promptPassword(title string) string {
	as := fmt.Sprintf(`try
	set r to text returned of (display dialog %q default answer "" with hidden answer buttons {"Cancel","OK"} default button "OK")
	return r
on error number -128
	return "__CANCEL__"
end try`, title)
	out, err := exec.Command("osascript", "-e", as).Output()
	if err != nil {
		return ""
	}
	s := strings.TrimRight(string(out), "\n")
	if s == "__CANCEL__" {
		return ""
	}
	return s
}

func openBrowser(url string) { _ = exec.Command("open", url).Start() }

// q single-quotes a string for safe use in a /bin/sh command.
func q(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
