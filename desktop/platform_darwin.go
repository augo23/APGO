//go:build darwin

package main

// macOS platform layer: elevation via osascript ("with administrator
// privileges"), native dialogs/notifications, and opening URLs with `open`.

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const clientExeName = "overlay-client"

func doConnect() {
	// Only one privileged connect/disconnect at a time. TryLock (not Lock) so a
	// stray double-click is dropped rather than queuing a second osascript
	// prompt behind the first.
	if !opMu.TryLock() {
		return
	}
	defer opMu.Unlock()

	c := loadConfig()
	if c.NetworkName == "" || c.PSK == "" {
		notify("Set the network name and PSK in Settings first.")
		doSettings()
		return
	}
	applyDefaults(&c)
	_ = saveConfig(c)

	// Already running? Do nothing.
	//
	// The boot LaunchDaemon starts the client too, so Connect is not the only
	// starter — and after an install that restores the daemon, it has usually
	// won the race. Launching a second one produced two clients fighting over
	// one overlay identity: the newcomer generated a fresh node key and a utun
	// before noticing the conflict and dying.
	//
	// EXCEPT when what's running is a client PARKED IN SETUP MODE (it started
	// before the network was configured — e.g. the boot daemon right after an
	// install wiped ~/.apgo). Its setup server answers /api/info too, so this
	// check used to report "Already connected." and return — deadlock: the
	// config we just saved above was never read by anyone. A parked client
	// polls its config file and restarts itself once valid details appear, so
	// wait for that handoff instead.
	if info, ok := fetchInfo(); ok {
		if ns, _ := info["needs_setup"].(bool); !ns {
			refreshStatus()
			notify("Already connected.")
			return
		}
		notify("Applying configuration…")
		for i := 0; i < 24; i++ { // parked client notices the config within ~2s
			time.Sleep(500 * time.Millisecond)
			info, ok = fetchInfo()
			if !ok {
				break // setup instance exited — safe to start the real one
			}
			if ns, _ := info["needs_setup"].(bool); !ns {
				refreshStatus()
				notify("Connected.")
				return
			}
		}
		if ok {
			// Still parked after 12s — likely an old client build that
			// doesn't poll its config. Don't stack a second instance on it.
			notify("The client is stuck waiting for setup — quit it (Disconnect) and Connect again, or reinstall.")
			return
		}
		// The parked instance exited. If a KeepAlive boot daemon exists it
		// relaunches the (now configured) client itself — give it a moment
		// before racing it with our own copy.
		for i := 0; i < 10; i++ {
			time.Sleep(500 * time.Millisecond)
			if info, ok := fetchInfo(); ok {
				if ns, _ := info["needs_setup"].(bool); !ns {
					refreshStatus()
					notify("Connected.")
					return
				}
			}
		}
	}

	env := fmt.Sprintf("CLIENT_CONFIG=%s CONTROL_SOCKET=%s ADMIN_PUBKEY_FILE=%s PROVISIONS_FILE=%s REVOCATIONS_FILE=%s SEALED_ADMIN_KEY_FILE=%s APPROVALS_FILE=%s NETCONFIG_FILE=%s TRACKERS_FILE=%s POLICY_FILE=%s NETSHARES_FILE=%s APGO_NETWORKS_DIR=%s",
		q(configPath()), q(controlSocket()), q(adminPubKeyPath()), q(provisionsPath()), q(revocationsPath()), q(sealedKeyPath()), q(approvalsPath()), q(netConfigPath()), q(trackersPath()), q(policyPath()), q(netSharesPath()), q(networksStateDir()))
	if c.AdminPublicKey != "" {
		env += " ADMIN_PUBLIC_KEY=" + q(c.AdminPublicKey)
	}
	// Hand ~/.apgo back to the user before launching anything as root.
	//
	// The client runs privileged, so any file or directory it creates here is
	// root-owned. If root gets there first — a boot LaunchDaemon, or simply the
	// first Connect after a fresh install — ~/.apgo ends up owned by root with
	// mode 0700, and THIS app, which runs as the logged-in user, can no longer
	// write in it:
	//
	//     Could not save: open ~/.apgo/webui-credentials.json.tmp: permission denied
	//
	// Only the directory matters: creating a temp file and renaming it needs
	// write permission on the directory, not on the file being replaced. Doing
	// it on every Connect means an already-broken install repairs itself the
	// next time the user clicks the button, with no reinstall.
	//
	// Root keeps full access regardless, so the client is unaffected.
	fixOwn := fmt.Sprintf("chown %d:%d %s 2>/dev/null || true; chmod 700 %s 2>/dev/null || true; ",
		os.Getuid(), os.Getgid(), q(appDir()), q(appDir()))

	// Launch detached: redirect all std fds (no controlling terminal — no nohup,
	// which fails under privileged exec) and background it; the child reparents
	// to launchd and keeps running after the privileged shell returns.
	sh := fixOwn + fmt.Sprintf("%s %s >> %s 2>&1 </dev/null & echo $! > %s",
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
	// Say WHY, not just that it failed. Two independent sources: the socket
	// itself (is the client there, and may we talk to it?) and the client's
	// own log (did it refuse to start, and why?). A bare "open the log" turns
	// every failure into a scavenger hunt.
	notify("Client didn't come up — " + controlSocketDiagnosis() + " | log says: " + lastClientError())
}

func doDisconnect() {
	opMu.Lock()
	defer opMu.Unlock()

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

// notify lives in notify_darwin.go: it posts through the app's OWN bundled
// process (NSUserNotification) so the alert carries the APGO icon, instead of
// osascript's generic Script-Editor identity.

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
