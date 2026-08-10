//go:build windows

package main

// Start-at-login on Windows via the per-user Run key
// (HKCU\Software\Microsoft\Windows\CurrentVersion\Run). We register THIS tray
// app to launch at login; it then auto-connects the overlay if autoConnect is
// set (see onReady), so the UAC elevation for the privileged client happens
// through the normal prompt rather than silently at boot. HKCU (not HKLM)
// means no admin rights are needed just to toggle the setting.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

// --- boot-time connection (scheduled task, runs before login) --------------

// The tray UI can't run before login, but the overlay client can: a scheduled
// task triggered "at startup" runs overlay-client as SYSTEM at boot, so the
// network is up before (and independent of) any login. Creating a SYSTEM task
// needs Administrator, so enable/disable elevate via UAC.

const bootTaskName = "APGOClient"

func bootStartSupported() bool { return true }

// bootLauncherPath is the batch the boot task runs — it sets the client's env
// (absolute user paths) and launches overlay-client with output to the log.
func bootLauncherPath() string { return filepath.Join(appDir(), "boot-launch.cmd") }

func bootStartEnabled() bool {
	cmd := exec.Command("schtasks", "/Query", "/TN", bootTaskName)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run() == nil
}

// writeBootLauncher regenerates the boot batch from the current config so the
// SYSTEM task starts the client with the right environment.
func writeBootLauncher() error {
	c := loadConfig()
	var b strings.Builder
	b.WriteString("@echo off\r\n")
	b.WriteString("set \"CLIENT_CONFIG=" + configPath() + "\"\r\n")
	b.WriteString("set \"CONTROL_SOCKET=" + controlSocket() + "\"\r\n")
	b.WriteString("set \"ADMIN_PUBKEY_FILE=" + adminPubKeyPath() + "\"\r\n")
	b.WriteString("set \"PROVISIONS_FILE=" + provisionsPath() + "\"\r\n")
	b.WriteString("set \"REVOCATIONS_FILE=" + revocationsPath() + "\"\r\n")
	b.WriteString("set \"SEALED_ADMIN_KEY_FILE=" + sealedKeyPath() + "\"\r\n")
	b.WriteString("set \"APPROVALS_FILE=" + approvalsPath() + "\"\r\n")
	b.WriteString("set \"NETCONFIG_FILE=" + netConfigPath() + "\"\r\n")
	b.WriteString("set \"TRACKERS_FILE=" + trackersPath() + "\"\r\n")
	b.WriteString("set \"POLICY_FILE=" + policyPath() + "\"\r\n")
	if c.AdminPublicKey != "" {
		b.WriteString("set \"ADMIN_PUBLIC_KEY=" + c.AdminPublicKey + "\"\r\n")
	}
	b.WriteString("\"" + clientBinary() + "\" >> \"" + logPath() + "\" 2>&1\r\n")
	return os.WriteFile(bootLauncherPath(), []byte(b.String()), 0o644)
}

// setBootStart creates (enable) or deletes (disable) the boot scheduled task.
// Both elevate via UAC because a SYSTEM / highest-privilege task requires admin.
func setBootStart(enable bool) error {
	if !enable {
		ps := "Start-Process -FilePath 'schtasks' -ArgumentList '/Delete','/TN','" +
			bootTaskName + "','/F' -Verb RunAs -WindowStyle Hidden -Wait"
		return exec.Command("powershell", "-NoProfile", "-Command", ps).Run()
	}
	if err := writeBootLauncher(); err != nil {
		return err
	}
	// /RU SYSTEM + /RL HIGHEST so it runs fully privileged at boot with no login;
	// /SC ONSTART triggers at system startup.
	ps := fmt.Sprintf(
		"Start-Process -FilePath 'schtasks' -ArgumentList '/Create','/TN','%s',"+
			"'/TR','\"%s\"','/SC','ONSTART','/RU','SYSTEM','/RL','HIGHEST','/F' "+
			"-Verb RunAs -WindowStyle Hidden -Wait",
		bootTaskName, bootLauncherPath())
	return exec.Command("powershell", "-NoProfile", "-Command", ps).Run()
}
