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

// --- boot-time connection (scheduled task, runs before login) --------------

// The tray UI can't run before login, but the overlay client can: a scheduled
// task triggered "at startup" runs overlay-client as SYSTEM at boot, so the
// network is up before (and independent of) any login. Creating a SYSTEM task
// needs Administrator, so enable/disable elevate via UAC.

const bootTaskName = "APGOClient"

func bootStartSupported() bool { return true }

// bootLauncherPath (sysdir_windows.go) is the batch the boot task runs. It
// lives in the protected %ProgramData%\\APGO, not the user profile.

func bootStartEnabled() bool {
	cmd := exec.Command("schtasks", "/Query", "/TN", bootTaskName)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run() == nil
}

// setBootStart creates (enable) or deletes (disable) the boot scheduled task,
// in one elevated step. Enabling also prepares the protected system dir and
// writes the launcher there (see bootTaskInstallPS).
func setBootStart(enable bool) error {
	if !enable {
		return runElevatedPS("$ErrorActionPreference = 'Stop'\n" +
			"Unregister-ScheduledTask -TaskName " + psQuote(bootTaskName) + " -Confirm:$false -ErrorAction SilentlyContinue\n" +
			"Remove-Item -LiteralPath " + psQuote(bootLauncherPath()) + " -Force -ErrorAction SilentlyContinue\n")
	}
	bat, err := clientLaunchBatch(loadConfig())
	if err != nil {
		return err
	}
	return runElevatedPS(prepareSysDirPS() + bootTaskInstallPS(bat))
}

// bootTaskInstallPS returns elevated PowerShell that writes the boot launcher
// into the protected system dir and (re)registers the SYSTEM startup task to
// run it. Register-ScheduledTask -Force replaces a task left by an older
// version that pointed at a batch in the user's profile.
func bootTaskInstallPS(bat string) string {
	return writeSysFilePS(bootLauncherPath(), bat) +
		"$a = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument ('/c \"' + " + psQuote(bootLauncherPath()) + " + '\"')\n" +
		"$t = New-ScheduledTaskTrigger -AtStartup\n" +
		"$pr = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest\n" +
		"Register-ScheduledTask -TaskName " + psQuote(bootTaskName) + " -Action $a -Trigger $t -Principal $pr -Force | Out-Null\n"
}
