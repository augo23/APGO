//go:build windows

package main

// Windows platform layer: the client needs Administrator rights (Wintun
// adapter), so Connect/Disconnect elevate via UAC (PowerShell
// `Start-Process -Verb RunAs`). Dialogs/notifications use PowerShell WinForms;
// URLs open with rundll32.

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
)

const clientExeName = "overlay-client.exe"

// psQuote single-quotes a string for a PowerShell command.
func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func doConnect() {
	c := loadConfig()
	if c.NetworkName == "" || c.PSK == "" {
		notify("Set the network name and PSK in Settings first.")
		doSettings()
		return
	}
	applyDefaults(&c)
	_ = saveConfig(c)

	// Build the launcher batch, then — in ONE elevated step — create the
	// protected %ProgramData%\APGO, install the client there, write the
	// launcher there and start it. Nothing that runs elevated is read from a
	// user-writable location. See sysdir_windows.go.
	bat, err := clientLaunchBatch(c)
	if err != nil {
		notify("Connect failed: " + err.Error())
		return
	}
	script := prepareSysDirPS() + writeSysFilePS(connectLauncherPath(), bat) +
		"Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', ('\"' + " + psQuote(connectLauncherPath()) + " + '\"') -WindowStyle Hidden\n"
	if bootStartEnabled() {
		// Migrate a boot task left by an older version (it ran a batch in the
		// user's profile as SYSTEM) — same prompt, no extra step for the user.
		script += bootTaskInstallPS(bat)
	}
	if err := runElevatedPS(script); err != nil {
		notify("Connect failed (UAC declined?): " + err.Error())
		return
	}
	for i := 0; i < 16; i++ {
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
	// Killing an elevated process requires elevation, so run taskkill via RunAs.
	ps := "Start-Process -FilePath 'taskkill' -ArgumentList '/IM','" + clientExeName + "','/F' -Verb RunAs -WindowStyle Hidden"
	_ = exec.Command("powershell", "-NoProfile", "-Command", ps).Run()
	time.Sleep(400 * time.Millisecond)
	refreshStatus()
}

func notify(msg string) {
	ps := fmt.Sprintf("Add-Type -AssemblyName System.Windows.Forms; [void][System.Windows.Forms.MessageBox]::Show(%s,'APGO')", psQuote(msg))
	// Fire-and-forget so it doesn't block the tray loop.
	_ = exec.Command("powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps).Start()
}

// promptPassword shows a masked WinForms input box; "" if cancelled. The title
// is passed via the environment to avoid quoting problems.
func promptPassword(title string) string {
	ps := `Add-Type -AssemblyName System.Windows.Forms,System.Drawing;` +
		`$f=New-Object Windows.Forms.Form;$f.Text='APGO';$f.Width=410;$f.Height=170;$f.StartPosition='CenterScreen';$f.TopMost=$true;` +
		`$l=New-Object Windows.Forms.Label;$l.Text=$env:APGO_PROMPT;$l.AutoSize=$true;$l.Top=14;$l.Left=14;$f.Controls.Add($l);` +
		`$t=New-Object Windows.Forms.TextBox;$t.UseSystemPasswordChar=$true;$t.Top=46;$t.Left=14;$t.Width=366;$f.Controls.Add($t);` +
		`$b=New-Object Windows.Forms.Button;$b.Text='OK';$b.Top=84;$b.Left=296;$b.Width=84;$b.DialogResult='OK';$f.Controls.Add($b);$f.AcceptButton=$b;` +
		`if($f.ShowDialog() -eq 'OK'){[Console]::Out.Write($t.Text)}`
	cmd := exec.Command("powershell", "-NoProfile", "-STA", "-Command", ps)
	cmd.Env = append(os.Environ(), "APGO_PROMPT="+title)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimRight(string(out), "\r\n")
}

func openBrowser(url string) {
	_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
}

// --- elevated, protected launch -------------------------------------------

// batchUnsafe matches characters that would let a value break out of a
// `set "NAME=value"` line (or be expanded by cmd.exe) in the launcher batch.
// Values come from the user's profile and config, which malware running as the
// user can edit; the batch then runs elevated or as SYSTEM.
const batchUnsafe = "\"%!^&|<>\r\n"

// clientLaunchBatch renders the batch that sets the client's environment and
// starts the protected client copy with output appended to the protected log.
func clientLaunchBatch(c mConfig) (string, error) {
	vars := [][2]string{
		{"CLIENT_CONFIG", configPath()},
		{"CONTROL_SOCKET", controlSocket()},
		{"ADMIN_PUBKEY_FILE", adminPubKeyPath()},
		{"PROVISIONS_FILE", provisionsPath()},
		{"REVOCATIONS_FILE", revocationsPath()},
		{"SEALED_ADMIN_KEY_FILE", sealedKeyPath()},
		{"APPROVALS_FILE", approvalsPath()},
		{"NETCONFIG_FILE", netConfigPath()},
		{"TRACKERS_FILE", trackersPath()},
		{"POLICY_FILE", policyPath()},
		{"NETSHARES_FILE", netSharesPath()},
		{"APGO_NETWORKS_DIR", networksStateDir()},
	}
	if c.AdminPublicKey != "" {
		vars = append(vars, [2]string{"ADMIN_PUBLIC_KEY", c.AdminPublicKey})
	}
	var b strings.Builder
	b.WriteString("@echo off\r\n")
	for _, kv := range vars {
		if strings.ContainsAny(kv[1], batchUnsafe) {
			return "", fmt.Errorf("refusing to launch: %s contains a character that is not allowed (%q)", kv[0], kv[1])
		}
		b.WriteString("set \"" + kv[0] + "=" + kv[1] + "\"\r\n")
	}
	b.WriteString("\"" + installedClient() + "\" >> \"" + logPath() + "\" 2>&1\r\n")
	return b.String(), nil
}

// prepareSysDirPS returns PowerShell (run elevated) that creates
// %ProgramData%\APGO, takes ownership of it for Administrators, resets its ACL
// to SYSTEM/Administrators full + Users read, and installs the client and
// wintun.dll into its bin folder.
//
// ProgramData lets ordinary users create subfolders, so an attacker could have
// pre-created APGO with their own ACL (or as a junction). Hence: a reparse
// point is deleted, ownership is taken, and the ACL is replaced, not merged.
func prepareSysDirPS() string {
	src := filepath.Dir(clientBinary())
	return "$ErrorActionPreference = 'Stop'\n" +
		"$d = " + psQuote(sysDir()) + "\n" +
		"$bin = " + psQuote(sysBinDir()) + "\n" +
		"if (Test-Path -LiteralPath $d) { $i = Get-Item -LiteralPath $d -Force; " +
		"if ($i.Attributes -band [IO.FileAttributes]::ReparsePoint) { $i.Delete() } }\n" +
		"New-Item -ItemType Directory -Force -Path $bin | Out-Null\n" +
		"& icacls.exe $d /setowner '*S-1-5-32-544' /T /C /Q | Out-Null\n" +
		"& icacls.exe $d /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' /Q | Out-Null\n" +
		"if ($LASTEXITCODE -ne 0) { throw 'could not secure ' + $d }\n" +
		"& icacls.exe (Join-Path $d '*') /reset /T /C /Q | Out-Null\n" +
		"$src = " + psQuote(src) + "\n" +
		"foreach ($f in @(" + psQuote(clientExeName) + ", 'wintun.dll')) {\n" +
		"  $s = Join-Path $src $f\n" +
		"  if (Test-Path -LiteralPath $s) { Copy-Item -LiteralPath $s -Destination (Join-Path $bin $f) -Force }\n" +
		"}\n" +
		"if (-not (Test-Path -LiteralPath " + psQuote(installedClient()) + ")) { throw 'overlay-client.exe not found next to APGO.exe' }\n"
}

// writeSysFilePS writes content to path from INSIDE the elevated script. The
// content travels base64-encoded in the command, never via a staging file a
// user process could swap before the elevated side reads it.
func writeSysFilePS(path, content string) string {
	b64 := base64.StdEncoding.EncodeToString([]byte(content))
	return "[IO.File]::WriteAllBytes(" + psQuote(path) + ", [Convert]::FromBase64String('" + b64 + "'))\n"
}

// runElevatedPS runs script in an elevated PowerShell (one UAC prompt) and
// waits for it. -EncodedCommand (UTF-16LE base64) sidesteps every quoting
// problem between Go, the outer PowerShell and the elevated one.
func runElevatedPS(script string) error {
	u := utf16.Encode([]rune(script))
	raw := make([]byte, 0, len(u)*2)
	for _, r := range u {
		raw = append(raw, byte(r), byte(r>>8))
	}
	enc := base64.StdEncoding.EncodeToString(raw)
	outer := "$p = Start-Process -FilePath 'powershell.exe' -Verb RunAs -WindowStyle Hidden -Wait -PassThru " +
		"-ArgumentList '-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand','" + enc + "'; " +
		"exit $p.ExitCode"
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", outer)
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return fmt.Errorf("the elevated step failed or was declined (exit %d)", ee.ExitCode())
		}
		return err
	}
	return nil
}
