//go:build windows

package main

// Windows platform layer: the client needs Administrator rights (Wintun
// adapter), so Connect/Disconnect elevate via UAC (PowerShell
// `Start-Process -Verb RunAs`). Dialogs/notifications use PowerShell WinForms;
// URLs open with rundll32.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
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

	// Write a launcher batch that sets the env and runs the client with output
	// redirected to the log, then launch it elevated (UAC).
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
	launch := filepath.Join(appDir(), "launch.cmd")
	if err := os.WriteFile(launch, []byte(b.String()), 0o644); err != nil {
		notify("Connect failed: " + err.Error())
		return
	}

	ps := fmt.Sprintf("Start-Process -FilePath %s -Verb RunAs -WindowStyle Hidden", psQuote(launch))
	if err := exec.Command("powershell", "-NoProfile", "-Command", ps).Run(); err != nil {
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
