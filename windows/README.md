# APGO for Windows (in progress)

A native Windows tray client — the same overlay, the same admin panel — driven
from a system-tray icon, with a `.cmd` script that builds and installs it.

## Approach

The Go **core** (Noise handshake, sessions, tracker/STUN discovery, endpoint
roaming) is shared with the other platforms. Only two things are Windows-specific:

1. **Data plane — Wintun (not TAP).** Windows' legacy TAP driver is layer-2
   (Ethernet frames); APGO is a layer-3 IP overlay, so we use **Wintun**
   (WireGuard's L3 adapter). It delivers raw IP packets and ships as a single
   `wintun.dll` placed next to the client — no driver install. This lives in
   `client/tun_windows.go` (build-tagged `//go:build windows`), configured via
   `winipcfg`/`netsh` for the address, MTU and route.

2. **App shell.** A `getlantern/systray` tray app (works on Windows) reusing the
   macOS app's cross-platform pieces — the localhost **settings / admin panel /
   login** web UI, config store, and control-socket client are all portable.
   Windows differences:
   - Elevation for the adapter uses **UAC** (`ShellExecute`/`runas`), not `sudo`.
   - Config, keys, log, and control socket live under `%USERPROFILE%\.apgo\`
     (AF_UNIX sockets are supported on Windows 10 1803+).
   - Native dialogs via PowerShell instead of `osascript`.

## Planned layout

```
windows/
  install.cmd        build + bundle wintun.dll + install to %LOCALAPPDATA%\APGO, add to startup
  app/               the tray app (Go, getlantern/systray) + shared web UI
client/tun_windows.go  Wintun data plane
```

## Prerequisites (to build)

- Go for Windows (the installer will offer to fetch it if missing)
- Administrator rights (Wintun adapter creation)
- `wintun.dll` — downloaded automatically by `install.cmd` from wintun.net

## Uniformity plan

To keep macOS and Windows literally the same app, the tray app is being moved
into a shared **`desktop/`** module. ~95% of it (config, the settings/admin/login
web UI, control-socket client, systray menu wiring, status polling) is
OS-independent. Only a thin per-OS layer differs, in build-tagged files:

- `platform_darwin.go` — `osascript` for elevation/dialogs, `~/.apgo` paths.
- `platform_windows.go` — UAC (`Start-Process -Verb RunAs`) + PowerShell dialogs.

Both `macos/install-macos.sh` and `windows/install.cmd` then build the same
`desktop/` module with the appropriate `GOOS`.

## Status

- [x] Shared Go core is already portable
- [x] `client/tun_windows.go` (Wintun L3 data plane)
- [x] `desktop/` shared app module — macOS **and** Windows build from one codebase
- [x] `desktop/platform_windows.go` (UAC elevation, PowerShell dialogs, rundll32)
- [x] `windows/install.cmd` + `install.ps1` (build, fetch wintun.dll, install, startup, launch)

All pending an on-Windows compile/test pass. The macOS app now builds from the
same `desktop/` module (installer updated), so re-running `macos/install-macos.sh`
verifies there's no regression there.

## Build it

On a Windows machine with [Go](https://go.dev/dl/) installed, from the repo:

```
windows\install.cmd
```

