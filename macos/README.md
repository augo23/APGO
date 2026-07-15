# APGO menu-bar app (macOS)

A ZeroTier-style menu-bar app for macOS. It shows connection status and peer
count, lets you enter the network config, and connects/disconnects the native
macOS overlay client ([`docs/macos.md`](../docs/macos.md), Stage 1).

> Must be built **on a Mac** — it links against Cocoa (via `getlantern/systray`)
> and drives the root data plane through macOS's authentication prompt. It
> cannot be built or run on Linux.

## Prerequisites

- macOS with the Xcode Command Line Tools: `xcode-select --install`
- Go 1.22+

## Build

```bash
cd macos
./build.sh
```

This runs `go mod tidy` (populating `go.sum` — the reason a network build is
needed once), builds the menu-bar binary and the native `overlay-client`, and
packages them into `APGO.app` (a Dock-less `LSUIElement` menu-bar app with the
client binary bundled inside).

## Use

1. `open APGO.app` (or double-click it). A small node-mesh icon appears in the
   menu bar. If Gatekeeper blocks it (unsigned): right-click → Open, or
   `xattr -dr com.apple.quarantine APGO.app`.
2. **Settings…** → enter the **network name**, **PSK** (`base64:...`), **overlay
   subnet**, and **UDP port** — the same values as the rest of your network.
   These are saved to `~/.apgo/client.yaml`.
3. **Connect** → macOS prompts for your password (the client needs root to
   create the `utun` interface and routes). The status flips to **● Connected**
   with your overlay IP, and **Peers** updates live.
4. **Disconnect** stops it. **Open log** opens `~/.apgo/overlay-client.log`.

To let this Mac be managed by the admin dashboard's network revocations, launch
the app with `ADMIN_PUBLIC_KEY` set (same value as the fleet) before Connect,
e.g. `ADMIN_PUBLIC_KEY=... open -a APGO`.

## How it works

- Config, node key, control socket, and log all live under `~/.apgo/`.
- **Connect** launches the bundled `overlay-client` as root via
  `osascript … with administrator privileges`, writing a PID file; **Disconnect**
  kills it. No preinstalled privileged helper is required.
- The menu polls the client's unix **control socket** (`~/.apgo/control.sock`,
  the same API the web dashboard uses) for overlay IP and peer count.
- **Settings…** opens a single one-page form in your browser, served from a
  localhost-only, single-use endpoint (a menu-bar dropdown can't host text
  fields). All fields are on one window and the PSK is a password box with a
  Show toggle. The little server shuts down after you Save.

## Notes / not-yet

- The app is unsigned; for distribution you'd code-sign and notarize it.
- Connect/Disconnect via `osascript` prompts for a password each time. A
  persistent `launchd` privileged helper (no repeated prompts, auto-start on
  login) is a natural follow-up.
- This depends on the Stage 1 data plane working on your Mac first — verify with
  `docs/macos.md` before wiring up the app.
