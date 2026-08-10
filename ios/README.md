# APGO for iOS

A native iOS VPN client built on Apple's **NetworkExtension** (Packet Tunnel
Provider), driving the shared Go overlay core via the `mobile/` gomobile bridge.

> iOS cannot be built, signed, or run from a script — Apple requires **Xcode**,
> an **Apple Developer account** ($99/yr) for the NetworkExtension entitlement
> and code signing, and you install to a physical device via Xcode/TestFlight.
> This folder is the complete app source; you generate + sign it in Xcode.

## What's here (complete, self-contained app)

```
ios/
├── App/                        # the SwiftUI app target
│   ├── APGOApp.swift           #   @main entry
│   ├── ContentView.swift       #   config form: network, PSK, subnet-linked IP octet, Connect
│   ├── TunnelManager.swift     #   installs + starts/stops the VPN profile (NETunnelProviderManager)
│   ├── OverlayConfig.swift     #   config model -> JSON for the overlay core
│   ├── Info.plist
│   └── APGO.entitlements       #   packet-tunnel-provider + app group
├── Tunnel/                     # the Packet Tunnel Provider extension target
│   ├── PacketTunnelProvider.swift  # applies overlay IP/route, grabs utun fd, starts core
│   ├── Info.plist              #   principal class = PacketTunnelProvider
│   └── APGOTunnel.entitlements
├── core/                       # the FULL overlay core (vendored Go), gomobile-bound
│   ├── bridge.go               #   Start(fd, json) / Stop() — the gomobile entry point
│   ├── run.go                  #   runs the overlay over the injected tunnel fd
│   ├── overlay.go, sessions.go, control.go, revocation.go, ip_learning.go, bencode.go
│   └── go.mod / go.sum
├── project.yml                 # XcodeGen spec -> generates APGO.xcodeproj
└── build-xcframework.sh        # builds Overlaymobile.xcframework from ios/core
```

Everything the app needs is inside `ios/` — the Go overlay engine (Noise
handshake, sessions, tracker/STUN discovery, endpoint roaming, admin-key
seeding) is vendored into `ios/core` and driven directly by the tunnel fd, so
the app actually tunnels (no external module, no stub).

The UI mirrors the desktop client: enter the network name + PSK, pick the last
octet of the overlay IP (the subnet prefix autofills from the CIDR), Connect.
The extension applies the overlay IP/route, grabs the utun fd, and hands it to
the vendored Go core via `OverlaymobileStart(fd, json)`.

> When you run `gomobile bind`, it prints `skipping ... unsupported` warnings for
> the core's internal Go API (functions that take `*net.UDPConn`, `[32]byte`,
> etc.). That's expected and harmless — gomobile still exports `Start`, `Stop`,
> and `Running`, which is all the app calls.

## Build

1. Build the Go bindings (needs Go + gomobile — see `mobile/README.md`):
   ```
   cd ios && bash build-xcframework.sh
   ```
2. Generate the Xcode project (needs `brew install xcodegen`):
   ```
   xcodegen generate
   open APGO.xcodeproj
   ```
3. The **Team** (AUSTIN PAUL GOULD, `58ZSP5V9AC`) is set in `project.yml`, so
   both targets are signed automatically after every `xcodegen generate` — no
   manual selection needed. (Anyone else building this must change
   `DEVELOPMENT_TEAM` there to their own Team ID.) The
   entitlements + App Group (`group.org.apgo.APGO`) and the Packet Tunnel
   capability are already declared.
4. Run on a **physical device** (the tunnel does not run in the simulator).

> **Rebuild the xcframework after ANY change in `ios/core`** (step 1) — the
> Swift app links the prebuilt `Overlaymobile.xcframework`, not the Go sources.

## Same-Wi-Fi peers (Local Network permission)

iOS 14+ gates LAN traffic behind two separate mechanisms, and both matter for
finding a peer on the same Wi-Fi:

1. **Local Network permission** — the app triggers the system prompt on the
   first Connect (`LocalNetworkPrompt.swift`; the tunnel extension itself can
   never show it). If the user denied it, peers on the same Wi-Fi won't be
   found: Settings → Privacy & Security → Local Network → APGO.
2. **UDP broadcast** — blocked without Apple's restricted
   `com.apple.developer.networking.multicast` entitlement. The core therefore
   falls back to a **unicast LAN sweep** (probing each host on attached
   /24-or-smaller subnets with the discovery beacon), which iOS always allows.
   If you want instant broadcast discovery too, request the entitlement at
   <https://developer.apple.com/contact/request/networking-multicast>, then
   uncomment the key in both `.entitlements` files.

Note that networks with **AP/client isolation** (common on guest/public Wi-Fi)
block ALL device-to-device traffic — no app can discover peers there; those
peers still connect via trackers/relay like any remote node.

## Full VPN (exit node) checklist

"Route all traffic via an exit node" needs **at least one node on the mesh
running with `exit_node: true`** (a Linux server or desktop — phones can't be
exits). Without one, there is nowhere to send internet traffic and the phone
will appear offline while connected. Toggling it while connected now restarts
the tunnel automatically (the extension only reads config at start).

## How the core is wired

`ios/core` is a vendored copy of the overlay engine (from `client/`), with the
package renamed and the OS-specific TUN creation and `main()` removed. In their
place:

- `bridge.go` exposes `Start(fd, json)` / `Stop()` / `Running()` to Swift.
- `run.go` is the client's run loop with the tunnel **injected** (the OS owns the
  fd) instead of created, and shutdown driven by a stop channel instead of
  signals.

This keeps the desktop/Linux/Windows `client/` binaries completely untouched —
`ios/core` is an independent copy, so building the iOS app can't break them. The
tradeoff is that fixes to the overlay core need to be mirrored into `ios/core`
(re-copy `overlay.go`/`sessions.go`/etc. and re-run the package rename).

## What still requires your Mac

Only the parts Apple makes unavoidable: building `Overlaymobile.xcframework` with
`gomobile`, generating + signing the Xcode project with your Developer account,
and running on a device. There's no remaining Go wiring — the core is complete
and connected.
