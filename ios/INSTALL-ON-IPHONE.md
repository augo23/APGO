# Getting APGO onto your personal iPhone

This walks you from a fresh Mac to the app running on your own iPhone. Plan for
about an hour the first time, most of it waiting on downloads.

## The one thing to know first: you need a **paid** Apple Developer account

APGO is a VPN. On iOS, VPNs are built with the **Network Extension**
(Packet Tunnel Provider) capability, and Apple only grants that entitlement to
members of the **Apple Developer Program ($99/year)**.

A *free* Apple ID can sideload ordinary apps to your own device, but it **cannot**
use the Packet Tunnel entitlement — the app will build but fail to start the VPN.
So for this app specifically, the $99/year membership is required. Enroll at
https://developer.apple.com/programs/ before you start (approval can take a few
hours to a day).

## What you need

- A Mac (Apple Silicon or Intel).
- **Xcode** from the Mac App Store (this is the big download, ~7–15 GB — start it
  first). The Command Line Tools alone are not enough to build an app.
- Your iPhone + its USB cable.
- A paid Apple Developer account (above).

## Step 1 — Build the Go framework (installs everything else for you)

Open Terminal and run:

```
cd /path/to/P2P-Overlay-Network/ios
bash build-xcframework.sh
```

This script installs Homebrew, Go, XcodeGen, and gomobile if they're missing,
then produces `ios/Overlaymobile.xcframework`. Re-run it any time; it skips
whatever is already installed.

(If it prints "Finish the Command Line Tools installer, then re-run" — do that
and run it again.)

## Step 2 — Generate and open the Xcode project

```
cd /path/to/P2P-Overlay-Network/ios
xcodegen generate && open APGO.xcodeproj
```

## Step 3 — Sign in and set your Team

1. In Xcode: **Settings → Accounts → +** and sign in with the Apple ID that has
   your paid Developer membership.
2. In the project navigator click the **APGO** project, then:
   - Select the **APGO** target → **Signing & Capabilities** → check
     **Automatically manage signing** → pick your **Team**.
   - Select the **APGOTunnel** target → do the same (same Team).
3. If Xcode complains the bundle IDs are taken, change the prefix on both targets
   to something unique to you, e.g. `com.yourname.APGO` and
   `com.yourname.APGO.Tunnel`. Keep the tunnel ID as the app ID + `.Tunnel`, and
   update the App Group on both to match (see note below).

## Step 4 — Plug in your iPhone and run

1. Connect the iPhone by cable. The first time, tap **Trust** on the phone.
2. In Xcode's top toolbar, choose your iPhone as the run destination (next to the
   APGO scheme).
3. Press **▶ (Run)**.
4. On the iPhone the first launch is blocked by "Untrusted Developer." Go to
   **Settings → General → VPN & Device Management → [your Apple ID] → Trust**.
5. Launch APGO, enter your network name + PSK, pick the last octet of your
   overlay IP, and tap **Connect**. iOS shows a one-time "APGO would like to add
   VPN configurations" prompt — allow it.

## Step 5 — Use it

Once connected, the phone can reach your other APGO nodes on the overlay subnet
(e.g. ping `10.22.55.x`). Use the **same network name and PSK** as your other
nodes, and a **unique last octet** so no two devices share an overlay IP. If
you've set an admin key anywhere on the network, the phone picks it up
automatically over the tunnel.

## Notes & gotchas

- **App Group:** the app and its tunnel extension share settings through an App
  Group (`group.org.apgo.APGO` in the entitlements). If you changed the bundle
  prefix, change the group to `group.<your prefix>.APGO` in **both**
  `App/APGO.entitlements` and `Tunnel/APGOTunnel.entitlements`, and add that same
  App Group under Signing & Capabilities on both targets.
- **Simulator won't work** — the packet tunnel only runs on a real device.
- **Provisioning takes a moment** — the first build registers your device and app
  IDs with Apple automatically; if it fails, wait a minute and build again.
- **7-day limit (free accounts only):** doesn't apply to you with a paid
  membership — your build stays valid for a year.
- **PSK format:** enter it as `base64:...` (generate one with
  `openssl rand -base64 32` and prefix it with `base64:`), matching your other
  nodes exactly.
- **Battery:** a running VPN keeps the radio active. Disconnect when you don't
  need the overlay.

## TestFlight (optional, later)

To install without a cable or share with others, archive the app
(**Product → Archive**) and upload to **TestFlight** via App Store Connect. That
needs the same paid account and an App Store Connect app record, but then you
install through the TestFlight app instead of Xcode.
