import SwiftUI
import UIKit
import NetworkExtension

/// ContentView is the main screen: connection control and the full-VPN toggle
/// at the top, then the live peers list, with a Support button at the bottom.
/// Everything configuration-related (network name, PSK, this device's overlay
/// address, post-quantum, IPv6) lives behind the gear icon in SettingsView, so
/// once you're joined the main screen never shows your name/PSK again.
struct ContentView: View {
    @StateObject private var tunnel = TunnelManager()
    @StateObject private var lanCheck = LocalNetworkChecker()
    @Environment(\.scenePhase) private var scenePhase
    // App lock — used only to close sheets when locking, so the lock cover
    // (which sits at the window's root) can never be under an open sheet
    // that shows the PSK or settings.
    @EnvironmentObject private var appLock: AppLock
    // Multi-network: all saved profiles + the selected one. `config` is the
    // working copy of the selected profile; every change is written back into
    // its slot and persisted (see .onChange below).
    @State private var networks: [OverlayConfig] = OverlayConfig.loadAll()
    @State private var selected: Int = OverlayConfig.loadSelectedIndex()
    @State private var config = OverlayConfig.load()   // persisted across launches
    @State private var octet: String = "30"
    @State private var showSettings = false
    @State private var showSupport = false
    @State private var peers: [Peer] = []
    @State private var exitsInfo: TunnelManager.ExitsView?
    @State private var netStatus: TunnelManager.NetStatus?
    /// Mirrors scenePhase == .background into @State so the long-lived poll
    /// task can read it (an @Environment value captured by that task would be
    /// frozen at its start-up value forever — see pollPeers).
    @State private var isBackgrounded = false

    private var isBusy: Bool {
        tunnel.status == .connecting || tunnel.status == .disconnecting || tunnel.status == .reasserting
    }
    private var isConnected: Bool { tunnel.status == .connected }
    private var configured: Bool { !config.networkName.isEmpty && !config.psk.isEmpty }

    var body: some View {
        NavigationStack {
            List {
                // --- Network switcher ------------------------------------------
                Section("Network") {
                    Menu {
                        ForEach(networks.indices, id: \.self) { i in
                            Button {
                                switchNetwork(to: i)
                            } label: {
                                if i == selected {
                                    Label(networks[i].displayName, systemImage: "checkmark")
                                } else {
                                    Text(networks[i].displayName)
                                }
                            }
                        }
                        Divider()
                        Button { addNetwork() } label: {
                            Label("Add network…", systemImage: "plus")
                        }
                    } label: {
                        HStack {
                            Image(systemName: "network")
                            Text(config.displayName)
                                .foregroundStyle(.primary)
                            Spacer()
                            Image(systemName: "chevron.up.chevron.down")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }

                // --- Connection (top of everything) ---------------------------
                Section {
                    HStack {
                        Circle()
                            .fill(isConnected ? .green : (isBusy ? .yellow : .gray))
                            .frame(width: 10, height: 10)
                        Text(tunnel.status.label)
                        Spacer()
                        if isConnected, !config.overlayIP.isEmpty {
                            Text(config.overlayIP)
                                .font(.footnote.monospaced())
                                .foregroundStyle(.secondary)
                        }
                    }
                    if isConnected {
                        Button(role: .destructive) { tunnel.disconnect() } label: {
                            Text("Disconnect").frame(maxWidth: .infinity)
                        }
                    } else {
                        Button {
                            if configured {
                                // Make iOS show the Local Network permission
                                // prompt (the tunnel extension can't) — without
                                // it, peers on the same Wi-Fi are unreachable.
                                lanCheck.check()
                                config.applyLastOctet(octet)
                                Task { await tunnel.connect(config: config) }
                            } else {
                                showSettings = true
                            }
                        } label: {
                            Text(configured ? "Connect" : "Set up your network…")
                                .frame(maxWidth: .infinity)
                        }
                        .disabled(isBusy)
                    }
                    if let err = tunnel.lastError {
                        Text(err).font(.footnote).foregroundStyle(.red)
                    }
                }

                // --- Local Network permission warning --------------------------
                // iOS silently drops the tunnel's LAN traffic when this
                // permission is off, so same-Wi-Fi peers "randomly" never
                // appear. Make the failure visible and one tap to fix.
                if lanCheck.status == .denied {
                    Section {
                        Label("Local Network access is off — devices on the same Wi‑Fi can't be found. They'll still connect over the internet.",
                              systemImage: "wifi.exclamationmark")
                            .font(.footnote)
                            .foregroundStyle(.orange)
                        Button("Enable in Settings") {
                            if let url = URL(string: UIApplication.openSettingsURLString) {
                                UIApplication.shared.open(url)
                            }
                        }
                    }
                }

                // --- Full VPN -------------------------------------------------
                Section("Full VPN") {
                    Toggle("Route all traffic via an exit node", isOn: $config.useExit)
                        // The tunnel only reads its config at start, so a live
                        // toggle must restart it — otherwise it silently does
                        // nothing until the next manual reconnect.
                        .onChange(of: config.useExit) { _ in
                            if isConnected || isBusy {
                                Task { await tunnel.reconnect(config: config) }
                            }
                        }
                    if config.useExit {
                        TextField("Exit node (blank = fastest)", text: $config.exitPeer)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .onSubmit {
                                if isConnected || isBusy {
                                    Task { await tunnel.reconnect(config: config) }
                                }
                            }
                    }
                    Text(config.useExit
                         ? "All internet traffic egresses via an exit node on your mesh. Needs at least one device with exit-node mode enabled (a Linux server or a Mac — phones can't be exits). Exit-capable devices show a green E in the peer list."
                         : "Off: only overlay traffic is tunneled.")
                        .font(.footnote).foregroundStyle(.secondary)
                    // Full VPN captures ALL traffic, so until an exit is
                    // selected the internet is deliberately paused (fail-closed,
                    // no leaks). Show the live outproxy state from the core so
                    // this is diagnosable on the device instead of a dead end.
                    if config.useExit && isConnected {
                        if let sel = exitsInfo?.exits.first(where: { $0.selected }) {
                            Label("Exit: \(sel.name.isEmpty ? sel.overlayIP : sel.name)" +
                                  (sel.rttMs >= 0 ? " · \(sel.rttMs) ms" : ""),
                                  systemImage: "checkmark.circle.fill")
                                .font(.footnote)
                                .foregroundStyle(.green)
                        } else {
                            Label(peers.contains(where: { $0.isExit })
                                  ? "Connecting to an exit node… internet is paused until one is selected."
                                  : "No exit node is reachable — internet is paused. Enable exit-node mode on a Linux, macOS, or Windows node on this mesh (green E), or turn Full VPN off.",
                                  systemImage: "exclamationmark.triangle.fill")
                                .font(.footnote)
                                .foregroundStyle(.orange)
                            if let ex = exitsInfo {
                                Text(ex.exits.isEmpty
                                     ? "Diagnostics: no exit announcement has reached this device. The exit must show “exit-node mode ON” in its log AND have a direct (green-dot) session to this phone — a relayed exit can't carry traffic."
                                     : "Diagnostics: known exits — " + ex.exits.map {
                                           ($0.name.isEmpty ? $0.overlayIP : $0.name) +
                                           ($0.reachable ? "" : " (unreachable)")
                                       }.joined(separator: ", ") +
                                       (ex.pin.isEmpty ? "" : " · pinned to “\(ex.pin)” — the pin must match the exit's name, IP, or fingerprint exactly"))
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }

                // --- Peers ----------------------------------------------------
                Section {
                    // WHY ARE MY PEERS RELAYED? This device's NAT type is the
                    // fact that answers it, and the phone was the only device
                    // that never showed it. Two symmetric NATs have no
                    // predictable port on either side, so that pair can NEVER
                    // punch — it is permanently relayed and no setting changes
                    // that. Carrier CGNAT is routinely symmetric, which is why
                    // a phone can behave differently from a laptop beside it.
                    if isConnected, let ns = netStatus, !ns.natType.isEmpty {
                        let symmetric = ns.natType.lowercased().contains("symmetric")
                        HStack(alignment: .top, spacing: 8) {
                            Image(systemName: symmetric ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                                .foregroundStyle(symmetric ? .orange : .green)
                            VStack(alignment: .leading, spacing: 2) {
                                Text("This device's NAT: \(ns.natType)")
                                    .font(.footnote.weight(.semibold))
                                Text(symmetric
                                     ? "A symmetric NAT gives this device no predictable port, so peers that are ALSO behind one can never connect directly — those stay relayed (still encrypted, just one extra hop). Wi-Fi is usually better than cellular here."
                                     : "Peers can punch directly to this device when their own network allows it.")
                                    .font(.caption2).foregroundStyle(.secondary)
                                if !ns.publicEndpoint.isEmpty {
                                    Text("Reachable at \(ns.publicEndpoint)")
                                        .font(.caption2.monospaced()).foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                    if !isConnected {
                        Text("Connect to see peers.")
                            .font(.footnote).foregroundStyle(.secondary)
                    } else if peers.isEmpty {
                        Text("No peers yet — discovering…")
                            .font(.footnote).foregroundStyle(.secondary)
                    } else {
                        ForEach(peers) { p in
                            HStack(spacing: 10) {
                                Circle()
                                    .fill(p.established ? .green : (p.relayed ? .blue : .orange))
                                    .frame(width: 8, height: 8)
                                VStack(alignment: .leading, spacing: 2) {
                                    // A key-DERIVED address is a guess: the peer
                                    // has not announced one yet. Showing it in
                                    // the same weight as a confirmed address is
                                    // what makes peers look like they have "the
                                    // wrong IP" — mark it instead of hiding it,
                                    // since it is usually right and always the
                                    // address that peer would default to.
                                    HStack(spacing: 4) {
                                        Text(p.overlayIP.isEmpty ? p.keyFP : p.overlayIP)
                                            .font(.body.monospaced())
                                            .foregroundStyle(p.ipDerived ? .secondary : .primary)
                                        if p.ipDerived {
                                            Text("?")
                                                .font(.caption2.weight(.bold))
                                                .foregroundStyle(.orange)
                                                .accessibilityLabel("Address not yet confirmed by this peer")
                                        }
                                    }
                                    if !p.name.isEmpty {
                                        Text(p.name).font(.caption).foregroundStyle(.secondary)
                                    }
                                    if p.relayed {
                                        Text("via \(p.via.isEmpty ? "mesh" : p.via)")
                                            .font(.caption2).foregroundStyle(.secondary)
                                    }
                                }
                                Spacer()
                                // Exit badges. Green "E" = this device can be an
                                // exit node for the VPN relay; the solid badge =
                                // the exit THIS device's internet traffic
                                // currently egresses through (full VPN).
                                if p.activeExit {
                                    Label("Exit", systemImage: "globe.americas.fill")
                                        .labelStyle(.titleAndIcon)
                                        .font(.caption2.weight(.semibold))
                                        .foregroundStyle(.blue)
                                        .padding(.horizontal, 6).padding(.vertical, 2)
                                        .background(.blue.opacity(0.12), in: Capsule())
                                }
                                if p.isExit {
                                    Text("E")
                                        .font(.caption2.weight(.bold))
                                        .foregroundStyle(.green)
                                        .padding(.horizontal, 5).padding(.vertical, 1)
                                        .background(.green.opacity(0.15), in: Capsule())
                                        .accessibilityLabel("Can be an exit node")
                                }
                                // Relay badge: reachable through another node
                                // rather than a direct session (traffic still
                                // works — this device just has no direct path,
                                // e.g. a same-Wi-Fi peer behind AP isolation).
                                if p.relayed {
                                    Label("Relay", systemImage: "arrow.triangle.branch")
                                        .labelStyle(.titleAndIcon)
                                        .font(.caption2.weight(.semibold))
                                        .foregroundStyle(.blue)
                                        .padding(.horizontal, 6).padding(.vertical, 2)
                                        .background(.blue.opacity(0.12), in: Capsule())
                                }
                                if p.postQuantum {
                                    Image(systemName: "lock.shield")
                                        .font(.caption).foregroundStyle(.green)
                                }
                                Text(p.lastSeenText)
                                    .font(.caption2).foregroundStyle(.secondary)
                            }
                        }
                    }
                } header: {
                    Text("Peers (\(peers.count))")
                }

                // --- Support (bottom) ------------------------------------------
                Section(footer:
                    Text("© 2026 The APGO Team · Another Pretty Good Overlay\nFree & open source, GPL-3.0-or-later")
                        .font(.caption2)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: .infinity)
                ) {
                    Button { showSupport = true } label: {
                        Label("Support APGO", systemImage: "heart")
                            .frame(maxWidth: .infinity)
                    }
                }
            }
            .navigationTitle("APGO")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button { showSettings = true } label: {
                        Image(systemName: "gearshape")
                    }
                }
            }
            .sheet(isPresented: $showSettings) {
                SettingsView(config: $config, octet: $octet, onDelete: deleteCurrentNetwork)
            }
            .sheet(isPresented: $showSupport) { SupportView() }
        }
        .onAppear {
            // Clamp the persisted selection, load its config, and recover the
            // last-octet field from the saved overlay IP.
            selected = min(max(0, selected), networks.count - 1)
            config = networks[selected]
            if let last = config.overlayIP.split(separator: ".").last { octet = String(last) }
            config.applyLastOctet(octet)
            // Trigger/verify Local Network permission right at launch, not
            // just on Connect — so the warning row is accurate immediately.
            lanCheck.check()
        }
        // Re-check when returning from Settings (the user may have just
        // flipped the Local Network toggle for APGO).
        .onChange(of: scenePhase) { phase in
            isBackgrounded = (phase == .background)
            if phase == .active { lanCheck.check() }
        }
        // Close any open sheet the moment the app locks — sheets present above
        // the window root, so they would otherwise stay visible over the lock.
        .onChange(of: appLock.isLocked) { locked in
            if locked {
                showSettings = false
                showSupport = false
            }
        }
        // React to connection-state changes IMMEDIATELY instead of waiting for
        // the next poll tick: clear the list the instant we drop, and pull a
        // fresh snapshot the instant we connect. Without this the peers section
        // (and the "Peers (N)" count) lagged the actual connection by up to a
        // full poll interval — the "UI doesn't update the connection in time"
        // symptom.
        .onChange(of: tunnel.status) { newStatus in
            if newStatus == .connected {
                Task { await refreshPeers() }
            } else if newStatus != .reasserting {
                peers = []
            }
        }
        // Persist every change into the selected profile's slot so a network
        // drop or relaunch never loses the scanned QR / settings.
        .onChange(of: config) { _ in
            guard networks.indices.contains(selected) else { return }
            networks[selected] = config
            OverlayConfig.saveAll(networks)
        }
        .task { await pollPeers() }
    }

    /// Switch the active network profile. Disconnects first — the tunnel keeps
    /// running the OLD network otherwise, which would silently mismatch the UI.
    private func switchNetwork(to i: Int) {
        guard networks.indices.contains(i), i != selected else { return }
        if isConnected || isBusy { tunnel.disconnect() }
        networks[selected] = config          // keep any unsaved edits
        selected = i
        OverlayConfig.saveSelectedIndex(i)
        config = networks[i]
        if let last = config.overlayIP.split(separator: ".").last { octet = String(last) }
        config.applyLastOctet(octet)
        OverlayConfig.saveAll(networks)
    }

    /// Create a blank profile, select it, and open Settings to fill it in.
    private func addNetwork() {
        if isConnected || isBusy { tunnel.disconnect() }
        networks[selected] = config
        networks.append(OverlayConfig())
        selected = networks.count - 1
        OverlayConfig.saveSelectedIndex(selected)
        config = networks[selected]
        octet = "30"
        OverlayConfig.saveAll(networks)
        showSettings = true
    }

    /// Delete the selected profile (the last one is reset to blank instead, so
    /// there is always at least one network).
    private func deleteCurrentNetwork() {
        if isConnected || isBusy { tunnel.disconnect() }
        // Forget must be COMPLETE: also wipe the extension-side overlay state
        // (node key, stale admin-assigned IP provisions, admin key material) on
        // the next connect, or rejoining this network announces a stale
        // provisioned IP and the device never receives traffic.
        OverlayConfig.requestStateWipe()
        if networks.count > 1 {
            networks.remove(at: selected)
            selected = min(selected, networks.count - 1)
        } else {
            networks[0] = OverlayConfig()
            selected = 0
        }
        OverlayConfig.saveSelectedIndex(selected)
        config = networks[selected]
        if let last = config.overlayIP.split(separator: ".").last { octet = String(last) }
        OverlayConfig.saveAll(networks)
    }

    /// Poll the tunnel extension for the peer list every few seconds while
    /// connected; clear it when not. Sorted by overlay IP (low→high) so rows
    /// keep a stable position instead of jumping around between refreshes.
    /// Also polls for an admin-assigned overlay address (a signed provision
    /// from the network admin panel): the extension can't re-address the OS
    /// tunnel itself, so when one is pending the app adopts it — update the
    /// stored config and reconnect. Without this, renaming/re-addressing an
    /// iOS device from the admin dashboard was silently ignored.
    private func pollPeers() async {
        // Poll count since the view became active, used to slow down once the
        // picture has stopped changing.
        var tick = 0
        while !Task.isCancelled {
            // BATTERY: don't poll while the app is in the background. The
            // view is not torn down there, so without this the app kept
            // waking every 1.5s to run cross-process IPC (sendProviderMessage
            // into the tunnel extension) to refresh a list nobody is looking
            // at. The tunnel itself is unaffected — it runs in the extension.
            //
            // Read @State, NOT @Environment(\.scenePhase), and gate on
            // BACKGROUND rather than "not active". Both details are load
            // bearing:
            //
            //  * This closure captures the View STRUCT that existed when
            //    .task started. @Environment values are resolved at view
            //    creation, so `scenePhase` read in here is frozen at whatever
            //    it was then — and at first appearance that is routinely
            //    .inactive. Gating on it meant the loop parked forever and
            //    the peer list stayed EMPTY for the whole session while the
            //    tunnel worked fine. @State is a reference to external
            //    storage, so reads through the captured struct see current
            //    values.
            //  * .inactive is a transient state (app switcher, notification
            //    shade, permission alert). Pausing on it buys nothing and
            //    risks exactly the class of bug above, so only .background
            //    stops the loop.
            guard !isBackgrounded else {
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                tick = 0   // resume at the fast rate when the user comes back
                continue
            }
            if isConnected {
                await refreshPeers()
                await adoptPendingAddressIfAny()
                // Exit diagnostics only matter (and only render) in full-VPN mode.
                exitsInfo = config.useExit ? await tunnel.fetchExits() : nil
                // Cheap and slow-changing; refresh it every few polls only.
                if tick % 5 == 0 || netStatus == nil { netStatus = await tunnel.fetchNetStatus() }
            } else {
                peers = []
                exitsInfo = nil
                netStatus = nil
            }
            tick += 1
            // On-screen cadence. 1.5s while the mesh is forming, then 2s —
            // NOT the 5s tried earlier: this list is the app's only feedback
            // that anything is happening, and at 5s it reads as frozen while
            // peers appear, change address and go direct. The saving was
            // measured against foreground IPC, which is not where phone
            // battery goes; the real wins were background polling (off
            // entirely) and the core's own radio traffic.
            let interval: UInt64 = tick <= 20 ? 1_500_000_000 : 2_000_000_000
            try? await Task.sleep(nanoseconds: interval)
        }
    }

    /// Pull one peer snapshot from the tunnel extension. A nil result is a
    /// transient IPC failure — keep whatever we last showed rather than blanking
    /// the list; a non-nil result (including an empty array) is authoritative.
    private func refreshPeers() async {
        guard isConnected else { peers = []; return }
        if let fetched = await tunnel.fetchPeers() {
            peers = fetched.sorted { ipSortKey($0.overlayIP) < ipSortKey($1.overlayIP) }
        }
    }

    /// Adopt an admin-assigned overlay address if one is pending. The extension's
    /// Go core can't re-address the OS tunnel itself, so we update the stored
    /// config and reconnect. Guard on a well-formed, DIFFERENT IPv4 so a stale or
    /// malformed pending value can never drive a reconnect loop.
    private func adoptPendingAddressIfAny() async {
        let pending = await tunnel.fetchPendingAddress()
        // Pending arrives as "10.22.55.42" or "10.22.55.42/24".
        let newIP = pending.split(separator: "/").first.map(String.init) ?? ""
        guard isValidIPv4(newIP), newIP != config.overlayIP else { return }
        config.overlayIP = newIP
        if let last = newIP.split(separator: ".").last { octet = String(last) }
        // .onChange(of: config) persists the profile; reconnect so the OS tunnel
        // (NEIPv4Settings) picks up the new address.
        await tunnel.reconnect(config: config)
    }

    /// True for a syntactically valid dotted-quad IPv4 address.
    private func isValidIPv4(_ s: String) -> Bool {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return false }
        return parts.allSatisfy { p in
            if let v = UInt(p), v <= 255, String(v) == p { return true }
            return false
        }
    }

    /// Numeric sort key for an IPv4 string; non-IPs sort last.
    private func ipSortKey(_ ip: String) -> UInt32 {
        let p = ip.split(separator: ".").compactMap { UInt32($0) }
        guard p.count == 4 else { return UInt32.max }
        return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]
    }
}

#Preview { ContentView().environmentObject(AppLock()) }
