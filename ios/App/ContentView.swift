import SwiftUI
import UIKit
import NetworkExtension

/// ContentView is the main screen: connection control and the full-VPN toggle
/// at the top, then the live peers list, with an APGO website link at the bottom.
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
    @State private var peers: [Peer] = []
    // Admission control state, refreshed on the same poll as the peer list.
    @State private var admission = TunnelManager.AdmissionStatus()
    @State private var approveTarget: Peer? = nil     // nil + showApprove = self
    @State private var showApprove = false
    @State private var approvePassword = ""
    @State private var approveError: String? = nil
    @State private var approveBusy = false

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
                         ? "All internet traffic egresses via an exit node on your mesh. Needs at least one device with exit-node mode enabled (a server or desktop — phones can't be exits)."
                         : "Off: only overlay traffic is tunneled.")
                        .font(.footnote).foregroundStyle(.secondary)
                }

                // --- Not approved on this network ------------------------------
                // The most misleading state the system has: peers accept our
                // control traffic, so this device shows up in their lists
                // looking healthy, while every packet of real data is dropped.
                // From here it presents as "connected but nothing works".
                if isConnected && admission.required && !admission.selfApproved {
                    Section {
                        VStack(alignment: .leading, spacing: 8) {
                            Label("This device is not approved", systemImage: "exclamationmark.triangle.fill")
                                .font(.subheadline.weight(.semibold))
                                .foregroundStyle(.orange)
                            Text("Peers show it as connected but discard all of its data, so nothing is reachable. Approve it from the admin panel of another node that holds the network admin key — a device cannot approve itself.")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        .padding(.vertical, 4)
                    }
                }

                // --- Peers ----------------------------------------------------
                Section("Peers (\(peers.count))") {
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
                                    Text(p.overlayIP.isEmpty ? p.keyFP : p.overlayIP)
                                        .font(.body.monospaced())
                                    if !p.name.isEmpty {
                                        Text(p.name).font(.caption).foregroundStyle(.secondary)
                                    }
                                    if p.relayed {
                                        Text("via \(p.via.isEmpty ? "mesh" : p.via)")
                                            .font(.caption2).foregroundStyle(.secondary)
                                    }
                                }
                                Spacer()
                                // Exit badge: solid globe = the exit THIS device's
                                // internet traffic currently egresses through
                                // (full VPN); faint globe = advertises as an exit.
                                if p.activeExit {
                                    Label("Exit", systemImage: "globe.americas.fill")
                                        .labelStyle(.titleAndIcon)
                                        .font(.caption2.weight(.semibold))
                                        .foregroundStyle(.blue)
                                        .padding(.horizontal, 6).padding(.vertical, 2)
                                        .background(.blue.opacity(0.12), in: Capsule())
                                } else if p.isExit {
                                    Image(systemName: "globe")
                                        .font(.caption).foregroundStyle(.secondary)
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
                                // Pending badge. Until now the phone could not
                                // even SEE that a peer was unapproved, let alone
                                // do anything about it.
                                if !p.approved && !p.pubkey.isEmpty {
                                    Text("pending")
                                        .font(.caption2.weight(.semibold))
                                        .foregroundStyle(.orange)
                                        .padding(.horizontal, 6).padding(.vertical, 2)
                                        .background(.orange.opacity(0.14), in: Capsule())
                                }
                                Text(p.lastSeenText)
                                    .font(.caption2).foregroundStyle(.secondary)
                            }
                            .contentShape(Rectangle())
                            .onTapGesture {
                                guard !p.approved, !p.pubkey.isEmpty, admission.canSign else { return }
                                approveTarget = p
                                approvePassword = ""
                                approveError = nil
                                showApprove = true
                            }
                            // Swipe works too, and is the gesture people expect
                            // in a SwiftUI list.
                            .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                                if !p.approved && !p.pubkey.isEmpty && admission.canSign {
                                    Button {
                                        approveTarget = p
                                        approvePassword = ""
                                        approveError = nil
                                        showApprove = true
                                    } label: {
                                        Label("Approve", systemImage: "checkmark.seal")
                                    }
                                    .tint(.green)
                                }
                            }
                        }
                    }
                }

                // --- Website (bottom) ------------------------------------------
                Section(footer:
                    Text("© 2026 The APGO Team · Another Pretty Good Overlay\nFree & open source, GPL-3.0-or-later")
                        .font(.caption2)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: .infinity)
                ) {
                    Link(destination: URL(string: "https://apgoverlay.com")!) {
                        Label("APGO website", systemImage: "globe")
                            .frame(maxWidth: .infinity)
                    }
                }
            }
            .phoneWidthLayout()
            .navigationTitle("APGO")
            .navigationBarTitleDisplayMode(.inline)
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
            .sheet(isPresented: $showApprove) {
                NavigationStack {
                    Form {
                        Section {
                            Text(approveTarget.map { p in
                                p.overlayIP.isEmpty ? p.keyFP : p.overlayIP
                            } ?? "\u{2014}")
                                .font(.body.monospaced())
                            if let n = approveTarget?.name, !n.isEmpty {
                                Text(n).font(.caption).foregroundStyle(.secondary)
                            }
                        } header: {
                            Text("Approve")
                        } footer: {
                            Text("Signs an approval with the network admin key and sends it to the mesh. Every node accepts it exactly as it would an approval made from the desktop or web dashboard.")
                        }

                        Section {
                            SecureField("Network admin password", text: $approvePassword)
                                .textContentType(.password)
                                .submitLabel(.go)
                                .onSubmit { Task { await submitApproval() } }
                            if let e = approveError {
                                Text(e).font(.caption).foregroundStyle(.red)
                            }
                        }
                    }
                    .navigationTitle("Approve device")
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbar {
                        ToolbarItem(placement: .cancellationAction) {
                            Button("Cancel") { showApprove = false; approveTarget = nil }
                        }
                        ToolbarItem(placement: .confirmationAction) {
                            Button("Approve") { Task { await submitApproval() } }
                                .disabled(approvePassword.isEmpty || approveBusy)
                        }
                    }
                }
                .presentationDetents([.medium])
            }
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
            if phase == .active { lanCheck.check() }
        }
        // Close any open sheet the moment the app locks — sheets present above
        // the window root, so they would otherwise stay visible over the lock.
        .onChange(of: appLock.isLocked) { locked in
            if locked {
                showSettings = false
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
        while !Task.isCancelled {
            if isConnected {
                await refreshPeers()
                await adoptPendingAddressIfAny()
            } else {
                peers = []
            }
            // 1.5s cadence: sessions form within a few seconds of connecting, so
            // a snappier poll makes new peers (and dropped ones) appear promptly
            // without meaningfully affecting battery — the peers query is a cheap
            // in-process snapshot in the tunnel extension.
            try? await Task.sleep(nanoseconds: 1_500_000_000)
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
        // Same cadence as the peer list: canSign flips to true on its own once
        // the sealed admin key gossips in, and the Approve button has to become
        // usable when it does without the user reopening anything.
        admission = await tunnel.fetchAdmission()
    }

    /// Sign the approval and report the outcome. Kept off the view body so the
    /// sheet stays declarative.
    private func submitApproval() async {
        // Only ever approves a SELECTED PEER. A node cannot approve itself —
        // an approval has to be issued by an admin on another device.
        guard let target = approveTarget?.pubkey, !target.isEmpty else {
            approveError = "No device selected."
            return
        }
        approveBusy = true
        defer { approveBusy = false }
        if let err = await tunnel.approve(pubkey: target, action: "approve",
                                          password: approvePassword) {
            approveError = err
            return
        }
        approvePassword = ""
        showApprove = false
        approveTarget = nil
        // Re-read immediately: the banner clearing is the confirmation that
        // actually matters, and waiting up to 1.5s for the next poll reads as
        // "did that work?".
        await refreshPeers()
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
