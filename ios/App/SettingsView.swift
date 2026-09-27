import SwiftUI

/// SettingsView holds everything that isn't day-to-day connection control:
/// the network identity (name / PSK / device name), this node's overlay
/// address, and the security/transport toggles. Presented as a sheet from the
/// gear icon on the main screen. Editing binds straight back to the shared
/// OverlayConfig, so changes are picked up on the next Connect.
struct SettingsView: View {
    @Binding var config: OverlayConfig
    @Binding var octet: String
    /// Deletes the current network profile (multi-network switcher).
    var onDelete: (() -> Void)? = nil
    /// Restart a LIVE tunnel so a changed log level takes effect now. The
    /// providerConfiguration is only read at startTunnel, so without this a
    /// toggle flipped while connected captures nothing until the next manual
    /// reconnect — and an empty log is indistinguishable from a broken one.
    var onLogLevelChange: (() -> Void)? = nil
    @Environment(\.dismiss) private var dismiss
    /// App lock (Face ID / Touch ID) — injected from APGOApp.
    @EnvironmentObject private var appLock: AppLock

    @State private var showScanner = false
    @State private var scanError: String?
    @State private var confirmDelete = false

    // Diagnostics. The export is a merged COPY of both log generations, built
    // off the main actor because it can be several megabytes; the Send row
    // appears once it's ready.
    @State private var logBytes: Int64 = 0
    @State private var logExportURL: URL?
    @State private var confirmClearLog = false

    // Tracker editor state. Displayed/edited in the trackers.txt format: one
    // tracker per line, separated by one blank line. Parsed tolerantly (any
    // blank lines are skipped), committed back to config on Done/dismiss.
    // Committed only when the text differs from what was loaded — .onChange
    // also fires for our own programmatic load, so a dirty flag would mark the
    // list user-edited just for opening Settings.
    @State private var trackersText = ""
    @State private var trackersLoadedText = ""

    var body: some View {
        NavigationStack {
            Form {
                Section("Network") {
                    Button {
                        showScanner = true
                    } label: {
                        Label("Scan QR to join", systemImage: "qrcode.viewfinder")
                    }
                    TextField("Network name", text: $config.networkName)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    SecureField("Pre-shared key (base64:…)", text: $config.psk)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    TextField("This device's name (optional)", text: $config.friendlyName)
                        .autocorrectionDisabled()
                    if let e = scanError {
                        Text(e).font(.footnote).foregroundStyle(.red)
                    }
                    Text("Use the same network name and PSK on every device.")
                        .font(.footnote).foregroundStyle(.secondary)
                }

                Section("Overlay address") {
                    HStack {
                        Text(config.subnetPrefix())
                            .foregroundStyle(.secondary)
                        TextField("last octet", text: $octet)
                            .keyboardType(.numberPad)
                            .onChange(of: octet) { _ in config.applyLastOctet(octet) }
                            .frame(width: 70)
                    }
                    TextField("Subnet CIDR", text: $config.overlayCIDR)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .onChange(of: config.overlayCIDR) { _ in config.applyLastOctet(octet) }
                    Text("This device's address on the overlay. Blank last octet auto-assigns.")
                        .font(.footnote).foregroundStyle(.secondary)
                }

                Section("Security") {
                    Toggle("Post-quantum encryption", isOn: $config.postQuantum)
                    Text("Adds a hybrid ML-KEM-768 layer (protects against future quantum computers). Slightly slower; enable it on every device.")
                        .font(.footnote).foregroundStyle(.secondary)
                    Toggle(isOn: Binding(
                        get: { appLock.enabled },
                        set: { on in Task { await appLock.setEnabled(on) } }
                    )) {
                        Label("Require \(AppLock.biometryLabel)", systemImage: AppLock.biometrySymbol)
                    }
                    .disabled(!AppLock.available)
                    Text(AppLock.available
                         ? "Locks the app (settings, PSK, and peer list) behind \(AppLock.biometryLabel) when you leave it. The VPN itself keeps running while locked."
                         : "Set up Face ID, Touch ID, or a passcode on this device to use the app lock.")
                        .font(.footnote).foregroundStyle(.secondary)
                }

                Section("Transport") {
                    Toggle("IPv6 dual-stack", isOn: $config.ipv6)
                    Text("Connects directly over IPv6 where available (no NAT) — fixes hotspot/CGNAT reachability. The overlay stays IPv4. Reconnect to apply.")
                        .font(.footnote).foregroundStyle(.secondary)
                }

                Section("Trackers") {
                    TextEditor(text: $trackersText)
                        .font(.footnote.monospaced())
                        .frame(minHeight: 180)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                    Button("Reset to defaults") {
                        trackersText = OverlayConfig.defaultTrackers.joined(separator: "\n\n")
                    }
                    Text("These help nodes discover each other. One tracker per line, separated by one blank line — edit the box to add or remove them (same list as the desktop app's tracker manager). Reconnect to apply.")
                        .font(.footnote).foregroundStyle(.secondary)
                }

                Section("Diagnostics") {
                    Picker("Log capture", selection: Binding(
                        get: { config.logLevel ?? 0 },
                        set: { newLevel in
                            guard newLevel != (config.logLevel ?? 0) else { return }
                            config.logLevel = newLevel
                            onLogLevelChange?()
                            refreshLogState()
                        }
                    )) {
                        Text("Off").tag(0)
                        Text("Normal").tag(1)
                        Text("Verbose").tag(2)
                    }

                    if OverlayConfig.logDirectoryURL == nil {
                        // The App Group in OverlayConfig.appGroupID doesn't
                        // match this build's entitlements, so the app and the
                        // tunnel extension have no shared folder to hand a log
                        // through. Say so: otherwise capture looks enabled and
                        // silently produces an empty file forever.
                        Label("App Group \(OverlayConfig.appGroupID) is unavailable \u{2014} logging can't be stored. Check the entitlements on both targets.",
                              systemImage: "exclamationmark.triangle")
                            .font(.footnote)
                            .foregroundStyle(.red)
                    }

                    HStack {
                        Text("Captured")
                        Spacer()
                        Text(logSizeLabel).foregroundStyle(.secondary)
                    }

                    if let url = logExportURL {
                        ShareLink(item: url) {
                            Label("Send log\u{2026}", systemImage: "square.and.arrow.up")
                        }
                        Button("Clear log", role: .destructive) { confirmClearLog = true }
                    }

                    Text("Records what the overlay core is doing \u{2014} NAT classification, hole-punch attempts, and why a peer ends up relayed \u{2014} to a file you can send from here. Normal skips the repeating handshake-retry lines; Verbose keeps everything. Capture keeps up to 8 MB and discards the oldest. Changing this reconnects the tunnel.")
                        .font(.footnote).foregroundStyle(.secondary)
                }

                if onDelete != nil {
                    Section {
                        Button("Delete this network", role: .destructive) {
                            confirmDelete = true
                        }
                        Text("Removes \"\(config.displayName)\" from this device. Other devices on the network are unaffected.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                }
            }
            .confirmationDialog("Clear the captured log?",
                                isPresented: $confirmClearLog,
                                titleVisibility: .visible) {
                Button("Clear log", role: .destructive) {
                    OverlayConfig.clearLogs()
                    refreshLogState()
                }
                Button("Cancel", role: .cancel) {}
            }
            .confirmationDialog("Delete \"\(config.displayName)\"?",
                                isPresented: $confirmDelete,
                                titleVisibility: .visible) {
                Button("Delete network", role: .destructive) {
                    onDelete?()
                    dismiss()
                }
                Button("Cancel", role: .cancel) {}
            }
            .phoneWidthLayout()
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") {
                        config.applyLastOctet(octet)
                        commitTrackers()
                        dismiss()
                    }
                }
            }
            .sheet(isPresented: $showScanner) {
                QRScannerView { code in applyScannedCode(code) }
                    .ignoresSafeArea()
            }
            .onAppear {
                // Show the user's list, or the effective defaults if untouched.
                let list = config.trackers.isEmpty && config.trackersEdited != true
                    ? OverlayConfig.defaultTrackers
                    : config.trackers
                trackersText = list.joined(separator: "\n\n")
                trackersLoadedText = trackersText
                refreshLogState()
            }
            .onDisappear { commitTrackers() }   // swipe-down dismiss too
        }
    }

    private var logSizeLabel: String {
        guard logBytes > 0 else { return "nothing yet" }
        return ByteCountFormatter.string(fromByteCount: logBytes, countStyle: .file)
    }

    /// Re-read the captured size and rebuild the shareable copy. The merge
    /// runs off the main actor: it can be several megabytes, and doing it in
    /// the Picker's setter would hitch the toggle.
    private func refreshLogState() {
        logBytes = OverlayConfig.logSizeBytes()
        guard logBytes > 0 else {
            logExportURL = nil
            return
        }
        Task {
            let url = await Task.detached(priority: .utility) {
                OverlayConfig.exportLog()
            }.value
            logExportURL = url
        }
    }

    /// Parse the editor text (skip blanks, trim, dedupe) back into the config.
    /// Only marks the list as user-managed if the user actually changed it, so
    /// merely opening Settings never freezes the defaults.
    private func commitTrackers() {
        guard trackersText != trackersLoadedText else { return }
        var seen = Set<String>()
        let list = trackersText
            .split(separator: "\n", omittingEmptySubsequences: true)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && seen.insert($0).inserted }
        config.trackers = list
        config.trackersEdited = true
        trackersLoadedText = trackersText
    }

    /// Fill the form from a scanned "join QR" (admin panel → Join QR).
    private func applyScannedCode(_ code: String) {
        guard let jc = JoinCode.parse(code) else {
            scanError = "That QR isn't an APGO join code."
            return
        }
        scanError = nil
        config.networkName = jc.network_name
        config.psk = jc.psk
        if let cidr = jc.overlay_cidr, !cidr.isEmpty { config.overlayCIDR = cidr }
        config.rendezvousServers = jc.rendezvous_servers ?? []
        // Adopt this network's trackers (incl. any private tracker); the core
        // still unions in its curated defaults on top.
        if let t = jc.trackers, !t.isEmpty { config.trackers = t }
        // Adopt the network's crypto profile — absent fields default to quantum-safe ON.
        if let c = jc.cipher, !c.isEmpty { config.cipher = c }
        config.postQuantum = jc.post_quantum ?? true
        config.pqAuth = jc.pq_auth ?? true
        // Pin the network's admin key (absent on QRs from older admin panels).
        if let fp = jc.admin_key_fp, !fp.isEmpty { config.adminKeyFP = fp } else { config.adminKeyFP = nil }
        config.applyLastOctet(octet)
    }
}
