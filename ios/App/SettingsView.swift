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
    @Environment(\.dismiss) private var dismiss
    /// App lock (Face ID / Touch ID) — injected from APGOApp.
    @EnvironmentObject private var appLock: AppLock

    @State private var showScanner = false
    @State private var scanError: String?
    @State private var confirmDelete = false

    // Tracker editor state. Displayed/edited in the trackers.txt format: one
    // tracker per line, separated by one blank line. Parsed tolerantly (any
    // blank lines are skipped), committed back to config on Done/dismiss.
    // Committed only when the text differs from what was loaded — .onChange
    // also fires for our own programmatic load, so a dirty flag would mark the
    // list user-edited just for opening Settings.
    @State private var trackersText = ""
    @State private var trackersLoadedText = ""

    // Rendezvous editor state. The credential is stored as ONE string
    // ("user:pass" or a bare token) but edited as two fields, because a single
    // box that means two different things depending on whether it contains a
    // colon is a UI nobody can use correctly.
    @State private var rendezvousText = ""
    @State private var rendezvousUser = ""
    @State private var rendezvousPass = ""

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

                // Rendezvous: HTTPS discovery for networks that block
                // BitTorrent. Normally arrives via the join QR (servers AND
                // credential), but must be enterable by hand too — a phone
                // added without a QR, or a server whose password rotated.
                Section("Rendezvous servers") {
                    TextEditor(text: $rendezvousText)
                        .font(.footnote.monospaced())
                        .frame(minHeight: 60)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                    Text("One HTTPS URL per line, e.g. https://rv.example.com — used instead of (or alongside) trackers where BitTorrent is blocked.")
                        .font(.footnote).foregroundStyle(.secondary)

                    TextField("Username or token", text: $rendezvousUser)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                    SecureField("Password (leave blank if using a token)", text: $rendezvousPass)
                    Text("Only if your rendezvous server requires a credential. Enter a username AND password, or just a token in the first box. Sent over HTTPS.")
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
            .confirmationDialog("Delete \"\(config.displayName)\"?",
                                isPresented: $confirmDelete,
                                titleVisibility: .visible) {
                Button("Delete network", role: .destructive) {
                    onDelete?()
                    dismiss()
                }
                Button("Cancel", role: .cancel) {}
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") {
                        config.applyLastOctet(octet)
                        commitTrackers()
                        commitRendezvous()
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
                rendezvousText = config.rendezvousServers.joined(separator: "\n")
                // Split the stored credential back into the two fields.
                let cred = config.rendezvousAuth
                if let colon = cred.firstIndex(of: ":") {
                    rendezvousUser = String(cred[cred.startIndex..<colon])
                    rendezvousPass = String(cred[cred.index(after: colon)...])
                } else {
                    rendezvousUser = cred
                    rendezvousPass = ""
                }
            }
            .onDisappear { commitTrackers(); commitRendezvous() }   // swipe-down dismiss too
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

    /// Commit the rendezvous editor: one URL per line, and recombine the
    /// username/password fields into the single credential string the core
    /// takes ("user:pass" for Basic, bare token for Bearer, "" for none).
    private func commitRendezvous() {
        var seen = Set<String>()
        config.rendezvousServers = rendezvousText
            .split(separator: "\n", omittingEmptySubsequences: true)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && seen.insert($0).inserted }

        let u = rendezvousUser.trimmingCharacters(in: .whitespacesAndNewlines)
        let p = rendezvousPass.trimmingCharacters(in: .whitespacesAndNewlines)
        config.rendezvousAuth = p.isEmpty ? u : "\(u):\(p)"
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
        // Credential for rendezvous servers that require one — carried by the
        // QR so joining stays "scan and go" even on an authenticated server.
        config.rendezvousAuth = jc.rendezvous_auth ?? ""
        // Adopt this network's trackers (incl. any private tracker); the core
        // still unions in its curated defaults on top.
        if let t = jc.trackers, !t.isEmpty { config.trackers = t }
        // Adopt the network's crypto profile — absent fields default to quantum-safe ON.
        if let c = jc.cipher, !c.isEmpty { config.cipher = c }
        config.postQuantum = jc.post_quantum ?? true
        config.pqAuth = jc.pq_auth ?? true
        config.applyLastOctet(octet)
    }
}
