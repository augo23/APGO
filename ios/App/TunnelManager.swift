import Foundation
@preconcurrency import NetworkExtension   // silence Sendable warnings from NE types
import Combine

/// TunnelManager installs and controls the APGO packet-tunnel VPN profile.
/// It builds the config JSON the overlay core expects, stores it in the tunnel's
/// providerConfiguration, and starts/stops the extension.
@MainActor
final class TunnelManager: ObservableObject {

    @Published var status: NEVPNStatus = .invalid
    @Published var lastError: String?

    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?

    // Set this to your extension's bundle identifier (matches project.yml).
    private let tunnelBundleID = "com.APGOveraly.-.Tunnel"

    init() {
        Task { await load() }
    }

    /// Load any previously-saved APGO tunnel profile.
    func load() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            let mgr = managers.first ?? NETunnelProviderManager()
            self.manager = mgr
            observe(mgr)
            self.status = mgr.connection.status
        } catch {
            self.lastError = error.localizedDescription
        }
    }

    /// Save the profile and connect. `config` holds the user's network settings.
    func connect(config: OverlayConfig) async {
        do {
            let mgr = manager ?? NETunnelProviderManager()

            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = tunnelBundleID
            // serverAddress is display-only for a P2P overlay.
            proto.serverAddress = config.networkName
            proto.providerConfiguration = [
                "configJSON": config.toJSON(),
                "overlayIP": config.overlayIP,
                "overlayNetwork": config.overlayNetwork(),
                "fullTunnel": config.useExit
            ]

            // Keep physical-LAN traffic OFF the tunnel, even in full-VPN mode.
            // Without this, the tunnel can swallow the extension's own LAN
            // discovery beacons and handshakes to same-Wi-Fi peers (they're
            // routed into utun and dropped/sent to the exit), so LAN peers
            // never form direct sessions while "Route all traffic" is on —
            // they appear relayed even though they're one hop away. Standard
            // VPN behavior (printers etc. keep working) and no security loss:
            // LAN traffic never needed the exit.
            if #available(iOS 14.2, *) {
                proto.excludeLocalNetworks = true
            }

            mgr.localizedDescription = "APGO — \(config.networkName)"
            mgr.protocolConfiguration = proto
            mgr.isEnabled = true
            // Auto-reconnect: have iOS bring the tunnel back whenever any
            // network is available — after reboots, after the system kills
            // the extension (memory pressure), and across Wi-Fi↔cellular
            // moves — instead of staying down until the user reopens the
            // app. Cleared on explicit Disconnect, otherwise the system
            // would immediately restart what the user just stopped.
            let onDemand = NEOnDemandRuleConnect()
            onDemand.interfaceTypeMatch = .any
            mgr.onDemandRules = [onDemand]
            mgr.isOnDemandEnabled = true

            try await mgr.saveToPreferences()
            try await mgr.loadFromPreferences()   // reload to get a valid connection
            self.manager = mgr
            observe(mgr)

            try mgr.connection.startVPNTunnel()
        } catch {
            self.lastError = error.localizedDescription
        }
    }

    func disconnect() {
        Task { @MainActor in
            // Turn OFF on-demand before stopping, or iOS restarts the tunnel
            // the moment it drops — "disconnect" would look broken.
            if let mgr = manager, mgr.isOnDemandEnabled {
                mgr.isOnDemandEnabled = false
                try? await mgr.saveToPreferences()
            }
            manager?.connection.stopVPNTunnel()
        }
    }

    /// Apply a config change (e.g. the Full-VPN toggle) to a LIVE tunnel by
    /// restarting it with the new settings. The providerConfiguration is only
    /// read at startTunnel, so without this a toggle flipped while connected
    /// silently did nothing until the user manually disconnected/reconnected —
    /// which made "Route all traffic via an exit node" look broken.
    func reconnect(config: OverlayConfig) async {
        switch status {
        case .connected, .connecting, .reasserting:
            disconnect()
            // Wait (up to 10s) for the tunnel to fully stop, then start again.
            for _ in 0..<40 {
                try? await Task.sleep(nanoseconds: 250_000_000)
                if status == .disconnected || status == .invalid { break }
            }
            await connect(config: config)
        default:
            break // not running — the new config is picked up on next Connect
        }
    }

    /// Ask the running tunnel extension for its current peer list.
    ///
    /// Returns `nil` when the round-trip fails (not connected, sendProviderMessage
    /// throws, no response, or undecodable) — distinct from `[]`, which means the
    /// core genuinely reported ZERO peers. The caller uses this distinction to
    /// KEEP the last known list on a transient IPC hiccup instead of flashing the
    /// peers away to "No peers yet — discovering…" every time a single message
    /// round-trip drops (which made an otherwise-healthy connection look like it
    /// had lost all its peers).
    func fetchPeers() async -> [Peer]? {
        guard status == .connected,
              let session = manager?.connection as? NETunnelProviderSession else { return nil }
        return await withCheckedContinuation { (cont: CheckedContinuation<[Peer]?, Never>) in
            do {
                try session.sendProviderMessage(Data("peers".utf8)) { resp in
                    guard let resp = resp else {
                        cont.resume(returning: nil)   // no response — transient, keep last list
                        return
                    }
                    guard let peers = try? JSONDecoder().decode([Peer].self, from: resp) else {
                        cont.resume(returning: nil)   // undecodable — transient, keep last list
                        return
                    }
                    cont.resume(returning: peers)     // authoritative snapshot ([] = truly none)
                }
            } catch {
                cont.resume(returning: nil)
            }
        }
    }

    /// Ask the running tunnel extension whether an admin has assigned this
    /// device a NEW overlay address (returns the pending CIDR, or "" if none).
    /// The extension's Go core receives the signed provision over the mesh but
    /// cannot re-address the OS tunnel itself — the app owns NEIPv4Settings —
    /// so the app polls this and reconnects with the new address.
    func fetchPendingAddress() async -> String {
        guard status == .connected,
              let session = manager?.connection as? NETunnelProviderSession else { return "" }
        return await withCheckedContinuation { (cont: CheckedContinuation<String, Never>) in
            do {
                try session.sendProviderMessage(Data("pending".utf8)) { resp in
                    guard let resp = resp, let s = String(data: resp, encoding: .utf8) else {
                        cont.resume(returning: "")
                        return
                    }
                    cont.resume(returning: s.trimmingCharacters(in: .whitespacesAndNewlines))
                }
            } catch {
                cont.resume(returning: "")
            }
        }
    }

    // MARK: - Admission control

    /// What this device can do about approvals right now.
    struct AdmissionStatus: Decodable {
        /// The network gates new devices (it has an admin key).
        var required: Bool = false
        /// THIS device is approved.
        var selfApproved: Bool = true
        /// This device holds the sealed admin key, so it can sign approvals
        /// given the password. Arrives by mesh gossip, so it can be false for
        /// the first few seconds after connecting and then become true.
        var canSign: Bool = false

        enum CodingKeys: String, CodingKey {
            case required, selfApproved = "self_approved", canSign = "can_sign"
        }
    }

    func fetchAdmission() async -> AdmissionStatus {
        guard status == .connected,
              let session = manager?.connection as? NETunnelProviderSession else { return AdmissionStatus() }
        return await withCheckedContinuation { (cont: CheckedContinuation<AdmissionStatus, Never>) in
            do {
                try session.sendProviderMessage(Data("admission".utf8)) { resp in
                    guard let resp = resp,
                          let st = try? JSONDecoder().decode(AdmissionStatus.self, from: resp) else {
                        cont.resume(returning: AdmissionStatus())
                        return
                    }
                    cont.resume(returning: st)
                }
            } catch {
                cont.resume(returning: AdmissionStatus())
            }
        }
    }

    /// Approve or deny a device by its base64 static key.
    ///
    /// There is deliberately no way to approve THIS device from here: an
    /// approval must be issued by an admin on another node.
    ///
    /// Returns nil on success, or a message to show the user. The password is
    /// sent to the extension and used there to unseal the admin key; it is
    /// never persisted on either side.
    func approve(pubkey: String, action: String, password: String) async -> String? {
        guard status == .connected,
              let session = manager?.connection as? NETunnelProviderSession else {
            return "Not connected."
        }
        let req: [String: String] = ["cmd": "approve", "pubkey": pubkey,
                                     "action": action, "password": password]
        guard let body = try? JSONSerialization.data(withJSONObject: req) else {
            return "Could not encode the request."
        }
        return await withCheckedContinuation { (cont: CheckedContinuation<String?, Never>) in
            do {
                try session.sendProviderMessage(body) { resp in
                    guard let resp = resp, let s = String(data: resp, encoding: .utf8) else {
                        cont.resume(returning: "No response from the tunnel.")
                        return
                    }
                    let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
                    // The extension answers "ok" or an error message.
                    cont.resume(returning: t == "ok" ? nil : t)
                }
            } catch {
                cont.resume(returning: error.localizedDescription)
            }
        }
    }

    private func observe(_ mgr: NETunnelProviderManager) {
        if let obs = statusObserver {
            NotificationCenter.default.removeObserver(obs)
        }
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: mgr.connection,
            queue: .main
        ) { [weak self] _ in
            // Read status via self.manager (don't capture the non-Sendable mgr
            // in this @Sendable closure).
            Task { @MainActor in
                guard let self = self, let conn = self.manager?.connection else { return }
                self.status = conn.status
            }
        }
    }
}

/// Peer is one entry from the Go core's session snapshot (SessionInfo JSON).
/// All fields are decoded defensively so an older core that omits one doesn't
/// break the list.
struct Peer: Decodable, Identifiable {
    let remote: String     // stable per-session table key (ip:port, or relay/<ip>)
    let overlayIP: String
    let name: String
    let keyFP: String
    let established: Bool
    let postQuantum: Bool
    let isExit: Bool       // peer advertises as an internet exit node
    let activeExit: Bool   // the exit THIS device currently egresses through
    let relayed: Bool      // reachable only via a relay (no direct session)
    let via: String        // relayed rows: the relaying node (overlay IP or endpoint)
    let lastSeenUnix: Int64
    // Admission control. The app could not previously SEE these, so a device
    // stuck in "pending" looked like a healthy peer that mysteriously passed no
    // traffic — the same misleading state the desktop dashboard calls out.
    let pubkey: String     // base64 static key; the identity an approval names
    let approved: Bool     // false = waiting for an admin to approve it

    enum CodingKeys: String, CodingKey {
        case remote
        case overlayIP = "overlay_ip"
        case name
        case keyFP = "key_fp"
        case established
        case postQuantum = "post_quantum"
        case isExit = "exit"
        case activeExit = "active_exit"
        case relayed
        case via
        case lastSeenUnix = "last_seen_unix"
        case pubkey
        case approved
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        remote = (try? c.decode(String.self, forKey: .remote)) ?? ""
        overlayIP = (try? c.decode(String.self, forKey: .overlayIP)) ?? ""
        name = (try? c.decode(String.self, forKey: .name)) ?? ""
        keyFP = (try? c.decode(String.self, forKey: .keyFP)) ?? ""
        established = (try? c.decode(Bool.self, forKey: .established)) ?? false
        postQuantum = (try? c.decode(Bool.self, forKey: .postQuantum)) ?? false
        isExit = (try? c.decode(Bool.self, forKey: .isExit)) ?? false
        pubkey = (try? c.decode(String.self, forKey: .pubkey)) ?? ""
        // Defaults to TRUE on purpose. A client build that predates this field
        // is not reporting "unapproved", it is reporting nothing — and marking
        // every peer pending would be a false alarm on every row at once.
        approved = (try? c.decode(Bool.self, forKey: .approved)) ?? true
        activeExit = (try? c.decode(Bool.self, forKey: .activeExit)) ?? false
        relayed = (try? c.decode(Bool.self, forKey: .relayed)) ?? false
        via = (try? c.decode(String.self, forKey: .via)) ?? ""
        lastSeenUnix = (try? c.decode(Int64.self, forKey: .lastSeenUnix)) ?? 0
    }

    // Identity for SwiftUI's ForEach. `remote` is the Go core's stable, unique
    // per-row key (a direct session's ip:port, or "relay/<ip>" for a relay-only
    // peer), so it never collides. The old id fell back to keyFP/overlayIP,
    // which two distinct devices could share (both empty right after connect, or
    // a key-derived overlay-IP collision) — SwiftUI then merged them and only
    // ONE device showed even though both were reachable. Fall back to a
    // composite only for older cores that don't emit `remote`.
    var id: String {
        if !remote.isEmpty { return remote }
        let composite = keyFP + "|" + overlayIP
        return composite == "|" ? name : composite
    }

    /// "3s ago" style relative last-seen.
    var lastSeenText: String {
        guard lastSeenUnix > 0 else { return "—" }
        let secs = max(0, Int(Date().timeIntervalSince1970) - Int(lastSeenUnix))
        if secs < 60 { return "\(secs)s ago" }
        if secs < 3600 { return "\(secs / 60)m ago" }
        return "\(secs / 3600)h ago"
    }
}

extension NEVPNStatus {
    var label: String {
        switch self {
        case .invalid:       return "Not configured"
        case .disconnected:  return "Disconnected"
        case .connecting:    return "Connecting…"
        case .connected:     return "Connected"
        case .reasserting:   return "Reconnecting…"
        case .disconnecting: return "Disconnecting…"
        @unknown default:    return "Unknown"
        }
    }
}
