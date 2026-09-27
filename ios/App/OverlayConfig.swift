import Foundation

/// OverlayConfig is the user-facing network configuration. It serializes to the
/// same JSON shape the Go overlay core (mobile/bridge.go `Config`) parses.
struct OverlayConfig: Codable, Equatable {
    var networkName: String = ""          // shared network identity (info-hash seed)
    var psk: String = ""                  // "base64:..." pre-shared key
    var friendlyName: String = ""         // human label shown to peers
    var useExit: Bool = false             // route ALL traffic via an exit node (full VPN)
    var exitPeer: String = ""             // pin ONE exit (overlay IP / device name / key / "public"); "" = fastest
    // Let Full VPN fall back to a PUBLIC exit node (another APGO user's
    // device) when this network has no internal exit online. Optional so
    // configs saved by older builds still decode; nil = off.
    var usePublicExits: Bool? = nil
    // Reach peers through a public relay when no direct path can be punched
    // (symmetric NAT / CGNAT). Optional: nil = the core's default, which is on.
    var usePublicRelays: Bool? = nil
    var postQuantum: Bool = true          // hybrid post-quantum layer (ML-KEM-768), on by default
    var pqAuth: Bool = true               // quantum-resistant handshake auth (XXpsk0), on by default
    // Pin for the network admin key ("sha256:..."), taken from the join QR.
    // The core refuses any other admin key a peer seeds. Optional so configs
    // saved by older builds still decode; nil = unpinned (legacy TOFU).
    var adminKeyFP: String? = nil
    var cipher: String = ""               // transport cipher; "" = core default, set by join QR
    var ipv6: Bool = true                 // dual-stack transport (direct v6, no NAT), on by default
    var overlayIP: String = "10.22.55.30" // this node's overlay address
    var overlayCIDR: String = "10.22.55.0/24"
    // Leave empty: the Go core unions in its curated, currently-reachable
    // default tracker set. Shipping a single tracker here (as an old build did)
    // meant one flaky tracker starved discovery — the phone found LAN peers but
    // nothing from the wider swarm.
    var trackers: [String] = []
    // Set once the user edits the tracker list in Settings. When true, the
    // core treats `trackers` as the AUTHORITATIVE list (persisted to the same
    // managed trackers.txt the desktop app uses), so removals stick instead of
    // being unioned back with the defaults. Optional so configs saved by older
    // builds still decode (a missing key must not wipe the user's settings).
    var trackersEdited: Bool? = nil
    /// In-app diagnostic log capture: 0 = off, 1 = normal, 2 = verbose.
    /// Optional so configs saved by older builds still decode — a missing key
    /// must read as "off", not as some other level.
    var logLevel: Int? = nil
    var stunServers: [String] = ["stun.l.google.com:19302", "stun1.l.google.com:19302"]
    var rendezvousServers: [String] = []  // HTTPS discovery servers (from a join QR)
    var mtu: Int = 1280

    /// The core's curated default trackers (keep in sync with
    /// ios/core/overlay.go defaultTrackers and config/trackers.txt). Shown in
    /// the Settings editor when the user hasn't customized the list.
    static let defaultTrackers = [
        "udp://tracker.opentrackr.org:1337/announce",
        "udp://open.demonii.com:1337/announce",
        "udp://open.stealth.si:80/announce",
        "udp://exodus.desync.com:6969/announce",
        "udp://tracker.torrent.eu.org:451/announce",
        "udp://explodie.org:6969/announce",
        "udp://opentracker.io:6969/announce",
        "udp://tracker.dler.org:6969/announce"
    ]

    // --- diagnostics ---------------------------------------------------------
    //
    // The overlay core runs inside the TUNNEL EXTENSION, and this app process
    // cannot read the extension's own container — which is why the node key
    // and provisions are unreachable from here (see requestStateWipe). A log
    // written beside them could never be exported, so diagnostics go to the
    // shared App Group container instead, where both targets can reach them.

    /// The App Group declared on BOTH targets (App/APGO.entitlements and
    /// Tunnel/APGOTunnel.entitlements). Changing it here alone will silently
    /// produce an unreadable log.
    static let appGroupID = "group.com.you.APGOverlay"

    static var logDirectoryURL: URL? {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: appGroupID)?
            .appendingPathComponent("Logs", isDirectory: true)
    }

    /// Current file plus the single rotated generation behind it. Keep these
    /// names in sync with ios/core/mobilelog.go, which appends ".1" on rotate.
    static var logFileURL: URL? {
        logDirectoryURL?.appendingPathComponent("apgo.log")
    }

    static var rotatedLogFileURL: URL? {
        logDirectoryURL?.appendingPathComponent("apgo.log.1")
    }

    private static var logFilesOldestFirst: [URL] {
        [rotatedLogFileURL, logFileURL]
            .compactMap { $0 }
            .filter { FileManager.default.fileExists(atPath: $0.path) }
    }

    /// Total bytes captured across both generations.
    static func logSizeBytes() -> Int64 {
        logFilesOldestFirst.reduce(into: Int64(0)) { total, url in
            let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
            total += (attrs?[.size] as? NSNumber)?.int64Value ?? 0
        }
    }

    static func clearLogs() {
        for url in [rotatedLogFileURL, logFileURL].compactMap({ $0 }) {
            try? FileManager.default.removeItem(at: url)
        }
    }

    /// Merge both generations into ONE file for the share sheet, oldest first
    /// so the result reads chronologically. Returns nil when nothing has been
    /// captured yet.
    ///
    /// Copying rather than sharing the live file is deliberate: the extension
    /// may be appending to (or rotating) it at this instant, and the share
    /// sheet can hold its URL well past the moment the user tapped.
    static func exportLog() -> URL? {
        let sources = logFilesOldestFirst
        guard !sources.isEmpty else { return nil }

        let name = "apgo-log-\(Int(Date().timeIntervalSince1970)).txt"
        let dest = FileManager.default.temporaryDirectory.appendingPathComponent(name)
        try? FileManager.default.removeItem(at: dest)
        guard FileManager.default.createFile(atPath: dest.path, contents: nil),
              let out = try? FileHandle(forWritingTo: dest) else { return nil }
        defer { try? out.close() }

        for url in sources {
            if let data = try? Data(contentsOf: url, options: .mappedIfSafe) {
                try? out.write(contentsOf: data)
            }
        }
        return dest
    }

    // --- persistence ---------------------------------------------------------
    // The config MUST survive app relaunches and network changes (a dropped
    // Wi-Fi connection was wiping the scanned QR settings because config lived
    // only in @State). Configs persist as JSON in UserDefaults.
    //
    // Multi-network: the app stores a LIST of network profiles plus the index
    // of the selected one, so the user can save several networks (home, work,
    // …) and switch between them. The legacy single-config key is migrated
    // into the list on first run of a new build.
    private static let storageKey = "apgo.overlayConfig"          // legacy (pre-profiles)
    private static let listKey = "apgo.networks"
    private static let selectedKey = "apgo.selectedNetwork"
    private static let wipeNonceKey = "apgo.stateWipeNonce"

    /// Deleting a network must also wipe the overlay state persisted in the
    /// TUNNEL EXTENSION's container (node key, admin-assigned IP provisions,
    /// admin key material) — the app can't reach those files, so it records a
    /// fresh nonce here; the Go core wipes once when it sees a new nonce on the
    /// next connect. Without this, rejoining a forgotten network re-adopted the
    /// stale provisioned IP: the core announced an address the OS tunnel didn't
    /// own and the device received no traffic until an admin re-assigned it.
    static func requestStateWipe() {
        UserDefaults.standard.set(UUID().uuidString, forKey: wipeNonceKey)
    }

    static func stateWipeNonce() -> String {
        UserDefaults.standard.string(forKey: wipeNonceKey) ?? ""
    }

    /// Display label for pickers: the network name, or a placeholder.
    var displayName: String {
        networkName.isEmpty ? "New network" : networkName
    }

    /// Load all saved network profiles (never empty — creates/migrates one).
    static func loadAll() -> [OverlayConfig] {
        if let data = UserDefaults.standard.data(forKey: listKey),
           let list = try? JSONDecoder().decode([OverlayConfig].self, from: data),
           !list.isEmpty {
            return list
        }
        // Migrate the pre-profiles single config, or start fresh.
        if let data = UserDefaults.standard.data(forKey: storageKey),
           let cfg = try? JSONDecoder().decode(OverlayConfig.self, from: data) {
            let list = [cfg]
            saveAll(list)
            return list
        }
        return [OverlayConfig()]
    }

    /// Persist all profiles.
    static func saveAll(_ list: [OverlayConfig]) {
        if let data = try? JSONEncoder().encode(list) {
            UserDefaults.standard.set(data, forKey: listKey)
        }
    }

    /// Selected profile index (clamped by the caller against the list count).
    static func loadSelectedIndex() -> Int {
        UserDefaults.standard.integer(forKey: selectedKey)
    }

    static func saveSelectedIndex(_ i: Int) {
        UserDefaults.standard.set(i, forKey: selectedKey)
    }

    /// Load the selected config (legacy single-config API, kept for callers).
    static func load() -> OverlayConfig {
        let all = loadAll()
        let i = min(max(0, loadSelectedIndex()), all.count - 1)
        return all[i]
    }

    /// Persist the current config into its slot in the profile list.
    func save() {
        var all = Self.loadAll()
        let i = min(max(0, Self.loadSelectedIndex()), all.count - 1)
        all[i] = self
        Self.saveAll(all)
    }

    /// Network address (no host bits) for routing, e.g. "10.22.55.0".
    func overlayNetwork() -> String {
        overlayCIDR.split(separator: "/").first.map(String.init) ?? "10.22.55.0"
    }

    /// The first three octets of the subnet plus a trailing dot, e.g. "10.22.55.".
    func subnetPrefix() -> String {
        let parts = overlayNetwork().split(separator: ".")
        guard parts.count == 4 else { return "10.22.55." }
        return "\(parts[0]).\(parts[1]).\(parts[2])."
    }

    /// Recompute overlayIP from the subnet prefix and a last-octet string.
    mutating func applyLastOctet(_ octet: String) {
        overlayIP = subnetPrefix() + (octet.isEmpty ? "0" : octet)
    }

    /// JSON payload handed to the overlay core via providerConfiguration.
    func toJSON() -> String {
        var dict: [String: Any] = [
            "network_name": networkName,
            "psk": psk,
            "friendly_name": friendlyName,
            "use_exit": useExit,
            "use_public_exits": usePublicExits ?? false,
            "use_public_relays": usePublicRelays ?? true,
            "exit_peer": exitPeer.trimmingCharacters(in: .whitespacesAndNewlines),
            "post_quantum": postQuantum,
            "pq_auth": pqAuth,
            "ipv6": ipv6,
            "overlay_ip": overlayIP,
            "overlay_cidr": overlayCIDR,
            // This app reads the raw iOS utun fd, which carries a 4-byte AF
            // header on every packet; tell the Go core to strip/prepend it,
            // otherwise the tunnel forms sessions but can't move data.
            "utun_header": true,
            "trackers": trackers,
            "manage_trackers": trackersEdited ?? false,
            "stun_servers": stunServers,
            "rendezvous_servers": rendezvousServers,
            "tun": ["mtu": mtu]
        ]
        if let fp = adminKeyFP?.trimmingCharacters(in: .whitespacesAndNewlines), !fp.isEmpty {
            dict["admin_key_fp"] = fp
        }
        // In-app diagnostics. Sent ONLY when switched on, so an untouched
        // install gets exactly the previous behavior (stderr only) and never
        // writes a file it was not asked for.
        if let lvl = logLevel, lvl > 0, let path = Self.logFileURL?.path {
            dict["log_path"] = path
            dict["log_level"] = lvl
        }
        // One-shot state wipe (see requestStateWipe). Nonce-guarded in the
        // core, so resending it on every connect is harmless.
        let nonce = Self.stateWipeNonce()
        if !nonce.isEmpty { dict["wipe_state_nonce"] = nonce }
        let c = cipher.trimmingCharacters(in: .whitespacesAndNewlines)
        if !c.isEmpty { dict["cipher"] = c }
        let data = try? JSONSerialization.data(withJSONObject: dict, options: [])
        return data.flatMap { String(data: $0, encoding: .utf8) } ?? "{}"
    }
}
