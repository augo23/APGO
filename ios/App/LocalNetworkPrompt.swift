import Foundation
import Network
import Combine

/// LocalNetworkChecker triggers iOS's "allow local network access" prompt AND
/// detects the resulting permission state, so the app can warn the user when
/// LAN discovery is doomed.
///
/// Why this matters: the packet-tunnel extension finds peers on the same
/// Wi-Fi (beacon + unicast sweep), but iOS silently drops ALL of the app
/// bundle's LAN traffic if Local Network permission was never granted — and a
/// NetworkExtension provider can neither show the prompt nor see that it was
/// denied. The failure is completely invisible, which reads as "sometimes my
/// devices just don't show up." So the app itself (1) touches the local
/// network via Bonjour to make iOS show the prompt (TN3179 technique), and
/// (2) watches whether its own published service becomes visible:
///   * we can browse our own service      -> permission granted
///   * browser reports a policy denial / nothing appears -> denied
///
/// Requires in Info.plist: NSLocalNetworkUsageDescription and
/// NSBonjourServices = ["_apgo._udp."].
@MainActor
final class LocalNetworkChecker: ObservableObject {
    enum Status: Equatable {
        case unknown, checking, granted, denied
    }

    @Published var status: Status = .unknown

    private var browser: NWBrowser?
    private var listener: NWListener?
    private var timeoutTask: Task<Void, Never>?

    /// Publish + browse a throwaway Bonjour service. First run shows the
    /// system prompt; every run updates `status`. Safe to call repeatedly
    /// (e.g. on foreground/Connect) — it re-checks unless already checking.
    func check() {
        guard status != .checking else { return }
        status = .checking
        teardown()

        if let l = try? NWListener(using: .udp) {
            l.service = NWListener.Service(name: "APGO-\(Int.random(in: 100_000...999_999))",
                                           type: "_apgo._udp")
            l.newConnectionHandler = { $0.cancel() }
            l.start(queue: .main)
            listener = l
        }

        let params = NWParameters()
        params.includePeerToPeer = true
        let b = NWBrowser(for: .bonjour(type: "_apgo._udp", domain: nil), using: params)
        b.browseResultsChangedHandler = { [weak self] results, _ in
            // Seeing ANY result (our own service) proves LAN access works.
            if !results.isEmpty {
                Task { @MainActor in self?.finish(.granted) }
            }
        }
        b.stateUpdateHandler = { [weak self] st in
            // A browser stuck in .waiting means mDNS was refused — on iOS
            // that's the local-network policy denial.
            if case .waiting = st {
                Task { @MainActor in self?.finish(.denied) }
            }
        }
        b.start(queue: .main)
        browser = b

        // No sighting within 6s: treat as denied (the prompt may also still
        // be on screen — a re-check on the next Connect/foreground corrects
        // this as soon as the user answers).
        timeoutTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 6_000_000_000)
            guard let self, self.status == .checking else { return }
            self.finish(.denied)
        }
    }

    private func finish(_ s: Status) {
        guard status == .checking else { return }
        status = s
        teardown()
    }

    private func teardown() {
        timeoutTask?.cancel(); timeoutTask = nil
        browser?.cancel(); browser = nil
        listener?.cancel(); listener = nil
    }
}
