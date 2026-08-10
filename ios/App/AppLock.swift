import SwiftUI
import LocalAuthentication

/// AppLock gates the app's UI behind Face ID / Touch ID (with device-passcode
/// fallback) when "Require Face ID/Touch ID" is enabled in Settings. It
/// protects what's on screen — the PSK, peer list, and network settings — NOT
/// the tunnel: the VPN keeps running while the app is locked, exactly like
/// other VPN apps' app locks.
///
/// Behavior:
///   * Locks on launch and whenever the app leaves the foreground, so coming
///     back always re-prompts.
///   * Enabling the toggle requires a successful biometric check first — this
///     both confirms it works on this device and prevents flipping it on for
///     someone else's face/finger by accident.
///   * Uses .deviceOwnerAuthentication (biometics + passcode fallback) so a
///     failed Face ID scan can never permanently lock the user out.
@MainActor
final class AppLock: ObservableObject {
    private static let key = "appLockEnabled"

    /// Whether the UI is currently hidden behind the lock screen.
    @Published var isLocked: Bool
    /// Last auth failure, shown on the lock screen ("" = none).
    @Published var lastError = ""
    /// Guard against overlapping evaluatePolicy calls (e.g. scene-phase churn).
    private var authInFlight = false

    init() {
        // Start locked only if the user enabled the lock. UserDefaults is fine
        // here: the toggle is a UI preference, not a secret — the actual gate
        // is the OS biometric check.
        isLocked = UserDefaults.standard.bool(forKey: Self.key)
    }

    var enabled: Bool {
        UserDefaults.standard.bool(forKey: Self.key)
    }

    /// Whether the device can authenticate at all (biometrics OR passcode).
    static var available: Bool {
        LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
    }

    /// "Face ID" / "Touch ID" for the Settings label and lock-screen button,
    /// falling back to "device passcode" on devices without biometrics.
    static var biometryLabel: String {
        let ctx = LAContext()
        _ = ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        switch ctx.biometryType {
        case .faceID: return "Face ID"
        case .touchID: return "Touch ID"
        default: return "device passcode"
        }
    }

    /// Matching SF Symbol for the lock screen / settings row.
    static var biometrySymbol: String {
        let ctx = LAContext()
        _ = ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        switch ctx.biometryType {
        case .faceID: return "faceid"
        case .touchID: return "touchid"
        default: return "lock"
        }
    }

    /// Flip the setting. Turning it ON prompts for authentication first and
    /// only persists on success (returns the state actually in effect).
    func setEnabled(_ on: Bool) async {
        if on {
            guard await authenticate(reason: "Confirm \(Self.biometryLabel) to enable the app lock") else {
                objectWillChange.send() // snap the toggle back
                return
            }
        }
        UserDefaults.standard.set(on, forKey: Self.key)
        if !on { isLocked = false }
        objectWillChange.send()
    }

    /// Called when the app leaves the foreground.
    func lockIfEnabled() {
        if enabled { isLocked = true }
    }

    /// Prompt and unlock (no-op when already unlocked or a prompt is showing).
    func unlock() {
        guard isLocked, !authInFlight else { return }
        Task {
            if await authenticate(reason: "Unlock APGO") {
                isLocked = false
                lastError = ""
            }
        }
    }

    /// One OS auth prompt: biometrics with automatic passcode fallback.
    private func authenticate(reason: String) async -> Bool {
        guard Self.available else {
            // No biometrics and no passcode set — nothing to check against.
            lastError = "No Face ID, Touch ID, or passcode is set up on this device."
            return false
        }
        authInFlight = true
        defer { authInFlight = false }
        do {
            return try await LAContext().evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
        } catch {
            lastError = error.localizedDescription
            return false
        }
    }
}

/// Full-screen cover shown while locked. The tunnel status stays private —
/// nothing from the UI underneath is visible or tappable.
struct LockScreenView: View {
    @EnvironmentObject var appLock: AppLock

    var body: some View {
        ZStack {
            Rectangle().fill(.background).ignoresSafeArea()
            VStack(spacing: 18) {
                Image(systemName: AppLock.biometrySymbol)
                    .font(.system(size: 52))
                    .foregroundStyle(.secondary)
                Text("APGO is locked")
                    .font(.headline)
                if !appLock.lastError.isEmpty {
                    Text(appLock.lastError)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 32)
                }
                Button {
                    appLock.unlock()
                } label: {
                    Label("Unlock with \(AppLock.biometryLabel)", systemImage: AppLock.biometrySymbol)
                        .padding(.horizontal, 6)
                }
                .buttonStyle(.borderedProminent)
            }
        }
    }
}
