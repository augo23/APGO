import SwiftUI

@main
struct APGOApp: App {
    // App lock (Face ID / Touch ID) — created here so the lock cover sits ABOVE
    // every screen, including sheets presented from ContentView.
    @StateObject private var appLock = AppLock()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ZStack {
                ContentView()
                    .environmentObject(appLock)
                if appLock.isLocked {
                    LockScreenView()
                        .environmentObject(appLock)
                        .transition(.opacity)
                        .zIndex(1)
                }
            }
            .onChange(of: scenePhase) { phase in
                switch phase {
                case .active:
                    // Prompt as soon as we're frontmost again (also covers launch).
                    appLock.unlock()
                case .background:
                    // Re-lock when leaving, so returning always re-authenticates.
                    appLock.lockIfEnabled()
                default:
                    break
                }
            }
        }
    }
}
