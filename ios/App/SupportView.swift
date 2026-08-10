import SwiftUI
import StoreKit
import UIKit

// SupportView offers App Store in-app gifts (fixed tiers — Apple doesn't allow
// arbitrary IAP amounts), monthly recurring support (auto-renewable
// subscriptions), a link to the website gift page for truly arbitrary
// amounts (Apple Pay / Google Pay / card via Stripe), plus Cash App and Monero.
//
// Note: APGO is not a charity or registered non-profit. Support sent through this
// screen is a personal gift to the project and is not tax-deductible.
//
// App Store Connect setup (docs/gifts-setup.md has the walkthrough):
//   • One-time tiers  — CONSUMABLE in-app purchases with these exact IDs,
//     priced $1 / $3 / $5 / $10 / $25 / $50 / $100.
//   • Monthly tiers   — AUTO-RENEWABLE subscriptions in one subscription
//     group ("APGO Support"), priced $1 / $3 / $5 / $10 per month.
struct SupportConstants {
    static let cashApp = "$APGOverlay"
    // Opening the Cash App profile is the path that actually completes a
    // payment — on a phone the link hands off to the installed app. The tag
    // stays copyable underneath for anyone paying from another device.
    static let cashAppURL = URL(string: "https://cash.app/$APGOverlay")!
    static let monero  = "463y7FwfniMAsR2a3hQAQCh4FVuv2bKU86yFBj1SGUmkdgieFi2U4qaSuyyJNfgqEHd7gciN8YfnuGES3dEb1uimLnaQSTr"
    // Website gift page: custom amounts via Apple Pay / Google Pay / card.
    static let giftURL = URL(string: "https://www.apgoverlay.com/support.html")!
    static let manageSubsURL = URL(string: "https://apps.apple.com/account/subscriptions")!
    static let giftIDs = [
        "org.apgo.gift.1",
        "org.apgo.gift.3",
        "org.apgo.gift.5",
        "org.apgo.gift.10",
        "org.apgo.gift.25",
        "org.apgo.gift.50",
        "org.apgo.gift.100",
    ]
    static let monthlyIDs = [
        "org.apgo.monthly.1",
        "org.apgo.monthly.3",
        "org.apgo.monthly.5",
        "org.apgo.monthly.10",
    ]
}

@MainActor
final class SupportStore: ObservableObject {
    @Published var gifts: [Product] = []
    @Published var monthly: [Product] = []
    @Published var status: String = ""
    @Published var activeMonthlyID: String?

    func load() async {
        do {
            let items = try await Product.products(
                for: SupportConstants.giftIDs + SupportConstants.monthlyIDs)
            gifts = items.filter { $0.type == .consumable }.sorted { $0.price < $1.price }
            monthly = items.filter { $0.type == .autoRenewable }.sorted { $0.price < $1.price }
            await refreshActiveMonthly()
        } catch {
            status = "Could not load support options."
        }
    }

    // Reflect an already-running monthly support so the screen can say so
    // instead of offering to start a second one.
    func refreshActiveMonthly() async {
        for await entitlement in Transaction.currentEntitlements {
            if case .verified(let t) = entitlement,
               t.productType == .autoRenewable,
               SupportConstants.monthlyIDs.contains(t.productID) {
                activeMonthlyID = t.productID
                return
            }
        }
        activeMonthlyID = nil
    }

    func buy(_ product: Product) async {
        do {
            let result = try await product.purchase()
            switch result {
            case .success(let verification):
                if case .verified(let transaction) = verification {
                    await transaction.finish()
                    if transaction.productType == .autoRenewable {
                        status = "Monthly support active — thank you! 🙏"
                        await refreshActiveMonthly()
                    } else {
                        status = "Thank you for your support! 🙏"
                    }
                }
            case .userCancelled:
                status = ""
            default:
                status = ""
            }
        } catch {
            status = "Purchase failed. Please try again."
        }
    }
}

struct SupportView: View {
    @StateObject private var store = SupportStore()
    @Environment(\.dismiss) private var dismiss
    @State private var copied = ""

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("APGO is free and open source. Gifts fund the App Store presence — there's no free way to ship an iOS app. You never have to give anything to use it. Anything is appreciated!")
                        .font(.footnote).foregroundStyle(.secondary)
                    Text("APGO is not a charity or registered non-profit. Your support is a personal gift to the project and is not tax-deductible — it cannot be written off on your taxes, and no goods or services are provided in exchange.")
                        .font(.footnote).foregroundStyle(.secondary)
                }

                Section("Monthly support") {
                    if let active = store.activeMonthlyID,
                       let p = store.monthly.first(where: { $0.id == active }) {
                        Label("You give \(p.displayPrice)/month — thank you!",
                              systemImage: "heart.circle.fill")
                            .foregroundStyle(.pink)
                        Link("Manage or cancel", destination: SupportConstants.manageSubsURL)
                    } else if store.monthly.isEmpty {
                        Text("Loading…").foregroundStyle(.secondary)
                    } else {
                        ForEach(store.monthly, id: \.id) { p in
                            Button {
                                Task { await store.buy(p) }
                            } label: {
                                HStack {
                                    Text("\(p.displayPrice) / month")
                                    Spacer()
                                    Image(systemName: "arrow.triangle.2.circlepath")
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                        Text("Auto-renews monthly. Cancel anytime in your App Store subscriptions.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                }

                Section("One-time gift") {
                    if store.gifts.isEmpty {
                        Text("Loading…").foregroundStyle(.secondary)
                    } else {
                        ForEach(store.gifts, id: \.id) { p in
                            Button {
                                Task { await store.buy(p) }
                            } label: {
                                HStack {
                                    Text("Gift \(p.displayPrice)")
                                    Spacer()
                                    Image(systemName: "heart.fill").foregroundStyle(.pink)
                                }
                            }
                        }
                    }
                    if !store.status.isEmpty {
                        Text(store.status).font(.footnote).foregroundStyle(.secondary)
                    }
                }

                Section("Any amount you like") {
                    Link(destination: SupportConstants.giftURL) {
                        HStack {
                            Text("Choose your own amount on our website")
                            Spacer()
                            Image(systemName: "safari").foregroundStyle(.secondary)
                        }
                    }
                    Text("Opens APGO's gift page — Apple Pay, Google Pay, or card; one-time or monthly; any amount.")
                        .font(.footnote).foregroundStyle(.secondary)
                }

                Section("Cash App") {
                    Link(destination: SupportConstants.cashAppURL) {
                        HStack {
                            Text("Open \(SupportConstants.cashApp) in Cash App")
                            Spacer()
                            Image(systemName: "arrow.up.right.square")
                                .foregroundStyle(.secondary)
                        }
                    }
                    copyRow(label: "Copy \(SupportConstants.cashApp)", value: SupportConstants.cashApp, key: "cash")
                }

                Section("Monero (XMR)") {
                    Text(SupportConstants.monero)
                        .font(.system(.footnote, design: .monospaced))
                        .textSelection(.enabled)
                    copyRow(label: "Copy Monero address", value: SupportConstants.monero, key: "xmr")
                }
            }
            .navigationTitle("Support APGO")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .task { await store.load() }
        }
    }

    private func copyRow(label: String, value: String, key: String) -> some View {
        Button {
            UIPasteboard.general.string = value
            copied = key
        } label: {
            HStack {
                Text(label)
                Spacer()
                Image(systemName: copied == key ? "checkmark" : "doc.on.doc")
                    .foregroundStyle(.secondary)
            }
        }
    }
}
