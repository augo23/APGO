package org.apgo.app

// Support constants. The Cash App tag and Monero address are shown for
// arbitrary amounts; the website gift page takes any amount via
// Google Pay / Apple Pay / card (Play in-app products are fixed price).
//
// Support is a personal gift to the project — APGO is not a charity or registered
// non-profit, and gifts are not tax-deductible. Product IDs below must match the
// products configured in the Play Console (docs/gifts-setup.md).
object Support {
    const val cashApp = "\$APGOverlay"
    // Opening the Cash App profile is the path that actually completes a
    // payment — on a phone the link hands off to the installed app. The tag
    // stays copyable underneath for anyone paying from another device.
    const val cashAppUrl = "https://cash.app/\$APGOverlay"
    const val monero = "463y7FwfniMAsR2a3hQAQCh4FVuv2bKU86yFBj1SGUmkdgieFi2U4qaSuyyJNfgqEHd7gciN8YfnuGES3dEb1uimLnaQSTr"
    // F-Droid build only (no payment flow inside the app there).
    const val githubSponsorsUrl = "https://github.com/sponsors/augo23"
    const val venmo = "@APGOverlay"
    const val venmoUrl = "https://www.venmo.com/u/APGOverlay"
    // Website gift page: custom amounts (Play build only).
    const val giftUrl = "https://www.apgoverlay.com/support.html"
    const val manageSubsUrl = "https://play.google.com/store/account/subscriptions"
    // Create these as CONSUMABLE in-app products in the Play Console, priced
    // $1 / $3 / $5 / $10 / $25 / $50 / $100.
    val productIds = listOf(
        "apgo_gift_1",
        "apgo_gift_3",
        "apgo_gift_5",
        "apgo_gift_10",
        "apgo_gift_25",
        "apgo_gift_50",
        "apgo_gift_100",
    )
    // Create these as SUBSCRIPTIONS in the Play Console (one base plan each,
    // monthly auto-renewing), priced $1 / $3 / $5 / $10 per month.
    val subscriptionIds = listOf(
        "apgo_monthly_1",
        "apgo_monthly_3",
        "apgo_monthly_5",
        "apgo_monthly_10",
    )
}
