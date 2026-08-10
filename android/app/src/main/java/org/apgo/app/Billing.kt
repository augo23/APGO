package org.apgo.app

import android.app.Activity
import android.content.Context
import com.android.billingclient.api.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

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
    // Website gift page: custom amounts.
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

data class GiftProduct(
    val id: String,
    val title: String,
    val price: String,
    val details: ProductDetails,
    // Present only for subscriptions: the offer token the billing flow needs.
    val offerToken: String? = null,
) {
    val isSubscription: Boolean get() = offerToken != null
}

// BillingManager wraps Google Play Billing for one-time gifts (consumables)
// and monthly support (auto-renewing subscriptions).
class BillingManager(context: Context) : PurchasesUpdatedListener {

    private val _products = MutableStateFlow<List<GiftProduct>>(emptyList())
    val products: StateFlow<List<GiftProduct>> = _products

    private val _subscriptions = MutableStateFlow<List<GiftProduct>>(emptyList())
    val subscriptions: StateFlow<List<GiftProduct>> = _subscriptions

    // Product ID of an already-active monthly support subscription, or "".
    private val _activeSubscription = MutableStateFlow("")
    val activeSubscription: StateFlow<String> = _activeSubscription

    private val _status = MutableStateFlow("")
    val status: StateFlow<String> = _status

    private val client = BillingClient.newBuilder(context)
        .setListener(this)
        .enablePendingPurchases(PendingPurchasesParams.newBuilder().enableOneTimeProducts().build())
        .build()

    fun start() {
        client.startConnection(object : BillingClientStateListener {
            override fun onBillingSetupFinished(result: BillingResult) {
                if (result.responseCode == BillingClient.BillingResponseCode.OK) {
                    queryProducts()
                    querySubscriptions()
                    queryActiveSubscription()
                }
            }
            override fun onBillingServiceDisconnected() {}
        })
    }

    private fun queryProducts() {
        val list = Support.productIds.map {
            QueryProductDetailsParams.Product.newBuilder()
                .setProductId(it)
                .setProductType(BillingClient.ProductType.INAPP)
                .build()
        }
        val params = QueryProductDetailsParams.newBuilder().setProductList(list).build()
        client.queryProductDetailsAsync(params) { result, details ->
            if (result.responseCode == BillingClient.BillingResponseCode.OK) {
                _products.value = details
                    .sortedBy { it.oneTimePurchaseOfferDetails?.priceAmountMicros ?: 0 }
                    .map {
                        GiftProduct(
                            id = it.productId,
                            title = it.title,
                            price = it.oneTimePurchaseOfferDetails?.formattedPrice ?: "",
                            details = it,
                        )
                    }
            }
        }
    }

    private fun querySubscriptions() {
        val list = Support.subscriptionIds.map {
            QueryProductDetailsParams.Product.newBuilder()
                .setProductId(it)
                .setProductType(BillingClient.ProductType.SUBS)
                .build()
        }
        val params = QueryProductDetailsParams.newBuilder().setProductList(list).build()
        client.queryProductDetailsAsync(params) { result, details ->
            if (result.responseCode == BillingClient.BillingResponseCode.OK) {
                _subscriptions.value = details.mapNotNull { d ->
                    // One base plan per product; take its first offer.
                    val offer = d.subscriptionOfferDetails?.firstOrNull() ?: return@mapNotNull null
                    val phase = offer.pricingPhases.pricingPhaseList.firstOrNull()
                    GiftProduct(
                        id = d.productId,
                        title = d.title,
                        price = phase?.formattedPrice ?: "",
                        details = d,
                        offerToken = offer.offerToken,
                    )
                }.sortedBy { p ->
                    p.details.subscriptionOfferDetails?.firstOrNull()
                        ?.pricingPhases?.pricingPhaseList?.firstOrNull()?.priceAmountMicros ?: 0
                }
            }
        }
    }

    // An already-running monthly support: surface it so the UI can thank the
    // user and offer "manage" instead of selling a second subscription.
    private fun queryActiveSubscription() {
        val params = QueryPurchasesParams.newBuilder()
            .setProductType(BillingClient.ProductType.SUBS)
            .build()
        client.queryPurchasesAsync(params) { result, purchases ->
            if (result.responseCode == BillingClient.BillingResponseCode.OK) {
                _activeSubscription.value = purchases
                    .filter { it.purchaseState == Purchase.PurchaseState.PURCHASED }
                    .flatMap { it.products }
                    .firstOrNull { it in Support.subscriptionIds } ?: ""
                // Re-acknowledge anything that slipped through (an unacknowledged
                // subscription is auto-refunded by Play after 3 days).
                purchases.filter {
                    it.purchaseState == Purchase.PurchaseState.PURCHASED && !it.isAcknowledged
                }.forEach(::acknowledge)
            }
        }
    }

    fun sendGift(activity: Activity, product: GiftProduct) {
        val details = BillingFlowParams.ProductDetailsParams.newBuilder()
            .setProductDetails(product.details)
        product.offerToken?.let { details.setOfferToken(it) }
        val params = BillingFlowParams.newBuilder()
            .setProductDetailsParamsList(listOf(details.build()))
            .build()
        client.launchBillingFlow(activity, params)
    }

    override fun onPurchasesUpdated(result: BillingResult, purchases: MutableList<Purchase>?) {
        if (result.responseCode == BillingClient.BillingResponseCode.OK && purchases != null) {
            for (p in purchases) {
                val isSub = p.products.any { it in Support.subscriptionIds }
                if (isSub) {
                    // Subscriptions are ACKNOWLEDGED (never consumed — consuming
                    // is how one-time products become repeatable; acknowledging
                    // is how recurring ones stay owned).
                    if (!p.isAcknowledged) acknowledge(p)
                    _activeSubscription.value =
                        p.products.firstOrNull { it in Support.subscriptionIds } ?: ""
                    _status.value = "Monthly support active — thank you! 🙏"
                } else {
                    consume(p)
                    _status.value = "Thank you for your support! 🙏"
                }
            }
        } else if (result.responseCode == BillingClient.BillingResponseCode.USER_CANCELED) {
            _status.value = ""
        }
    }

    // Consume so the gift can be repeated.
    private fun consume(purchase: Purchase) {
        val params = ConsumeParams.newBuilder().setPurchaseToken(purchase.purchaseToken).build()
        client.consumeAsync(params) { _, _ -> }
    }

    private fun acknowledge(purchase: Purchase) {
        val params = AcknowledgePurchaseParams.newBuilder()
            .setPurchaseToken(purchase.purchaseToken)
            .build()
        client.acknowledgePurchase(params) { _ -> }
    }
}
