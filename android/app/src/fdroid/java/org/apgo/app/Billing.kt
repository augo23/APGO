package org.apgo.app

// F-DROID build: no Google Play Billing (F-Droid accepts no proprietary
// libraries). Same API as the Play build's BillingManager, with nothing to
// sell, so the Support screen shows only the website, Cash App and Monero.

import android.app.Activity
import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

data class GiftProduct(val id: String, val title: String, val price: String)

class BillingManager(@Suppress("UNUSED_PARAMETER") context: Context) {
    val available = false
    val products: StateFlow<List<GiftProduct>> = MutableStateFlow(emptyList())
    val subscriptions: StateFlow<List<GiftProduct>> = MutableStateFlow(emptyList())
    val activeSubscription: StateFlow<String> = MutableStateFlow("")
    val status: StateFlow<String> = MutableStateFlow("")
    fun start() {}
    fun sendGift(@Suppress("UNUSED_PARAMETER") activity: Activity, @Suppress("UNUSED_PARAMETER") product: GiftProduct) {}
}
