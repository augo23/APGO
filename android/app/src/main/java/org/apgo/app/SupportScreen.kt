package org.apgo.app

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp

// SupportScreen shows monthly support (Play subscriptions), one-time Google
// Play gift tiers (fixed price — Play products can't be arbitrary amounts),
// a link to the website gift page for any amount (Google Pay / card),
// plus Cash App and Monero.
//
// Note: APGO is not a charity or registered non-profit. Support sent through this
// screen is a personal gift to the project and is not tax-deductible.
@Composable
fun SupportScreen(billing: BillingManager, activity: Activity, onClose: () -> Unit) {
    val products by billing.products.collectAsState()
    val subscriptions by billing.subscriptions.collectAsState()
    val activeSub by billing.activeSubscription.collectAsState()
    val status by billing.status.collectAsState()
    val ctx = LocalContext.current

    Surface(modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                Text("Support APGO", style = MaterialTheme.typography.headlineMedium)
                Spacer(Modifier.weight(1f))
                TextButton(onClick = onClose) { Text("Done") }
            }

            Text(
                "APGO is free and open source. Gifts help fund development. You never have to give anything to use it — anything is appreciated!",
                style = MaterialTheme.typography.bodySmall
            )

            Text(
                "APGO is not a charity or registered non-profit. Your support is a personal gift to the project and is not tax-deductible — it cannot be written off on your taxes, and no goods or services are provided in exchange.",
                style = MaterialTheme.typography.bodySmall
            )

            Text("Monthly support", style = MaterialTheme.typography.titleSmall)
            if (activeSub.isNotEmpty()) {
                val current = subscriptions.firstOrNull { it.id == activeSub }
                Text(
                    "You give ${current?.price ?: "monthly"} — thank you! 💚",
                    style = MaterialTheme.typography.bodyMedium
                )
                OutlinedButton(
                    onClick = { openUrl(ctx, Support.manageSubsUrl) },
                    modifier = Modifier.fillMaxWidth()
                ) { Text("Manage or cancel") }
            } else if (subscriptions.isEmpty()) {
                Text("Loading monthly options…", style = MaterialTheme.typography.bodySmall)
            } else {
                subscriptions.forEach { p ->
                    Button(onClick = { billing.sendGift(activity, p) }, modifier = Modifier.fillMaxWidth()) {
                        Text("${p.price} / month")
                    }
                }
                Text(
                    "Auto-renews monthly. Cancel anytime in Play Store → Subscriptions.",
                    style = MaterialTheme.typography.bodySmall
                )
            }

            Divider(Modifier.padding(vertical = 8.dp))

            Text("One-time gift", style = MaterialTheme.typography.titleSmall)
            if (products.isEmpty()) {
                Text("Loading support options…", style = MaterialTheme.typography.bodySmall)
            } else {
                products.forEach { p ->
                    Button(onClick = { billing.sendGift(activity, p) }, modifier = Modifier.fillMaxWidth()) {
                        Text("Gift ${p.price}")
                    }
                }
            }
            if (status.isNotEmpty()) {
                Text(status, style = MaterialTheme.typography.bodySmall)
            }

            Divider(Modifier.padding(vertical = 8.dp))

            Text("Any amount you like", style = MaterialTheme.typography.titleSmall)
            Button(
                onClick = { openUrl(ctx, Support.giftUrl) },
                modifier = Modifier.fillMaxWidth()
            ) { Text("Choose your own amount on our website") }
            Text(
                "Opens APGO's gift page — Google Pay, Apple Pay, or card; one-time or monthly; any amount.",
                style = MaterialTheme.typography.bodySmall
            )

            Divider(Modifier.padding(vertical = 8.dp))

            Text("Cash App", style = MaterialTheme.typography.titleSmall)
            Button(
                onClick = { openUrl(ctx, Support.cashAppUrl) },
                modifier = Modifier.fillMaxWidth()
            ) { Text("Open ${Support.cashApp} in Cash App") }
            CopyRow(label = "Copy ${Support.cashApp}", value = Support.cashApp, ctx = ctx)

            Text("Monero (XMR)", style = MaterialTheme.typography.titleSmall)
            Text(
                Support.monero,
                style = MaterialTheme.typography.bodySmall,
                maxLines = 3,
                overflow = TextOverflow.Ellipsis
            )
            CopyRow(label = "Copy Monero address", value = Support.monero, ctx = ctx)
        }
    }
}

private fun openUrl(ctx: Context, url: String) {
    ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
}

@Composable
private fun CopyRow(label: String, value: String, ctx: Context) {
    var copied by remember { mutableStateOf(false) }
    OutlinedButton(
        onClick = {
            val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("APGO support", value))
            copied = true
        },
        modifier = Modifier.fillMaxWidth()
    ) {
        Text(if (copied) "Copied ✓" else label)
    }
}
