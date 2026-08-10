package org.apgo.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import org.apgo.overlaymobile.Overlaymobile   // gomobile-generated .aar
import org.json.JSONObject

// OverlayVpnService runs the APGO overlay inside an Android VpnService. The app
// starts it with a "configJSON" extra; we build the tun, hand its fd to the Go
// overlay core, and run as a foreground service. Stop via ACTION_STOP.
class OverlayVpnService : VpnService() {

    private var tun: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopOverlay()
            return START_NOT_STICKY
        }
        // configJSON is set on a normal Connect from the app. For ALWAYS-ON
        // VPN (Settings → Network → VPN → Always-on) and for START_STICKY
        // restarts after the OS kills the process, Android starts this
        // service with a null intent / no extras — fall back to the
        // last-used config so the tunnel comes back by itself instead of
        // silently dying.
        val json = intent?.getStringExtra("configJSON")
            ?: prefs().getString(KEY_LAST_CONFIG, null)
            ?: run { stopSelf(); return START_NOT_STICKY }

        startForeground(NOTIF_ID, buildNotification())

        val cfg = JSONObject(json)
        val overlayIP = cfg.optString("overlay_ip")
        val overlayNet = cfg.optString("overlay_cidr", "10.22.55.0/24").substringBefore('/')
        val mtu = cfg.optJSONObject("tun")?.optInt("mtu", 1280) ?: 1280
        val useExit = cfg.optBoolean("use_exit", false)
        if (overlayIP.isEmpty()) {
            stopSelf(); return START_NOT_STICKY
        }

        val builder = Builder()
            .setSession("APGO")
            .addAddress(overlayIP, 24)
            .setMtu(mtu)
        // Full-VPN mode routes everything through the tunnel (the Go core forwards
        // internet traffic to the fastest exit); otherwise just the overlay subnet.
        if (useExit) {
            builder.addRoute("0.0.0.0", 0)
            // Full-VPN DNS: without this, apps keep resolving via the Wi-Fi
            // router's DNS (e.g. 192.168.1.1) — those packets get captured by
            // the 0.0.0.0/0 route, forwarded to the exit, and die there (the
            // exit can't reach OUR router). Public resolvers work from any
            // exit. (Matches the iOS tunnel's NEDNSSettings.)
            builder.addDnsServer("1.1.1.1")
            builder.addDnsServer("1.0.0.1")
        } else {
            builder.addRoute(overlayNet, 24)
        }
        // CRITICAL: exclude our own app from the VPN. The Go core runs in this
        // process, and its UDP socket (handshakes, tracker/STUN announces, the
        // encrypted transport itself) must egress via the real network. With a
        // 0.0.0.0/0 route and no exclusion, the core's own packets get routed
        // back into the tunnel they came from — a routing loop that kills all
        // connectivity the moment full-VPN mode connects.
        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: Exception) { /* NameNotFoundException can't happen for self */ }
        val pfd = builder.establish() ?: run { stopSelf(); return START_NOT_STICKY }
        tun = pfd

        try {
            Overlaymobile.start(pfd.fd.toLong(), json)
        } catch (e: Exception) {
            stopOverlay()
            return START_NOT_STICKY
        }
        // Remember the working config for always-on / sticky restarts.
        prefs().edit().putString(KEY_LAST_CONFIG, json).apply()
        return START_STICKY
    }

    private fun prefs() = getSharedPreferences("apgo_vpn", MODE_PRIVATE)

    override fun onDestroy() {
        stopOverlay()
        super.onDestroy()
    }

    private fun stopOverlay() {
        try { Overlaymobile.stop() } catch (_: Throwable) {}
        try { tun?.close() } catch (_: Throwable) {}
        tun = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun buildNotification(): Notification {
        val mgr = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            mgr.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "APGO VPN", NotificationManager.IMPORTANCE_LOW)
            )
        }
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("APGO connected")
            .setContentText("Overlay network is active")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .build()
    }

    companion object {
        const val ACTION_STOP = "org.apgo.app.STOP"
        private const val CHANNEL_ID = "apgo_vpn"
        private const val NOTIF_ID = 1
        private const val KEY_LAST_CONFIG = "last_config"
    }
}
