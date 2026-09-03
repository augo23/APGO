package org.apgo.app

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.fragment.app.FragmentActivity
import androidx.activity.result.contract.ActivityResultContracts
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.apgo.overlaymobile.Overlaymobile
import org.json.JSONArray
import org.json.JSONObject

// MainActivity is the APGO Android UI: enter the network name + PSK, pick the
// last octet of the overlay IP, and Connect. Connecting first asks Android for
// VPN permission, then starts OverlayVpnService with the config as JSON.
// FragmentActivity (not ComponentActivity) because androidx.biometric's
// BiometricPrompt requires one; it is a ComponentActivity subclass, so
// Compose setContent and the activity-result launchers work unchanged.
class MainActivity : FragmentActivity() {

    private var pendingConfig: String? = null

    // App lock (biometric / screen-lock credential) — see AppLock.kt.
    private lateinit var appLock: AppLock

    override fun onStart() {
        super.onStart()
        // Prompt as soon as we're frontmost again (also covers launch).
        if (::appLock.isInitialized) appLock.unlock()
    }

    override fun onStop() {
        super.onStop()
        // Re-lock when leaving, so returning always re-authenticates.
        if (::appLock.isInitialized) appLock.lockIfEnabled()
    }

    // VpnService.prepare() consent flow.
    private val vpnConsent = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            pendingConfig?.let { startOverlay(it) }
        }
        pendingConfig = null
    }

    private lateinit var billing: BillingManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        billing = BillingManager(applicationContext)
        billing.start()
        appLock = AppLock(this)
        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                val state = remember { AppState() }
                var screen by remember { mutableStateOf(Screen.Main) }
                var scanned by remember { mutableStateOf<JoinInfo?>(null) }

                // Multi-network profiles: persisted list + selection. The
                // active profile is loaded into `state`; edits are written
                // back into its slot on connect, switch, and settings-close.
                val store = remember { ProfileStore(applicationContext) }
                val profiles = remember {
                    mutableStateListOf<JSONObject>().apply { addAll(store.loadAll()) }
                }
                var selectedNet by remember {
                    mutableStateOf(store.selected.coerceIn(0, profiles.size - 1))
                }
                var loadedOnce by remember { mutableStateOf(false) }
                if (!loadedOnce) {
                    state.applyProfileJson(profiles[selectedNet])
                    loadedOnce = true
                }
                fun persistCurrent() {
                    profiles[selectedNet] = state.toProfileJson()
                    store.saveAll(profiles)
                }
                fun switchNetwork(i: Int) {
                    if (i == selectedNet || i !in profiles.indices) return
                    disconnect()                    // tunnel keeps OLD net otherwise
                    persistCurrent()
                    selectedNet = i
                    store.selected = i
                    state.applyProfileJson(profiles[i])
                }
                fun addNetwork() {
                    disconnect()
                    persistCurrent()
                    profiles.add(JSONObject())
                    selectedNet = profiles.size - 1
                    store.selected = selectedNet
                    state.applyProfileJson(profiles[selectedNet])
                    store.saveAll(profiles)
                    screen = Screen.Settings        // fill in the new network
                }
                fun deleteNetwork() {
                    disconnect()
                    // Forget must be COMPLETE: wipe the core's persisted state
                    // (node key, stale admin-assigned IP provisions, admin key
                    // material) on the next connect, or rejoining this network
                    // announces a stale provisioned IP and gets no traffic.
                    store.wipeNonce = java.util.UUID.randomUUID().toString()
                    if (profiles.size > 1) {
                        profiles.removeAt(selectedNet)
                        selectedNet = selectedNet.coerceAtMost(profiles.size - 1)
                    } else {
                        profiles[0] = JSONObject()  // always keep one
                        selectedNet = 0
                    }
                    store.selected = selectedNet
                    state.applyProfileJson(profiles[selectedNet])
                    store.saveAll(profiles)
                }
                val scanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
                    result.contents?.let { scanned = JoinInfo.parse(it) }
                }
                val startScan = {
                    val opts = ScanOptions().apply {
                        setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                        setPrompt("Point at the APGO “Join QR” on the admin panel")
                        setBeepEnabled(true)
                        setOrientationLocked(false)
                    }
                    scanLauncher.launch(opts)
                }
                // Apply a scanned join QR to the shared state, whatever screen we're on.
                LaunchedEffect(scanned) {
                    scanned?.let {
                        state.network = it.networkName
                        state.psk = it.psk
                        it.overlayCidr?.let { c -> state.cidr = c }
                        state.rendezvous = it.rendezvousServers
                        // Credential travels with the servers, so joining an
                        // authenticated rendezvous stays "scan and go".
                        state.rendezvousAuth = it.rendezvousAuth
                        if (it.trackers.isNotEmpty()) state.trackers = it.trackers
                        it.cipher?.let { c -> state.cipher = c }
                        state.postQuantum = it.postQuantum
                        state.pqAuth = it.pqAuth
                    }
                }
                if (appLock.isLocked.value) {
                    // Locked: show ONLY the lock screen (no screen state leaks).
                    LockScreen(appLock)
                    return@MaterialTheme
                }
                when (screen) {
                    Screen.Support -> SupportScreen(billing = billing, activity = this,
                        onClose = { screen = Screen.Main })
                    Screen.Settings -> SettingsScreen(state = state, onScan = startScan,
                        appLock = appLock,
                        onClose = { persistCurrent(); screen = Screen.Main },
                        onDeleteNetwork = { deleteNetwork(); screen = Screen.Main })
                    Screen.Main -> MainScreen(
                        state = state,
                        networkNames = profiles.mapIndexed { i, p ->
                            if (i == selectedNet) state.network else p.optString("network")
                        },
                        selectedNet = selectedNet,
                        onSwitchNetwork = ::switchNetwork,
                        onAddNetwork = ::addNetwork,
                        onConnect = { persistCurrent(); connect(it) },
                        onDisconnect = ::disconnect,
                        onOpenSettings = { screen = Screen.Settings },
                        onSupport = { screen = Screen.Support },
                    )
                }
            }
        }
    }

    private fun connect(cfg: UiConfig) {
        val json = cfg.toJson(filesDir.absolutePath + "/node.key",
                              wipeNonce = ProfileStore(this).wipeNonce)
        val prep = VpnService.prepare(this)
        if (prep != null) {
            pendingConfig = json
            vpnConsent.launch(prep)
        } else {
            startOverlay(json)
        }
    }

    private fun startOverlay(json: String) {
        val i = Intent(this, OverlayVpnService::class.java).putExtra("configJSON", json)
        startForegroundService(i)
    }

    private fun disconnect() {
        startService(Intent(this, OverlayVpnService::class.java).setAction(OverlayVpnService.ACTION_STOP))
    }
}

// JoinInfo is the payload decoded from an admin panel's "join QR". It carries
// the full crypto profile (cipher + post-quantum flags) so a scanned device
// matches the network exactly — mismatches fail every handshake silently.
data class JoinInfo(
    val networkName: String,
    val psk: String,
    val overlayCidr: String?,
    val rendezvousServers: List<String>,
    val rendezvousAuth: String = "",     // credential for servers that require one
    val trackers: List<String> = emptyList(),  // this network's top trackers
    val cipher: String? = null,          // "chacha" or "aesgcm"
    val postQuantum: Boolean = true,     // quantum-safe by default
    val pqAuth: Boolean = true,
) {
    companion object {
        fun parse(s: String): JoinInfo? = try {
            val o = JSONObject(s)
            if (o.optString("kind", "apgo-join") != "apgo-join") null
            else {
                val n = o.optString("network_name")
                val p = o.optString("psk")
                if (n.isBlank() || p.isBlank()) null
                else {
                    val rv = mutableListOf<String>()
                    o.optJSONArray("rendezvous_servers")?.let { arr ->
                        for (i in 0 until arr.length()) rv.add(arr.getString(i))
                    }
                    val tr = mutableListOf<String>()
                    o.optJSONArray("trackers")?.let { arr ->
                        for (i in 0 until arr.length()) tr.add(arr.getString(i))
                    }
                    val cidr = o.optString("overlay_cidr").ifBlank { null }
                    JoinInfo(n, p, cidr, rv, o.optString("rendezvous_auth"), tr,
                        cipher = o.optString("cipher").ifBlank { null },
                        postQuantum = o.optBoolean("post_quantum", true),
                        pqAuth = o.optBoolean("pq_auth", true))
                }
            }
        } catch (e: Exception) { null }
    }
}

data class UiConfig(
    val networkName: String,
    val psk: String,
    val friendlyName: String,
    val overlayCidr: String,
    val lastOctet: String,
    val useExit: Boolean = false,
    val exitPeer: String = "",
    val rendezvousServers: List<String> = emptyList(),
    // Credential for rendezvous servers that require one. ONE field, two
    // schemes, auto-detected by the core: "user:password" sends HTTP Basic,
    // anything without a colon is sent as a Bearer token. Blank = none.
    val rendezvousAuth: String = "",
    val postQuantum: Boolean = true,   // quantum-safe by default
    val pqAuth: Boolean = true,        // quantum-safe by default
    val ipv6: Boolean = true,
    val cipher: String = "",           // "" = core default; set by join QR
    val trackers: List<String> = emptyList(),  // from join QR; core unions defaults
    val trackersEdited: Boolean = false, // user edited the list in Settings — it's authoritative
) {
    private fun prefix(): String {
        val net = overlayCidr.substringBefore('/')
        val p = net.split('.')
        return if (p.size >= 3) "${p[0]}.${p[1]}.${p[2]}." else "10.22.55."
    }

    fun overlayIp(): String = prefix() + (lastOctet.ifBlank { "30" })

    fun toJson(keyPath: String, wipeNonce: String = ""): String {
        return JSONObject().apply {
            // One-shot state wipe after "Delete this network" (nonce-guarded in
            // the core, so resending on every connect is harmless). Clears the
            // node key + stale admin-assigned IP provisions; without it a
            // rejoined network announced the old provisioned IP and the device
            // never received traffic until an admin re-assigned its address.
            if (wipeNonce.isNotBlank()) put("wipe_state_nonce", wipeNonce)
            put("network_name", networkName.trim())
            put("psk", psk.trim())
            put("friendly_name", friendlyName.trim())
            put("use_exit", useExit)
            put("exit_peer", exitPeer.trim())
            put("post_quantum", postQuantum)
            put("pq_auth", pqAuth)
            put("ipv6", ipv6)
            if (cipher.isNotBlank()) put("cipher", cipher)
            put("overlay_ip", overlayIp())
            put("overlay_cidr", overlayCidr.trim().ifBlank { "10.22.55.0/24" })
            put("key_path", keyPath)
            put("rendezvous_servers", JSONArray(rendezvousServers))
            put("rendezvous_auth", rendezvousAuth.trim())
            if (trackers.isNotEmpty()) put("trackers", JSONArray(trackers))
            // User-edited list is AUTHORITATIVE (persisted to the managed
            // trackers.txt, same semantics as the desktop tracker manager) —
            // removals stick instead of being unioned back with the defaults.
            put("manage_trackers", trackersEdited)
            put("stun_servers", JSONArray(listOf("stun.l.google.com:19302", "stun1.l.google.com:19302")))
            put("tun", JSONObject().put("mtu", 1280))
        }.toString()
    }
}

// Which top-level screen is showing.
private enum class Screen { Main, Settings, Support }

// ProfileStore persists the multi-network profile list + selection in
// SharedPreferences, so saved networks survive relaunches and the user can
// switch between them (mirrors the iOS app's OverlayConfig.loadAll/saveAll).
class ProfileStore(ctx: Context) {
    private val prefs = ctx.getSharedPreferences("apgo", Context.MODE_PRIVATE)

    fun loadAll(): MutableList<JSONObject> {
        val raw = prefs.getString("profiles", null) ?: return mutableListOf(JSONObject())
        return try {
            val arr = JSONArray(raw)
            if (arr.length() == 0) mutableListOf(JSONObject())
            else MutableList(arr.length()) { arr.getJSONObject(it) }
        } catch (e: Exception) { mutableListOf(JSONObject()) }
    }

    fun saveAll(list: List<JSONObject>) {
        prefs.edit().putString("profiles", JSONArray(list).toString()).apply()
    }

    var selected: Int
        get() = prefs.getInt("selected", 0)
        set(v) { prefs.edit().putInt("selected", v).apply() }

    // Set when the user deletes a network; sent as wipe_state_nonce on the next
    // connect so the core wipes its persisted overlay state exactly once
    // (mirrors the iOS app — see OverlayConfig.requestStateWipe).
    var wipeNonce: String
        get() = prefs.getString("wipeNonce", "") ?: ""
        set(v) { prefs.edit().putString("wipeNonce", v).apply() }
}

// AppState is the shared, observable form/config state, hoisted so the main
// screen and the settings screen edit the same values.
class AppState {
    var network by mutableStateOf("")
    var psk by mutableStateOf("")
    var friendly by mutableStateOf("")
    var cidr by mutableStateOf("10.22.55.0/24")
    var octet by mutableStateOf("30")
    var useExit by mutableStateOf(false)
    var exitPeer by mutableStateOf("")
    var postQuantum by mutableStateOf(true)
    var pqAuth by mutableStateOf(true)
    var ipv6 by mutableStateOf(true)
    var cipher by mutableStateOf("")
    var rendezvous by mutableStateOf<List<String>>(emptyList())
    var rendezvousAuth by mutableStateOf("")
    var trackers by mutableStateOf<List<String>>(emptyList())
    var trackersEdited by mutableStateOf(false)

    fun toUiConfig() = UiConfig(network, psk, friendly, cidr, octet, useExit, exitPeer,
        rendezvous, rendezvousAuth, postQuantum, pqAuth, ipv6, cipher, trackers, trackersEdited)

    companion object {
        // The core's curated default trackers (keep in sync with
        // ios/core/overlay.go defaultTrackers and config/trackers.txt). Shown
        // in the Settings editor when the user hasn't customized the list.
        val DEFAULT_TRACKERS = listOf(
            "udp://tracker.opentrackr.org:1337/announce",
            "udp://open.demonii.com:1337/announce",
            "udp://open.stealth.si:80/announce",
            "udp://exodus.desync.com:6969/announce",
            "udp://tracker.torrent.eu.org:451/announce",
            "udp://explodie.org:6969/announce",
            "udp://opentracker.io:6969/announce",
            "udp://tracker.dler.org:6969/announce",
        )
    }

    fun overlayIp(): String =
        cidr.substringBefore('/').split('.').take(3).joinToString(".", postfix = ".") +
            octet.ifBlank { "0" }

    /// Serialize this state as one network profile (for ProfileStore).
    fun toProfileJson(): JSONObject = JSONObject().apply {
        put("network", network); put("psk", psk); put("friendly", friendly)
        put("cidr", cidr); put("octet", octet)
        put("useExit", useExit); put("exitPeer", exitPeer)
        put("postQuantum", postQuantum); put("pqAuth", pqAuth); put("ipv6", ipv6)
        put("cipher", cipher)
        put("rendezvous", JSONArray(rendezvous)); put("rendezvousAuth", rendezvousAuth)
        put("trackers", JSONArray(trackers))
        put("trackersEdited", trackersEdited)
    }

    /// Load a network profile into this state (missing keys = defaults).
    fun applyProfileJson(o: JSONObject) {
        network = o.optString("network")
        psk = o.optString("psk")
        friendly = o.optString("friendly")
        cidr = o.optString("cidr").ifBlank { "10.22.55.0/24" }
        octet = o.optString("octet").ifBlank { "30" }
        useExit = o.optBoolean("useExit", false)
        exitPeer = o.optString("exitPeer")
        postQuantum = o.optBoolean("postQuantum", true)
        pqAuth = o.optBoolean("pqAuth", true)
        ipv6 = o.optBoolean("ipv6", true)
        cipher = o.optString("cipher")
        rendezvous = o.optJSONArray("rendezvous")?.let { a ->
            (0 until a.length()).map { a.getString(it) } } ?: emptyList()
        rendezvousAuth = o.optString("rendezvousAuth")
        trackers = o.optJSONArray("trackers")?.let { a ->
            (0 until a.length()).map { a.getString(it) } } ?: emptyList()
        trackersEdited = o.optBoolean("trackersEdited", false)
    }
}

// Peer is one entry from the Go core's session snapshot (SessionInfo JSON).
data class Peer(
    val remote: String,   // stable per-session table key (ip:port, or relay/<ip>)
    val overlayIp: String,
    val name: String,
    val keyFp: String,
    val established: Boolean,
    val postQuantum: Boolean,
    val isExit: Boolean,       // peer advertises as an internet exit node
    val activeExit: Boolean,   // the exit THIS device currently egresses through
    val lastSeenUnix: Long,
    // Admission control. The app could not previously see these at all, so a
    // device stuck in "pending" looked like a healthy peer that inexplicably
    // passed no traffic.
    val pubkey: String = "",   // base64 static key — the identity an approval names
    val approved: Boolean = true,
) {
    fun lastSeenText(): String {
        if (lastSeenUnix <= 0) return "—"
        val s = maxOf(0L, System.currentTimeMillis() / 1000 - lastSeenUnix)
        return when {
            s < 60 -> "${s}s ago"
            s < 3600 -> "${s / 60}m ago"
            else -> "${s / 3600}h ago"
        }
    }

    /// Numeric sort key for the overlay IPv4; non-IPs sort last.
    fun ipKey(): Long {
        val p = overlayIp.split(".").mapNotNull { it.toIntOrNull() }
        return if (p.size == 4)
            (p[0].toLong() shl 24) or (p[1].toLong() shl 16) or (p[2].toLong() shl 8) or p[3].toLong()
        else Long.MAX_VALUE
    }

    companion object {
        fun parseList(json: String): List<Peer> = try {
            val arr = JSONArray(json)
            (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                Peer(
                    o.optString("remote"),
                    o.optString("overlay_ip"),
                    o.optString("name"),
                    o.optString("key_fp"),
                    o.optBoolean("established"),
                    o.optBoolean("post_quantum"),
                    o.optBoolean("exit"),
                    o.optBoolean("active_exit"),
                    o.optLong("last_seen_unix"),
                    o.optString("pubkey"),
                    // Defaults to TRUE: a core build that predates this field
                    // is reporting nothing, not "unapproved", and marking every
                    // peer pending would be a false alarm on every row at once.
                    o.optBoolean("approved", true),
                )
            }
        } catch (e: Exception) { emptyList() }
    }
}

// MainScreen: connection control and the full-VPN toggle at the top, the live
// peers list in the middle, and a Support button at the bottom. The gear in the
// header opens Settings; nothing here reveals the network name or PSK.
@Composable
fun MainScreen(
    state: AppState,
    networkNames: List<String>,
    selectedNet: Int,
    onSwitchNetwork: (Int) -> Unit,
    onAddNetwork: () -> Unit,
    onConnect: (UiConfig) -> Unit,
    onDisconnect: () -> Unit,
    onOpenSettings: () -> Unit,
    onSupport: () -> Unit,
) {
    var connected by remember { mutableStateOf(false) }
    var peers by remember { mutableStateOf<List<Peer>>(emptyList()) }
    // Admission control, polled with the peer list.
    //   admissionRequired — this network gates devices (it has an admin key)
    //   selfApproved      — THIS device is allowed to pass data
    //   canSignApprovals  — we hold the sealed admin key, so we can approve
    //                       others given the password. It arrives by mesh
    //                       gossip, so it flips to true on its own shortly
    //                       after connecting.
    var admissionRequired by remember { mutableStateOf(false) }
    var selfApproved by remember { mutableStateOf(true) }
    var canSignApprovals by remember { mutableStateOf(false) }
    // Non-null while the approval dialog is open. The Peer is the target;
    // null-with-dialog-open means "approve this device".
    var approveTarget by remember { mutableStateOf<Peer?>(null) }
    var showApprove by remember { mutableStateOf(false) }
    var approvePassword by remember { mutableStateOf("") }
    var approveError by remember { mutableStateOf<String?>(null) }
    var approveBusy by remember { mutableStateOf(false) }
    val onApproveRequest: (Peer) -> Unit = { p ->
        approveTarget = p; approvePassword = ""; approveError = null; showApprove = true
    }
    // Full-VPN outproxy diagnostics from the core ({"use_exit","pin","exits":[…]}).
    var exits by remember { mutableStateOf<JSONObject?>(null) }
    // Network + data-path status from the core (NAT type, LAN discovery,
    // packet counters). Polled less often than the peer list: it changes
    // slowly and every poll is a wakeup.
    var netStatus by remember { mutableStateOf<JSONObject?>(null) }

    // Poll the running core (same process) for status + peers every few
    // seconds — but ONLY while the activity is visible. The VPN service keeps
    // this process alive in the background, so an unconditional while(true)
    // loop here kept waking the CPU every 3s all day with the screen off:
    // pure battery drain for a UI nobody is looking at. repeatOnLifecycle
    // cancels the loop at onStop and restarts it at onStart.
    val lifecycleOwner = androidx.compose.ui.platform.LocalLifecycleOwner.current
    LaunchedEffect(Unit) {
        lifecycleOwner.repeatOnLifecycle(androidx.lifecycle.Lifecycle.State.STARTED) {
        // Adaptive cadence, on screen only (repeatOnLifecycle already stops
        // this entirely in the background): 2s while the mesh is still
        // forming and the list changes constantly, then 6s for a settled
        // mesh the user is merely watching.
        var tick = 0
        while (true) {
            tick++
            connected = try { Overlaymobile.running() } catch (e: Throwable) { false }
            peers = if (connected) {
                // Sorted by overlay IP (low→high) so rows stay put between refreshes.
                try { Peer.parseList(Overlaymobile.peersJSON()).sortedBy { it.ipKey() } }
                catch (e: Throwable) { emptyList() }
            } else emptyList()
            if (connected) {
                admissionRequired = try { Overlaymobile.admissionRequired() } catch (e: Throwable) { false }
                selfApproved = try { Overlaymobile.selfApproved() } catch (e: Throwable) { true }
                canSignApprovals = try { Overlaymobile.adminKeyAvailable() } catch (e: Throwable) { false }
            } else {
                admissionRequired = false; selfApproved = true; canSignApprovals = false
            }
            exits = if (connected && state.useExit) {
                try { JSONObject(Overlaymobile.exitsJSON()) } catch (e: Throwable) { null }
            } else null
            netStatus = if (connected && (tick % 3 == 1 || netStatus == null)) {
                try { JSONObject(Overlaymobile.networkStatusJSON()) } catch (e: Throwable) { netStatus }
            } else if (connected) netStatus else null

            // Admin-assigned overlay address (signed provision from the network
            // admin panel) pending? The Go core receives it over the mesh but
            // can't re-address the OS tunnel — the app owns the VpnService
            // Builder. Adopt the new address into the profile and re-establish,
            // mirroring the iOS app. Without this, re-addressing an Android
            // device from the admin dashboard was silently ignored.
            if (connected) {
                val pending = try { Overlaymobile.pendingAddress() } catch (e: Throwable) { "" }
                val newIp = pending.substringBefore('/').trim()
                val newOctet = newIp.substringAfterLast('.', "")
                if (newIp.isNotEmpty() && newOctet.isNotEmpty() && newOctet != state.octet) {
                    state.octet = newOctet
                    onDisconnect()
                    delay(1500) // let the service tear down before re-establishing
                    onConnect(state.toUiConfig())
                }
            }
            delay(if (tick <= 15) 2000L else 6000L)
        }
        }
    }

    val configured = state.network.isNotBlank() && state.psk.isNotBlank()

    Surface(modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier.fillMaxSize().padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // Header: title + settings gear (top-right).
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("APGO", style = MaterialTheme.typography.headlineMedium)
                Spacer(Modifier.weight(1f))
                TextButton(onClick = onOpenSettings) { Text("⚙", fontSize = 22.sp) }
            }

            // Network switcher: pick which saved network to use, or add one.
            var netMenu by remember { mutableStateOf(false) }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box {
                    TextButton(onClick = { netMenu = true }) {
                        Text(networkNames.getOrNull(selectedNet)?.ifBlank { "New network" }
                            ?: "New network")
                        Text("  ▾", style = MaterialTheme.typography.bodySmall)
                    }
                    DropdownMenu(expanded = netMenu, onDismissRequest = { netMenu = false }) {
                        networkNames.forEachIndexed { i, n ->
                            DropdownMenuItem(
                                text = {
                                    Text((n.ifBlank { "New network" }) +
                                        if (i == selectedNet) "   ✓" else "")
                                },
                                onClick = { netMenu = false; onSwitchNetwork(i) })
                        }
                        HorizontalDivider()
                        DropdownMenuItem(
                            text = { Text("＋ Add network…") },
                            onClick = { netMenu = false; onAddNetwork() })
                    }
                }
                Spacer(Modifier.weight(1f))
            }

            // Connection status + control (top of everything).
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(if (connected) "● Connected" else "○ Disconnected")
                Spacer(Modifier.weight(1f))
                if (connected) {
                    Text(state.overlayIp(), style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace)
                }
            }
            if (connected) {
                Button(onClick = onDisconnect, modifier = Modifier.fillMaxWidth()) { Text("Disconnect") }
            } else {
                Button(
                    onClick = { if (configured) onConnect(state.toUiConfig()) else onOpenSettings() },
                    modifier = Modifier.fillMaxWidth()
                ) { Text(if (configured) "Connect" else "Set up your network…") }
            }

            // Full VPN. The VpnService only reads its config at start, so
            // flipping this while connected must restart the tunnel — without
            // that, the switch silently did nothing until the next manual
            // reconnect (which made full-VPN mode look broken).
            val scope = rememberCoroutineScope()
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("Full VPN")
                    Text(if (state.exitPeer.isBlank())
                        "Route all traffic via the fastest exit node"
                    else
                        "Route all traffic via the pinned exit only",
                        style = MaterialTheme.typography.bodySmall)
                }
                Switch(checked = state.useExit, onCheckedChange = {
                    state.useExit = it
                    if (connected) {
                        scope.launch {
                            onDisconnect()
                            delay(1500)   // let the old tunnel tear down fully
                            onConnect(state.toUiConfig())
                        }
                    }
                })
            }
            if (state.useExit) {
                Text("Needs at least one device on the mesh with exit-node mode enabled (a Linux server or a Mac — phones can't be exits). Exit-capable devices show a green E in the peer list.",
                    style = MaterialTheme.typography.bodySmall)
            }
            // Full VPN captures ALL traffic, so until an exit is selected the
            // internet is deliberately paused (fail-closed, no leaks). Show the
            // live outproxy state from the core so this is diagnosable on the
            // device instead of a dead end.
            if (state.useExit && connected) {
                val exArr = exits?.optJSONArray("exits")
                var selLabel: String? = null
                val known = StringBuilder()
                if (exArr != null) for (i in 0 until exArr.length()) {
                    val o = exArr.getJSONObject(i)
                    val label = o.optString("name").ifBlank { o.optString("overlay_ip") }
                    if (o.optBoolean("selected")) {
                        val rtt = o.optLong("rtt_ms", -1)
                        selLabel = label + if (rtt >= 0) " · $rtt ms" else ""
                    }
                    if (known.isNotEmpty()) known.append(", ")
                    known.append(label)
                    if (!o.optBoolean("reachable")) known.append(" (unreachable)")
                }
                if (selLabel != null) {
                    Text("✓ Exit: $selLabel",
                        style = MaterialTheme.typography.bodySmall, color = Color(0xFF3FB950))
                } else {
                    Text(if (peers.any { it.isExit })
                            "⚠ Connecting to an exit node… internet is paused until one is selected."
                        else
                            "⚠ No exit node is reachable — internet is paused. Enable exit-node mode on a Linux, macOS, or Windows node on this mesh (green E), or turn Full VPN off.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error)
                    val pin = exits?.optString("pin").orEmpty()
                    Text(if (exArr == null || exArr.length() == 0)
                            "Diagnostics: no exit announcement has reached this device. The exit must show “exit-node mode ON” in its log AND have a direct (●) session to this phone — a relayed exit can't carry traffic."
                        else
                            "Diagnostics: known exits — $known" +
                            (if (pin.isNotEmpty()) " · pinned to “$pin” — the pin must match the exit's name, IP, or fingerprint exactly" else ""),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.outline)
                }
            }
            if (state.useExit) {
                OutlinedTextField(state.exitPeer, { state.exitPeer = it },
                    label = { Text("Exit node (blank = fastest)") },
                    singleLine = true, modifier = Modifier.fillMaxWidth())
            }

            // NETWORK STATUS. Android never showed any of this, so the two
            // questions users actually ask — "why is everything relayed?" and
            // "why can I see peers but not reach them?" — had no answer here
            // at all. iOS grew these cards; this is the same information, from
            // the same core call, so the apps agree.
            if (connected) netStatus?.let { ns ->
                val nat = ns.optString("nat_type", "")
                if (nat.isNotEmpty()) {
                    val symmetric = nat.lowercase().contains("symmetric")
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(
                            (if (symmetric) "⚠ " else "✓ ") + "This device's NAT: $nat",
                            style = MaterialTheme.typography.bodySmall,
                            color = if (symmetric) Color(0xFFE6A400) else Color(0xFF2E7D32)
                        )
                        Text(
                            if (symmetric)
                                "A symmetric NAT gives this device no predictable port, so peers that are ALSO behind one can never connect directly — those stay relayed (still encrypted, just one extra hop). Wi-Fi is usually better than mobile data here."
                            else "Peers can connect directly to this device when their own network allows it.",
                            style = MaterialTheme.typography.bodySmall
                        )
                        // LAN discovery: "can't find my laptop on the same
                        // Wi-Fi" has two causes that look identical in the
                        // peer list, and only this number separates them.
                        val lanTargets = ns.optInt("lan_targets", -1)
                        if (lanTargets == 0) {
                            Text(
                                "Local network: cannot see any local addresses, so same-Wi‑Fi devices cannot be found.",
                                style = MaterialTheme.typography.bodySmall,
                                color = Color(0xFFE6A400)
                            )
                        } else if (lanTargets > 0 && !ns.optBoolean("lan_peer", false)) {
                            Text(
                                "Local network: scanning $lanTargets address(es), no same-Wi‑Fi peer yet. If one is running, the router may be isolating clients (guest Wi‑Fi / AP isolation).",
                                style = MaterialTheme.typography.bodySmall
                            )
                        } else if (ns.optBoolean("lan_peer", false)) {
                            Text("Local network: connected to a same-Wi‑Fi peer directly.",
                                style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }

                // DATA PATH. A peer showing "connected" only proves CONTROL
                // frames flow; reaching a service needs the DATA path, and
                // every way it can fail looks the same from the peer list.
                val txd = ns.optInt("tx_direct", -1)
                val rxd = ns.optInt("rx_data", -1)
                if (txd >= 0 && rxd >= 0) {
                    val txf = ns.optInt("tx_flood", 0)
                    val del = ns.optInt("rx_delivered", 0)
                    val rel = ns.optInt("rx_relayed", 0)
                    val rep = ns.optInt("rx_replay_drop", 0)
                    val dec = ns.optInt("rx_decrypt_fail", 0)
                    val problem = when {
                        txd == 0 && txf == 0 -> null
                        rxd == 0 -> "Sending, but nothing is coming back — the return path is blocked."
                        txd == 0 && txf > 0 -> "No direct route learned: every packet is being broadcast to all peers."
                        dec > 0 && dec * 4 > rxd -> "Many packets fail to decrypt — session keys are out of sync."
                        rep > 0 && rep * 20 > rxd -> "Packets arrive out of order and are dropped as replays."
                        del == 0 -> "Packets arrive but none are for this device — check the overlay address."
                        else -> null
                    }
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(
                            (if (problem == null) "✓ " else "⚠ ") + "Data path",
                            style = MaterialTheme.typography.bodySmall,
                            color = if (problem == null) Color(0xFF2E7D32) else Color(0xFFE6A400)
                        )
                        Text(
                            problem
                                ?: if (txd == 0 && txf == 0) "Idle — no traffic sent to peers yet."
                                else "Packets are flowing in both directions.",
                            style = MaterialTheme.typography.bodySmall,
                            color = if (problem == null) Color.Unspecified else Color(0xFFE6A400)
                        )
                        Text(
                            "sent $txd direct / $txf broadcast · received $rxd, $del delivered" +
                                (if (rel > 0) " ($rel relayed)" else "") +
                                (if (rep > 0 || dec > 0) " · dropped $rep out-of-order, $dec undecryptable" else ""),
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            }

            // NOT APPROVED. Peers accept this device's control traffic, so it
            // appears in their lists looking perfectly healthy while every
            // packet of real data is dropped. From here that presents as
            // "connected, but nothing works".
            if (connected && admissionRequired && !selfApproved) {
                Column(
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("\u26a0 This device is not approved",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFFE6A400))
                    Text("Peers show it as connected but discard all of its data, so nothing is " +
                         "reachable. Approve it from the admin panel of another node that holds " +
                         "the network admin key — a device cannot approve itself.",
                        style = MaterialTheme.typography.bodySmall)
                }
            }

            // Peers (weighted so the list scrolls and the Support button stays put).
            Text("Peers (${peers.size})", style = MaterialTheme.typography.titleSmall)
            LazyColumn(
                modifier = Modifier.weight(1f).fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                if (peers.isEmpty()) {
                    item {
                        Text(if (connected) "No peers yet — discovering…" else "Connect to see peers.",
                            style = MaterialTheme.typography.bodySmall)
                    }
                } else {
                    // Key each row by the core's stable unique `remote` (prefixed
                    // with the index to stay collision-proof even against older
                    // cores that don't emit `remote`, since Compose crashes on
                    // duplicate keys). Keeps scroll/animation state attached to the
                    // right device across refreshes.
                    itemsIndexed(peers, key = { i, p -> "$i:${p.remote}" }) { _, p ->
                        PeerRow(p, canApprove = canSignApprovals, onApprove = onApproveRequest)
                    }
                }
            }

            // Support at the bottom.
            Button(onClick = onSupport, modifier = Modifier.fillMaxWidth()) { Text("♥ Support APGO") }

            // Approval dialog. Signs with the network admin key (unsealed from
            // the password, in memory, for the duration of one signature) and
            // gossips the record to the mesh — the same thing the desktop and
            // container dashboards do, so peers accept it identically.
            if (showApprove) {
                val label = approveTarget?.let {
                    if (it.overlayIp.isBlank()) it.keyFp else it.overlayIp
                } ?: "\u2014"
                AlertDialog(
                    onDismissRequest = { if (!approveBusy) showApprove = false },
                    title = { Text("Approve $label") },
                    text = {
                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            approveTarget?.name?.takeIf { it.isNotBlank() }?.let {
                                Text(it, style = MaterialTheme.typography.bodySmall)
                            }
                            OutlinedTextField(
                                value = approvePassword,
                                onValueChange = { approvePassword = it; approveError = null },
                                label = { Text("Network admin password") },
                                singleLine = true,
                                visualTransformation = PasswordVisualTransformation(),
                                modifier = Modifier.fillMaxWidth(),
                            )
                            approveError?.let {
                                Text(it, style = MaterialTheme.typography.bodySmall,
                                     color = MaterialTheme.colorScheme.error)
                            }
                        }
                    },
                    confirmButton = {
                        TextButton(
                            enabled = approvePassword.isNotBlank() && !approveBusy,
                            onClick = {
                                approveBusy = true
                                approveError = null
                                scope.launch {
                                    val err = withContext(Dispatchers.IO) {
                                        // Only ever a SELECTED PEER. A device
                                        // cannot approve itself; an approval
                                        // must come from an admin elsewhere.
                                        val target = approveTarget?.pubkey ?: ""
                                        if (target.isBlank()) "No device selected."
                                        else try {
                                            Overlaymobile.approveDevice(approvePassword, target, "approve")
                                            null
                                        } catch (e: Throwable) {
                                            e.message ?: "Approval failed."
                                        }
                                    }
                                    approveBusy = false
                                    if (err != null) {
                                        approveError = err
                                    } else {
                                        approvePassword = ""
                                        showApprove = false
                                        approveTarget = null
                                        // Reflect the result immediately; waiting
                                        // for the next poll reads as "did that
                                        // work?".
                                        selfApproved = try { Overlaymobile.selfApproved() } catch (e: Throwable) { selfApproved }
                                        peers = try {
                                            Peer.parseList(Overlaymobile.peersJSON()).sortedBy { it.ipKey() }
                                        } catch (e: Throwable) { peers }
                                    }
                                }
                            }) { Text(if (approveBusy) "Approving\u2026" else "Approve") }
                    },
                    dismissButton = {
                        TextButton(enabled = !approveBusy,
                            onClick = { showApprove = false; approveTarget = null }) { Text("Cancel") }
                    })
            }
            Text(
                "© 2026 The APGO Team · Another Pretty Good Overlay\nFree & open source, GPL-3.0-or-later",
                style = MaterialTheme.typography.labelSmall,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth()
            )
        }
    }
}

@Composable
fun PeerRow(p: Peer, canApprove: Boolean = false, onApprove: (Peer) -> Unit = {}) {
    val pending = !p.approved && p.pubkey.isNotBlank()
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        modifier = Modifier
            .fillMaxWidth()
            .then(if (pending && canApprove) Modifier.clickable { onApprove(p) } else Modifier)
    ) {
        Text(if (p.established) "●" else "○")
        Column(Modifier.weight(1f)) {
            Text(if (p.overlayIp.isBlank()) p.keyFp else p.overlayIp,
                fontFamily = FontFamily.Monospace)
            if (p.name.isNotBlank()) {
                Text(p.name, style = MaterialTheme.typography.bodySmall)
            }
        }
        // Exit badges. Green "E" = this device can be an exit node for the VPN
        // relay; the highlighted badge = the exit THIS device's internet
        // traffic currently egresses through (full VPN).
        if (p.activeExit) {
            Text("\uD83C\uDF10 EXIT", style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.primary)
        }
        if (p.isExit) {
            Text("E", style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.Bold,
                color = Color(0xFF3FB950))
        }
        if (p.postQuantum) Text("PQ", style = MaterialTheme.typography.labelSmall)
        if (pending) {
            Text(
                if (canApprove) "PENDING \u2013 TAP" else "PENDING",
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.Bold,
                color = Color(0xFFE3B341),
            )
        }
        Text(p.lastSeenText(), style = MaterialTheme.typography.labelSmall)
    }
}

// SettingsScreen: network identity, this device's overlay address, and the
// security/transport toggles. Reached from the gear on the main screen.
@Composable
fun SettingsScreen(
    state: AppState,
    onScan: () -> Unit,
    onClose: () -> Unit,
    onDeleteNetwork: (() -> Unit)? = null,
    appLock: AppLock? = null,
) {
    Surface(modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Settings", style = MaterialTheme.typography.headlineMedium)
                Spacer(Modifier.weight(1f))
                TextButton(onClick = onClose) { Text("Done") }
            }

            Button(onClick = onScan, modifier = Modifier.fillMaxWidth()) { Text("Scan QR to join") }

            OutlinedTextField(state.network, { state.network = it }, label = { Text("Network name") },
                singleLine = true, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(state.psk, { state.psk = it }, label = { Text("Pre-shared key (base64:…)") },
                singleLine = true, visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth())
            OutlinedTextField(state.friendly, { state.friendly = it },
                label = { Text("This device's name (optional)") },
                singleLine = true, modifier = Modifier.fillMaxWidth())
            Text("Use the same network name and PSK on every device.",
                style = MaterialTheme.typography.bodySmall)

            OutlinedTextField(state.cidr, { state.cidr = it }, label = { Text("Overlay subnet (CIDR)") },
                singleLine = true, modifier = Modifier.fillMaxWidth())
            Row(verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(state.cidr.substringBefore('/').split('.').take(3).joinToString(".", postfix = "."))
                OutlinedTextField(state.octet, { state.octet = it.filter { c -> c.isDigit() }.take(3) },
                    label = { Text("last octet") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    singleLine = true, modifier = Modifier.width(120.dp))
            }

            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("Post-quantum encryption")
                    Text("Adds a hybrid ML-KEM-768 layer (future-proof). Enable on every device.",
                        style = MaterialTheme.typography.bodySmall)
                }
                Switch(checked = state.postQuantum, onCheckedChange = { state.postQuantum = it })
            }

            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("IPv6 dual-stack transport")
                    Text("Connects directly over IPv6 where available (no NAT) — fixes hotspot/CGNAT reachability. Overlay stays IPv4. Reconnect to apply.",
                        style = MaterialTheme.typography.bodySmall)
                }
                Switch(checked = state.ipv6, onCheckedChange = { state.ipv6 = it })
            }

            if (appLock != null) {
                val lockAvailable = appLock.available()
                var lockOn by remember { mutableStateOf(appLock.enabled) }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("App lock (biometric)")
                        Text(if (lockAvailable)
                                "Requires your fingerprint, face, or screen lock to open the app (settings, PSK, and peer list). The VPN keeps running while locked."
                             else
                                "Set up a screen lock on this device to use the app lock.",
                            style = MaterialTheme.typography.bodySmall)
                    }
                    Switch(checked = lockOn, enabled = lockAvailable, onCheckedChange = { on ->
                        // Enabling prompts for auth first; the switch reflects
                        // the state actually in effect (snaps back on failure).
                        appLock.setEnabled(on) { ok -> lockOn = ok }
                    })
                }
            }

            // Rendezvous: HTTPS discovery for networks that block BitTorrent.
            // Normally arrives via the join QR (servers AND credential), but
            // must be enterable by hand too — a device added without a QR, or
            // a server whose password rotated.
            var rendezvousText by remember {
                mutableStateOf(state.rendezvous.joinToString("\n"))
            }
            // The credential is ONE stored string ("user:pass" or a bare
            // token) but edited as two fields — a single box meaning two
            // different things depending on a colon is unusable.
            var rvUser by remember {
                mutableStateOf(state.rendezvousAuth.substringBefore(":"))
            }
            var rvPass by remember {
                mutableStateOf(
                    if (state.rendezvousAuth.contains(":"))
                        state.rendezvousAuth.substringAfter(":") else ""
                )
            }
            fun commitRvAuth() {
                val u = rvUser.trim(); val p = rvPass.trim()
                state.rendezvousAuth = if (p.isEmpty()) u else "$u:$p"
            }
            HorizontalDivider()
            Text("Rendezvous servers", style = MaterialTheme.typography.titleSmall)
            OutlinedTextField(
                value = rendezvousText,
                onValueChange = {
                    rendezvousText = it
                    state.rendezvous = it.lines().map { l -> l.trim() }
                        .filter { l -> l.isNotEmpty() }.distinct()
                },
                label = { Text("One HTTPS URL per line") },
                modifier = Modifier.fillMaxWidth().heightIn(min = 60.dp),
            )
            OutlinedTextField(
                value = rvUser,
                onValueChange = { rvUser = it; commitRvAuth() },
                label = { Text("Username or token (optional)") },
                singleLine = true, modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = rvPass,
                onValueChange = { rvPass = it; commitRvAuth() },
                label = { Text("Password (blank if using a token)") },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth(),
            )
            Text("Used instead of (or alongside) trackers where BitTorrent is blocked. Credentials are only needed if your server requires them — enter a username AND password, or just a token in the first box.",
                style = MaterialTheme.typography.bodySmall)

            // Trackers editor — same list and semantics as the desktop app's
            // tracker manager. Displayed/edited in the trackers.txt format:
            // one tracker per line, separated by one blank line. Parsed
            // tolerantly (blank lines skipped); once edited, the list is
            // authoritative (removals stick).
            var trackersText by remember {
                mutableStateOf(
                    (if (state.trackers.isEmpty() && !state.trackersEdited)
                        AppState.DEFAULT_TRACKERS else state.trackers)
                        .joinToString("\n\n")
                )
            }
            Text("Trackers", style = MaterialTheme.typography.titleSmall)
            OutlinedTextField(
                value = trackersText,
                onValueChange = {
                    trackersText = it
                    state.trackers = it.lines().map { l -> l.trim() }
                        .filter { l -> l.isNotEmpty() }.distinct()
                    state.trackersEdited = true
                },
                label = { Text("One per line, blank line between") },
                modifier = Modifier.fillMaxWidth().heightIn(min = 180.dp),
            )
            TextButton(onClick = {
                trackersText = AppState.DEFAULT_TRACKERS.joinToString("\n\n")
                state.trackers = AppState.DEFAULT_TRACKERS
                state.trackersEdited = true
            }) { Text("Reset to defaults") }
            Text("These help nodes discover each other — same list as the desktop app's tracker manager. Reconnect to apply.",
                style = MaterialTheme.typography.bodySmall)

            if (onDeleteNetwork != null) {
                var confirmDelete by remember { mutableStateOf(false) }
                HorizontalDivider()
                TextButton(onClick = { confirmDelete = true }) {
                    Text("Delete this network",
                        color = MaterialTheme.colorScheme.error)
                }
                Text("Removes \"${state.network.ifBlank { "New network" }}\" from this device only.",
                    style = MaterialTheme.typography.bodySmall)
                if (confirmDelete) {
                    AlertDialog(
                        onDismissRequest = { confirmDelete = false },
                        title = { Text("Delete \"${state.network.ifBlank { "New network" }}\"?") },
                        text = { Text("Other devices on the network are unaffected.") },
                        confirmButton = {
                            TextButton(onClick = {
                                confirmDelete = false
                                onDeleteNetwork()
                            }) { Text("Delete", color = MaterialTheme.colorScheme.error) }
                        },
                        dismissButton = {
                            TextButton(onClick = { confirmDelete = false }) { Text("Cancel") }
                        })
                }
            }
        }
    }
}
