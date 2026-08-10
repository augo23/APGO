package org.apgo.app

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity

/**
 * AppLock gates the UI behind the device biometric (fingerprint/face) or the
 * screen-lock credential — the Android counterpart of the iOS Face ID app
 * lock. It protects what's on screen (PSK, peer list, settings), NOT the
 * tunnel: the VPN keeps running while the app is locked.
 *
 * Behavior mirrors iOS:
 *  - locks on launch and whenever the app leaves the foreground,
 *  - enabling the toggle requires one successful auth first,
 *  - biometrics fall back to the device PIN/pattern/password, so a failed
 *    fingerprint can never lock the user out.
 */
class AppLock(private val activity: FragmentActivity) {
    private val prefs = activity.getSharedPreferences("apgo", Context.MODE_PRIVATE)

    /** Whether the UI is currently hidden behind the lock screen. */
    val isLocked = mutableStateOf(prefs.getBoolean(KEY, false))

    /** Last auth failure message, shown on the lock screen ("" = none). */
    val lastError = mutableStateOf("")

    private var promptShowing = false

    val enabled: Boolean
        get() = prefs.getBoolean(KEY, false)

    /** Whether the device can authenticate at all (biometric OR screen lock). */
    fun available(): Boolean =
        BiometricManager.from(activity)
            .canAuthenticate(BIOMETRIC_WEAK or DEVICE_CREDENTIAL) == BiometricManager.BIOMETRIC_SUCCESS

    /**
     * Flip the setting. Turning it ON prompts for authentication first and
     * only persists on success; onResult receives the state actually in effect.
     */
    fun setEnabled(on: Boolean, onResult: (Boolean) -> Unit = {}) {
        if (!on) {
            prefs.edit().putBoolean(KEY, false).apply()
            isLocked.value = false
            onResult(false)
            return
        }
        authenticate("Confirm your screen lock to enable the app lock") { ok ->
            if (ok) prefs.edit().putBoolean(KEY, true).apply()
            onResult(ok)
        }
    }

    /** Called when the app leaves the foreground. */
    fun lockIfEnabled() {
        if (enabled) isLocked.value = true
    }

    /** Prompt and unlock (no-op when already unlocked or a prompt is up). */
    fun unlock() {
        if (!isLocked.value || promptShowing) return
        authenticate("Unlock APGO") { ok ->
            if (ok) {
                isLocked.value = false
                lastError.value = ""
            }
        }
    }

    private fun authenticate(title: String, onResult: (Boolean) -> Unit) {
        if (!available()) {
            lastError.value = "No screen lock is set up on this device."
            onResult(false)
            return
        }
        promptShowing = true
        val prompt = BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    promptShowing = false
                    onResult(true)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    // User cancelled or the prompt errored — stay locked; the
                    // lock screen's Unlock button re-prompts.
                    promptShowing = false
                    lastError.value = errString.toString()
                    onResult(false)
                }

                override fun onAuthenticationFailed() {
                    // Wrong finger/face — the system prompt stays up for retries.
                }
            })
        prompt.authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setAllowedAuthenticators(BIOMETRIC_WEAK or DEVICE_CREDENTIAL)
                .build()
        )
    }

    companion object {
        private const val KEY = "app_lock_enabled"
    }
}

/** Full-screen cover shown while locked — nothing underneath is visible. */
@Composable
fun LockScreen(appLock: AppLock) {
    Surface(modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier.fillMaxSize().padding(32.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text("APGO is locked", style = MaterialTheme.typography.headlineSmall)
            if (appLock.lastError.value.isNotEmpty()) {
                Text(
                    appLock.lastError.value,
                    style = MaterialTheme.typography.bodySmall,
                    textAlign = TextAlign.Center
                )
            }
            Button(onClick = { appLock.unlock() }) { Text("Unlock") }
        }
    }
}
