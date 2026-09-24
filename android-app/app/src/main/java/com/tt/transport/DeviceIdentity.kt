package com.tt.transport

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.SecureRandom

/**
 * Generates and persists the device's permanent device_id, per
 * PROTOCOL.md §0: created ONCE, never regenerated, never tied to
 * hardware identifiers (IMEI etc. -- deliberately just local random
 * bytes, since binding is via the provisioning token/account, not
 * hardware -- see server/binding.go).
 *
 * Stored in EncryptedSharedPreferences (Android Jetpack Security) so it
 * survives app restarts but isn't trivially readable by other apps.
 */
object DeviceIdentity {
    private const val PREFS_NAME = "turboflare_device_identity"
    private const val KEY_DEVICE_ID_HEX = "device_id_hex"

    fun getOrCreate(context: Context): String {
        val prefs = encryptedPrefs(context)
        prefs.getString(KEY_DEVICE_ID_HEX, null)?.let { return it }

        val bytes = ByteArray(8)
        SecureRandom().nextBytes(bytes)
        val hex = bytes.joinToString("") { "%02x".format(it) }

        prefs.edit().putString(KEY_DEVICE_ID_HEX, hex).apply()
        return hex
    }

    private fun encryptedPrefs(context: Context) = EncryptedSharedPreferences.create(
        context,
        PREFS_NAME,
        MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )
}
