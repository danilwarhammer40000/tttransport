package com.tt.transport

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Server connection config (base URL, server's static X25519 pubkey,
 * provisioning token) -- previously hardcoded in MainActivity.kt,
 * now stored on-device so the app doesn't need to be rebuilt every
 * time you point it at a different server (per the earlier discussion
 * about not baking server_pub/token into the APK).
 *
 * This is a minimal first step: values are entered once via a simple
 * dialog (see MainActivity.promptForConfigIfNeeded) and persisted.
 * A full provisioning-link/QR-code flow (server_pub+token+base_url
 * encoded in one link) is a natural next iteration on top of this,
 * without changing where the values ultimately get stored.
 */
object ServerConfig {
    private const val PREFS_NAME = "server_config"
    private const val KEY_BASE_URL = "base_url"
    private const val KEY_SERVER_PUB_HEX = "server_pub_hex"
    private const val KEY_TOKEN = "provision_token"

    private fun prefs(context: Context) = EncryptedSharedPreferences.create(
        context,
        PREFS_NAME,
        MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    fun isConfigured(context: Context): Boolean {
        val p = prefs(context)
        return !p.getString(KEY_BASE_URL, null).isNullOrBlank() &&
            !p.getString(KEY_SERVER_PUB_HEX, null).isNullOrBlank() &&
            !p.getString(KEY_TOKEN, null).isNullOrBlank()
    }

    fun getBaseUrl(context: Context): String =
        prefs(context).getString(KEY_BASE_URL, "") ?: ""

    fun getServerPubHex(context: Context): String =
        prefs(context).getString(KEY_SERVER_PUB_HEX, "") ?: ""

    fun getToken(context: Context): String =
        prefs(context).getString(KEY_TOKEN, "") ?: ""

    fun save(context: Context, baseUrl: String, serverPubHex: String, token: String) {
        prefs(context).edit()
            .putString(KEY_BASE_URL, baseUrl.trim())
            .putString(KEY_SERVER_PUB_HEX, serverPubHex.trim())
            .putString(KEY_TOKEN, token.trim())
            .apply()
    }

    fun clear(context: Context) {
        prefs(context).edit().clear().apply()
    }
}
