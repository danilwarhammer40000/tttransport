package com.tt.transport

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager

/**
 * Split-tunnel app selection: the set of package names whose traffic
 * should go through the VPN tunnel. Everything else bypasses it
 * (normal direct internet access) -- this is the "only selected apps"
 * mode requested, implemented via Android's native
 * VpnService.Builder.addAllowedApplication() per package, rather than
 * anything in our own protocol (the protocol has no concept of "which
 * app" -- that's handled entirely at the TUN/VpnService layer).
 */
object AppSelectionStore {
    private const val PREFS_NAME = "turboflare_app_selection"
    private const val KEY_SELECTED_PACKAGES = "selected_packages"

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun getSelectedPackages(context: Context): Set<String> =
        prefs(context).getStringSet(KEY_SELECTED_PACKAGES, emptySet()) ?: emptySet()

    fun setSelectedPackages(context: Context, packages: Set<String>) {
        prefs(context).edit().putStringSet(KEY_SELECTED_PACKAGES, packages).apply()
    }

    /**
     * Lists user-installed, launchable apps (skips system apps with no
     * launcher icon -- those are almost never what someone wants to
     * split-tunnel individually, and including them would make the
     * picker list hundreds of entries long).
     */
    data class AppEntry(val packageName: String, val label: String)

    fun listSelectableApps(context: Context): List<AppEntry> {
        val pm = context.packageManager
        val launcherIntent = android.content.Intent(android.content.Intent.ACTION_MAIN).apply {
            addCategory(android.content.Intent.CATEGORY_LAUNCHER)
        }
        val resolved = pm.queryIntentActivities(launcherIntent, 0)
        return resolved
            .map { it.activityInfo.applicationInfo }
            .distinctBy { it.packageName }
            .filter { it.packageName != context.packageName } // don't offer to tunnel ourselves
            .map { AppEntry(it.packageName, it.loadLabel(pm).toString()) }
            .sortedBy { it.label.lowercase() }
    }
}
