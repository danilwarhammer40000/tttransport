package com.tt.transport

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat

// NOTE: `gomobilebridge` here needs a StartVpnTunnel entry point that
// doesn't exist yet in android/gomobilebridge/bridge.go -- see
// android/vpntun/README.md for the Go side (gVisor netstack, isolated
// module, needs `go mod tidy` with network access). This file is
// written against the intended API; it will not compile until that
// Go-side function is added and a fresh .aar is built.
import gomobilebridge.Gomobilebridge
import gomobilebridge.VpnTunnelHandle

/**
 * The actual VPN: creates a TUN interface via VpnService.Builder,
 * applies split-tunnel app selection (AppSelectionStore), and hands the
 * raw TUN file descriptor to the Go side, which runs a userspace TCP/IP
 * stack (gVisor netstack, in android/vpntun/) that turns intercepted
 * TCP connections into CONNECT calls against our existing
 * client.Client -- the tunnel protocol itself is completely unchanged
 * from the manual CONNECT demo in MainActivity.
 */
class TurboflareVpnService : VpnService() {

    private var tunFd: ParcelFileDescriptor? = null
    private var tunnelHandle: VpnTunnelHandle? = null

    companion object {
        const val ACTION_START = "com.tt.transport.action.START_VPN"
        const val ACTION_STOP = "com.tt.transport.action.STOP_VPN"
        private const val NOTIFICATION_CHANNEL_ID = "turboflare_vpn"
        private const val NOTIFICATION_ID = 1
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopTunnel()
                stopSelf()
                return START_NOT_STICKY
            }
            else -> startTunnel()
        }
        return START_STICKY
    }

    private fun startTunnel() {
        if (tunnelHandle != null) return // already running

        if (!ServerConfig.isConfigured(applicationContext)) {
            stopSelf()
            return
        }

        startForeground(NOTIFICATION_ID, buildNotification())

        val builder = Builder()
            .setSession("TurboFlare Transport")
            .addAddress("10.0.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("1.1.1.1")
            .setMtu(1500)

        // Split tunnel: per the fixed design, ONLY the selected apps'
        // traffic enters the tunnel. Android's VpnService semantics:
        // calling addAllowedApplication at least once switches the VPN
        // into allow-list mode (everything NOT listed bypasses the
        // tunnel automatically) -- exactly the "only selected apps go
        // through" behavior requested. An empty selection falls back to
        // tunneling everything (no addAllowedApplication calls at all),
        // rather than silently tunneling nothing.
        val selected = AppSelectionStore.getSelectedPackages(applicationContext)
        for (pkg in selected) {
            try {
                builder.addAllowedApplication(pkg)
            } catch (e: PackageManager.NameNotFoundException) {
                // app was uninstalled since being selected -- skip it
            }
        }

        val pfd = builder.establish() ?: run {
            stopSelf()
            return
        }
        tunFd = pfd

        val baseUrl = ServerConfig.getBaseUrl(applicationContext)
        val serverPubHex = ServerConfig.getServerPubHex(applicationContext)
        val token = ServerConfig.getToken(applicationContext)
        val deviceIdHex = DeviceIdentity.getOrCreate(applicationContext)

        // detachFd(): ownership of the underlying fd moves to the Go
        // side from here on; Go is responsible for closing it when the
        // tunnel stops (see android/vpntun).
        val rawFd = pfd.detachFd()

        // FIX (found via real-device testing): startVpnTunnel can return
        // a Go error (e.g. a transient handshake failure right after a
        // previous tunnel was stopped) -- gomobile surfaces that as a
        // thrown exception here, which was previously uncaught and
        // crashed the whole app. Now it's treated as a failed start:
        // log it, clean up, and stop the service instead of crashing.
        try {
            tunnelHandle = Gomobilebridge.startVpnTunnel(
                rawFd.toLong(),
                baseUrl,
                serverPubHex,
                deviceIdHex,
                token
            )
        } catch (e: Exception) {
            android.util.Log.e("TurboflareVpnService", "startVpnTunnel failed: ${e.message}", e)
            tunFd = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    private fun stopTunnel() {
        tunnelHandle?.stop()
        tunnelHandle = null
        tunFd?.close()
        tunFd = null
    }

    private fun buildNotification(): Notification {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "TurboFlare VPN",
                NotificationManager.IMPORTANCE_LOW
            )
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(channel)
        }

        val stopIntent = Intent(this, TurboflareVpnService::class.java).apply {
            action = ACTION_STOP
        }
        val stopPendingIntent = PendingIntent.getService(
            this, 0, stopIntent,
            PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle("TurboFlare Transport")
            .setContentText("VPN tunnel active")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .addAction(0, "Stop", stopPendingIntent)
            .setOngoing(true)
            .build()
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }

    override fun onRevoke() {
        // User revoked VPN permission from system settings.
        stopTunnel()
        stopSelf()
        super.onRevoke()
    }
}
