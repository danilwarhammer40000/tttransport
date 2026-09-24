package com.tt.transport

import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

// NOTE: `gomobilebridge` below is the package produced by:
//   gomobile bind -target=android -o gomobilebridge.aar ./android/gomobilebridge
// per android/README.md. This file assumes that .aar has been built and
// added as a module dependency.
import gomobilebridge.Gomobilebridge
import gomobilebridge.SessionHandle

class MainActivity : AppCompatActivity() {

    // `session` is a manual, standalone protocol session used ONLY by
    // the "Test CONNECT + HTTP fetch" diagnostic button -- separate
    // from the actual VPN tunnel, which manages its own per-flow
    // sessions internally (see android/vpntun/tunnel.go). Conflating
    // the two would make the diagnostic button's state depend on
    // whether the VPN happens to be running, which isn't the intent.
    private var session: SessionHandle? = null
    private var vpnRunning = false

    private lateinit var logView: TextView
    private lateinit var scroll: ScrollView
    private lateinit var btnPower: Button
    private lateinit var tvConnState: TextView
    private lateinit var tvPowerHint: TextView
    private lateinit var tvServerUrl: TextView
    private lateinit var tvConnectionId: TextView

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startVpnServiceNow()
        } else {
            appendLog("VPN permission denied")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        logView = findViewById(R.id.logView)
        scroll = findViewById(R.id.logScroll)
        btnPower = findViewById(R.id.btnPower)
        tvConnState = findViewById(R.id.tvConnState)
        tvPowerHint = findViewById(R.id.tvPowerHint)
        tvServerUrl = findViewById(R.id.tvServerUrl)
        tvConnectionId = findViewById(R.id.tvConnectionId)
        val tvBuildVersion = findViewById<TextView>(R.id.tvBuildVersion)
        // Reading the version directly from the just-loaded .aar is the
        // most reliable way to confirm a rebuild actually picked up the
        // latest Go code -- a real, recurring problem during iterative
        // on-device debugging (mismatched/stale .aar copies).
        tvBuildVersion.text = try {
            "build: ${Gomobilebridge.version()}"
        } catch (e: Exception) {
            "build: unknown (old .aar?)"
        }

        btnPower.setOnClickListener { onPowerClicked() }
        findViewById<Button>(R.id.btnTestMode).setOnClickListener { onTestModeClicked() }
        findViewById<Button>(R.id.btnPushHello).setOnClickListener { onConnectAndFetchClicked() }
        findViewById<Button>(R.id.btnSettings).setOnClickListener { promptForConfig() }
        findViewById<Button>(R.id.btnSelectApps).setOnClickListener { openAppSelection() }
        findViewById<TextView>(R.id.btnCopyLogs).setOnClickListener { onCopyLogsClicked() }
        findViewById<TextView>(R.id.btnClearLogs).setOnClickListener { onClearLogsClicked() }

        findViewById<LinearLayout>(R.id.navHome).setOnClickListener { /* already here */ }
        findViewById<LinearLayout>(R.id.navApps).setOnClickListener { openAppSelection() }
        findViewById<LinearLayout>(R.id.navSettings).setOnClickListener { promptForConfig() }

        registerNetworkCallback()
        refreshServerCard()
        updatePowerUi()

        if (!ServerConfig.isConfigured(applicationContext)) {
            promptForConfig()
        }
    }

    private fun openAppSelection() {
        startActivity(Intent(this, AppSelectionActivity::class.java))
    }

    private fun refreshServerCard() {
        val url = ServerConfig.getBaseUrl(applicationContext)
        tvServerUrl.text = if (url.isBlank()) "not configured" else url
        val connId = session?.connectionIDHex()
        tvConnectionId.text = "connection_id: ${connId ?: "—"}"
    }

    private fun updatePowerUi() {
        if (vpnRunning) {
            btnPower.setBackgroundResource(R.drawable.bg_power_button_on)
            tvConnState.text = "ONLINE"
            tvConnState.setTextColor(resources.getColor(R.color.accent, theme))
            tvPowerHint.text = "Туннель активен — нажмите для отключения"
        } else {
            btnPower.setBackgroundResource(R.drawable.bg_power_button_off)
            tvConnState.text = "OFFLINE"
            tvConnState.setTextColor(resources.getColor(R.color.text_muted, theme))
            tvPowerHint.text = "Нажмите для подключения"
        }
    }

    /** Power button toggles the actual VPN tunnel (Start/Stop). */
    private fun onPowerClicked() {
        if (!ServerConfig.isConfigured(applicationContext)) {
            appendLog("configure server settings first")
            promptForConfig()
            return
        }
        if (vpnRunning) {
            stopVpn()
        } else {
            startVpn()
        }
    }

    private fun startVpn() {
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            vpnPermissionLauncher.launch(prepareIntent)
        } else {
            startVpnServiceNow()
        }
    }

    private fun startVpnServiceNow() {
        val intent = Intent(this, TurboflareVpnService::class.java).apply {
            action = TurboflareVpnService.ACTION_START
        }
        startService(intent)
        vpnRunning = true
        updatePowerUi()
        appendLog("VPN starting...")
        startVpnLogPolling()
    }

    /**
     * Polls Gomobilebridge.drainVpnLogs() once a second while the VPN is
     * running, so tunnel activity (DNS relay, per-flow CONNECT attempts,
     * errors) shows up directly in the app's log view instead of
     * requiring `adb logcat` for every debugging session.
     */
    private fun startVpnLogPolling() {
        CoroutineScope(Dispatchers.IO).launch {
            while (vpnRunning) {
                try {
                    val logs = Gomobilebridge.drainVpnLogs()
                    if (logs.isNotEmpty()) {
                        appendLog(logs)
                    }
                } catch (e: Exception) {
                    // gomobilebridge not yet built with VPN log support,
                    // or the tunnel isn't running yet -- ignore and retry.
                }
                Thread.sleep(1000)
            }
        }
    }

    private fun stopVpn() {
        val intent = Intent(this, TurboflareVpnService::class.java).apply {
            action = TurboflareVpnService.ACTION_STOP
        }
        startService(intent)
        vpnRunning = false
        updatePowerUi()
        appendLog("VPN stopping...")
    }

    private fun appendLog(line: String) {
        runOnUiThread {
            logView.append(line + "\n")
            scroll.post { scroll.fullScroll(ScrollView.FOCUS_DOWN) }
        }
    }

    private fun onCopyLogsClicked() {
        val text = logView.text.toString()
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("turboflare logs", text))
        Toast.makeText(this, "Logs copied to clipboard", Toast.LENGTH_SHORT).show()
    }

    private fun onClearLogsClicked() {
        logView.text = ""
    }

    /**
     * Config dialog: base URL, server's static X25519 pubkey (hex),
     * provisioning token. Reusable both for first-run setup AND for
     * editing an already-saved config (Settings card / bottom nav) --
     * fields are pre-filled with the current values either way.
     */
    private fun promptForConfig() {
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 32, 48, 0)
        }
        val baseUrlInput = EditText(this).apply {
            hint = "Base URL, e.g. https://pelevin-art.ru"
            setText(ServerConfig.getBaseUrl(applicationContext))
        }
        val serverPubInput = EditText(this).apply {
            hint = "Server static pubkey (hex)"
            setText(ServerConfig.getServerPubHex(applicationContext))
        }
        val tokenInput = EditText(this).apply {
            hint = "Provisioning token"
            setText(ServerConfig.getToken(applicationContext))
        }
        container.addView(baseUrlInput)
        container.addView(serverPubInput)
        container.addView(tokenInput)

        val builder = AlertDialog.Builder(this)
            .setTitle("Server configuration")
            .setView(container)
            .setPositiveButton("Save") { _, _ ->
                ServerConfig.save(
                    applicationContext,
                    baseUrlInput.text.toString(),
                    serverPubInput.text.toString(),
                    tokenInput.text.toString()
                )
                appendLog("config saved")
                // Any existing manual session was built against the OLD
                // config -- drop it so the next diagnostic fetch starts
                // a fresh handshake against the new one.
                session = null
                refreshServerCard()
            }

        if (ServerConfig.isConfigured(applicationContext)) {
            builder.setNegativeButton("Cancel", null)
        } else {
            builder.setCancelable(false)
        }

        builder.show()
    }

    /**
     * Diagnostic button: opens (or reuses) a standalone manual session,
     * CONNECTs to example.com:80, sends a raw HTTP GET, prints the
     * response -- exactly the same flow as the original demo, just
     * auto-connecting on demand instead of requiring a separate
     * "Connect" button first.
     */
    private fun onConnectAndFetchClicked() {
        if (!ServerConfig.isConfigured(applicationContext)) {
            appendLog("configure server settings first")
            promptForConfig()
            return
        }
        CoroutineScope(Dispatchers.IO).launch {
            try {
                var s = session
                if (s == null) {
                    val deviceIdHex = DeviceIdentity.getOrCreate(applicationContext)
                    val baseUrl = ServerConfig.getBaseUrl(applicationContext)
                    val serverPubHex = ServerConfig.getServerPubHex(applicationContext)
                    val token = ServerConfig.getToken(applicationContext)
                    s = Gomobilebridge.openSession(baseUrl, serverPubHex, deviceIdHex, token)
                    session = s
                    appendLog("connected, connection_id=${s.connectionIDHex()}")
                    runOnUiThread { refreshServerCard() }
                }

                s.push("example.com:80".toByteArray())
                appendLog("sent CONNECT example.com:80")

                var confirmed = false
                repeat(50) {
                    val reply = s.pullOne()
                    if (reply != null) {
                        val text = String(reply)
                        appendLog("<- $text")
                        if (text.startsWith("OK CONNECTED")) confirmed = true
                        if (text.startsWith("ERROR")) return@launch
                    }
                    if (confirmed) return@repeat
                    Thread.sleep(300)
                }
                if (!confirmed) {
                    appendLog("timed out waiting for OK CONNECTED")
                    return@launch
                }

                val httpRequest = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
                s.push(httpRequest.toByteArray())
                appendLog("-> sent HTTP GET through tunnel")

                repeat(20) {
                    val reply = s.pullOne()
                    if (reply != null) appendLog("<- ${reply.size} bytes: ${String(reply).take(200)}")
                    Thread.sleep(200)
                }
            } catch (e: Exception) {
                appendLog("push/pull failed: ${e.message}")
            }
        }
    }

    /**
     * Test Mode button per PROTOCOL.md §4: runs the diagnostic probe
     * suite and shows the structured PASS/WARN/FAIL summary. The Go-
     * side wiring (observability.TestMode via gomobilebridge) isn't
     * connected yet -- kept as an explicit TODO rather than pretending
     * it's already implemented.
     */
    private fun onTestModeClicked() {
        appendLog("TODO: wire observability.TestMode via gomobilebridge (see PROTOCOL.md §4)")
    }

    // Guards against onCapabilitiesChanged firing many times in quick
    // succession (observed on real devices -- not every firing means a
    // real network change) and spawning overlapping concurrent
    // Reconnect() calls on the same session, which is both wasteful and
    // was a likely contributor to instability before this fix.
    @Volatile private var reconnecting = false
    @Volatile private var lastReconnectAtMs = 0L
    private val minReconnectIntervalMs = 3000L

    private fun registerNetworkCallback() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        cm.registerDefaultNetworkCallback(object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                val s = session ?: return
                val now = System.currentTimeMillis()
                if (reconnecting || now - lastReconnectAtMs < minReconnectIntervalMs) {
                    return
                }
                reconnecting = true
                CoroutineScope(Dispatchers.IO).launch {
                    try {
                        s.reconnect()
                        lastReconnectAtMs = System.currentTimeMillis()
                        appendLog("network changed -> reconnect confirmed")
                    } catch (e: Exception) {
                        appendLog("reconnect failed: ${e.message}")
                    } finally {
                        reconnecting = false
                    }
                }
            }
        })
    }
}
