package org.amnezia.vpn.frontendprobe

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Process
import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import org.amnezia.vpn.protocol.ProtocolState
import org.amnezia.vpn.protocol.xray.Xray
import org.amnezia.vpn.protocol.xray.libXray.LibXray
import org.amnezia.vpn.util.net.NetworkState
import org.json.JSONArray
import org.json.JSONObject

/** Disposable fixture, not part of the production app/source sets. */
class ProbeService : VpnService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val state = MutableStateFlow(ProtocolState.UNKNOWN)
    private val protocol = Xray.instance
    private val report = JSONObject().put("pid", Process.myPid()).put("test_only", true)
    private val transitions = JSONArray()
    private val lock = Any()
    @Volatile private var started = false
    @Volatile private var ready = false
    @Volatile private var faultRequested = false
    @Volatile private var runId: String? = null
    private val published = CountDownLatch(1)
    private lateinit var network: ConnectivityManager
    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onLinkPropertiesChanged(n: Network, links: LinkProperties) {
            if (links.dnsServers.any { it.hostAddress == "198.19.255.1" }) published.countDown()
        }
    }

    private fun save(update: JSONObject.() -> Unit) = synchronized(lock) {
        report.update()
        val next = File(filesDir, "report.next")
        next.writeText(report.toString())
        check(next.renameTo(File(filesDir, "report.json"))) { "Cannot publish fixture report" }
    }

    private fun tunDescriptors(): Int {
        val entries = File("/proc/self/fdinfo").listFiles() ?: error("Cannot inspect owned fdinfo")
        return entries.count { file ->
            try { file.readLines().any { it.startsWith("iff:") } }
            catch (_: java.io.FileNotFoundException) { false } // Concurrent ordinary fd retirement.
        }
    }

    override fun onCreate() {
        super.onCreate()
        val notifications = getSystemService(NotificationManager::class.java)
        notifications.createNotificationChannel(NotificationChannel("probe", "Probe", NotificationManager.IMPORTANCE_LOW))
        startForeground(991, Notification.Builder(this, "probe").setContentTitle("Native DNS probe")
            .setSmallIcon(android.R.drawable.stat_sys_warning).build())
        network = getSystemService(ConnectivityManager::class.java)
        network.registerNetworkCallback(NetworkRequest.Builder()
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .addTransportType(NetworkCapabilities.TRANSPORT_VPN).build(), callback)
        scope.launch {
            state.collect { current ->
                save { transitions.put(current.name); put("transitions", transitions) }
                if (current == ProtocolState.DISCONNECTED && faultRequested) {
                    try {
                        check(!protocol.hasPendingNativeCleanup) { "Disconnected before Kotlin ownership retired" }
                        check(!LibXray.probeNativeDNSOwned()) { "Disconnected before native DNS ownership retired" }
                        val descriptors = tunDescriptors()
                        check(descriptors == 0) { "TUN fd remains after confirmed cleanup" }
                        save { put("final", true); put("native_owned", false); put("tun_fds_after", descriptors)
                            put("pid_after", Process.myPid()) }
                        stopForeground(true)
                        stopSelf()
                    } catch (e: Exception) { save { put("error", e.toString()) } }
                }
            }
        }
    }

    override fun onStartCommand(intent: android.content.Intent?, flags: Int, id: Int): Int {
        scope.launch {
            try {
                when (intent?.action) {
                    "start" -> {
                        check(!started)
                        runId = intent.getStringExtra("run_id")?.takeIf { it.isNotBlank() }
                            ?: error("Missing fixture run identity")
                        save { put("run_id", runId) }
                        startProbe()
                    }
                    "fail" -> {
                        check(intent.getStringExtra("run_id") == runId)
                        check(started && ready) { "Cannot fail an unready owner" }
                        faultRequested = true
                        save { put("fault_requested", true) }
                        val error = LibXray.probeAbortNativeDNS()
                        check(error.isNullOrBlank()) { error }
                    }
                    "stop" -> {
                        check(intent.getStringExtra("run_id") == runId)
                        do {
                            protocol.stopVpn()
                            if (protocol.hasPendingNativeCleanup) delay(250)
                        } while (protocol.hasPendingNativeCleanup)
                        save { put("stopped", true); put("native_owned", LibXray.probeNativeDNSOwned())
                            put("tun_fds_after_stop", tunDescriptors()) }
                        stopForeground(true)
                        stopSelf()
                    }
                }
            } catch (e: Exception) {
                save { put("error", e.toString()) }
                if (!protocol.hasPendingNativeCleanup) {
                    stopForeground(true)
                    stopSelf()
                }
            }
        }
        return START_NOT_STICKY
    }

    private suspend fun startProbe() {
        check(!started) { "Probe owner already started" }
        check(network.allNetworks.none {
            network.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        }) { "Refusing an existing VPN owner" }
        started = true
        val originalNetwork = NetworkState(this, {})
        protocol.initialize(applicationContext, state, { message ->
            save { put("native_notice", message) }
        })
        protocol.configureStrictPrivateDnsPolicy(originalNetwork::hasStrictPrivateDns)
        protocol.configureNetworkDns(originalNetwork::dnsSnapshot, originalNetwork::bindDnsSocket,
            originalNetwork::dnsIdentity)
        state.value = ProtocolState.CONNECTING
        val xray = """{"inbounds":[{"listen":"127.0.0.1","port":1080,"protocol":"socks","settings":{"udp":true}}],"outbounds":[{"protocol":"freedom","tag":"direct"}]}"""
        protocol.startVpn(JSONObject().put("protocol", "xray").put("hostName", "10.0.2.2")
            .put("dns1", "fd77::2").put("dns2", "").put("ipv6_enabled", false).put("mtu", "1280")
            .put("xray_config_data", JSONObject().put("config", xray)), Builder(), ::protect)
        check(state.value == ProtocolState.CONNECTED && protocol.hasPendingNativeCleanup)
        // Explicit fixture readiness, not a claim that app CONNECTED alone
        // proves netd publication. Observe the actual native VPN DNS link.
        check(published.await(10, TimeUnit.SECONDS)) { "Native DNS link was not published" }
        val descriptors = tunDescriptors()
        check(descriptors > 0) { "Real native TUN was not created" }
        save { put("tun_fds_before", descriptors) }
        for (tcp in listOf(false, true)) {
            query(tcp, 28, 0)
            query(tcp, 1, 2)
        }
        ready = true
        save { put("ready", true); put("native_owned", LibXray.probeNativeDNSOwned()) }
    }

    private fun query(tcp: Boolean, type: Int, rcode: Int) {
        val wire = byteArrayOf(0x39, 0x12, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
            5, 112, 114, 111, 98, 101, 4, 116, 101, 115, 116, 0, 0, type.toByte(), 0, 1)
        val start = System.nanoTime()
        val answer = if (tcp) Socket().use { socket ->
            socket.soTimeout = 2000
            socket.connect(java.net.InetSocketAddress("198.19.255.1", 53), 2000)
            val output = java.io.DataOutputStream(socket.getOutputStream())
            output.writeShort(wire.size); output.write(wire); output.flush()
            val input = java.io.DataInputStream(socket.getInputStream())
            ByteArray(input.readUnsignedShort()).also { input.readFully(it) }
        } else DatagramSocket().use { socket ->
            socket.soTimeout = 2000
            socket.send(DatagramPacket(wire, wire.size, InetAddress.getByName("198.19.255.1"), 53))
            val result = DatagramPacket(ByteArray(4096), 4096)
            socket.receive(result)
            check(result.address.hostAddress == "198.19.255.1" && result.port == 53)
            result.data.copyOf(result.length)
        }
        val millis = (System.nanoTime() - start) / 1_000_000
        check(answer.size >= 12 && answer[0] == wire[0] && answer[1] == wire[1] &&
            (answer[3].toInt() and 15) == rcode && answer[6].toInt() == 0 && answer[7].toInt() == 0)
        check(millis <= 250) { "DNS $tcp/$type exceeded 250ms: $millis" }
        save { put("${if (tcp) "tcp" else "udp"}_$type", millis) }
    }

    override fun onDestroy() {
        network.unregisterNetworkCallback(callback)
        if (protocol.hasPendingNativeCleanup) {
            save { put("error", "Service destruction with unjoined native owner") }
            protocol.stopVpn()
        }
        scope.cancel()
        super.onDestroy()
    }
}
