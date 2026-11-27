package org.amnezia.vpn.protocol.xray

import android.content.Context
import android.net.VpnService.Builder
import android.os.Build
import java.io.File
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.util.UUID
import go.Seq
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.amnezia.vpn.protocol.BadConfigException
import org.amnezia.vpn.protocol.Protocol
import org.amnezia.vpn.protocol.NativeDnsPlan
import org.amnezia.vpn.protocol.Route
import org.amnezia.vpn.protocol.ProtocolState.CONNECTED
import org.amnezia.vpn.protocol.ProtocolState.DISCONNECTED
import org.amnezia.vpn.protocol.ProtocolState.DISCONNECTING
import org.amnezia.vpn.protocol.Statistics
import org.amnezia.vpn.protocol.VpnStartException
import org.amnezia.vpn.protocol.xray.libXray.DialerController
import org.amnezia.vpn.protocol.xray.libXray.LibXray
import org.amnezia.vpn.protocol.xray.libXray.Logger
import org.amnezia.vpn.protocol.xray.libXray.Tun2SocksConfig
import org.amnezia.vpn.protocol.xray.libXray.NativeDNSController
import org.amnezia.vpn.util.Log
import org.amnezia.vpn.util.net.InetNetwork
import org.amnezia.vpn.util.net.ip
import org.amnezia.vpn.util.net.parseInetAddress
import org.json.JSONArray
import org.json.JSONObject

private const val TAG = "Xray"
private const val LIBXRAY_TAG = "libXray"

private fun findSocksInboundIndex(inbounds: JSONArray): Int {
    for (i in 0 until inbounds.length()) {
        val o = inbounds.optJSONObject(i) ?: continue
        if (o.optString("protocol").equals("socks", ignoreCase = true)) {
            return i
        }
    }
    return -1
}

private fun acquireFreeLocalPort(): Int {
    try {
        ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { return it.localPort }
    } catch (e: Exception) {
        throw VpnStartException(
            "Failed to acquire free TCP port on 127.0.0.1 for SOCKS inbound: ${e.message}"
        )
    }
}

class Xray : Protocol() {

    private var isRunning: Boolean = false
    private val nativeLock = Any()
    private val failureScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var dnsPublication: XrayDnsPublication? = null
    private val nativeLifecycle = XrayNativeLifecycle(
        LibXray::stopTun2Socks, LibXray::stopXray, LibXray::cancelNativeDNS)
    override val hasPendingNativeCleanup: Boolean get() = nativeLifecycle.ownsNativeResources
    override val statistics: Statistics = Statistics.EMPTY_STATISTICS

    override fun internalInit() {
        Seq.setContext(context)
        if (!isInitialized) {
            LibXray.initLogger(object : Logger {
                override fun warning(s: String) = Log.w(LIBXRAY_TAG, s)

                override fun error(s: String) = Log.e(LIBXRAY_TAG, s)

                override fun write(msg: ByteArray): Long {
                    Log.w(LIBXRAY_TAG, String(msg))
                    return msg.size.toLong()
                }
            }).isNotNullOrBlank { err ->
                Log.w(TAG, "Failed to initialize logger: $err")
            }
        }
    }

    override suspend fun startVpn(config: JSONObject, vpnBuilder: Builder, protect: (Int) -> Boolean) {
        synchronized(nativeLock) { startOwned(config, vpnBuilder, protect) }
    }

    private fun startOwned(config: JSONObject, vpnBuilder: Builder, protect: (Int) -> Boolean) {
        if (nativeLifecycle.ownsNativeResources)
            throw VpnStartException("Previous Xray native owner has not retired")

        val xrayConfigData = config.optJSONObject("xray_config_data")
            ?: config.optJSONObject("ssxray_config_data")
            ?: throw BadConfigException("config_data not found")
        val xrayJsonConfig = JSONObject(xrayConfigData.optString("config"))

        // Inject SOCKS5 auth before starting xray. Re-uses existing credentials if present.
        ensureInboundAuth(xrayJsonConfig)
        val ipv6Off = !config.optBoolean("ipv6_enabled", true)
        val selected = listOf(config.optString("dns1"), config.optString("dns2")).filter { it.isNotBlank() }
        // Prove numeric syntax BEFORE the legacy config parser can resolve a
        // hostname. No bootstrap/default DNS is permitted for this selection.
        if (ipv6Off) NativeDnsPlan.prepare(selected, emptyList())
        val original = parseConfig(config, xrayJsonConfig)
        val publication = if (ipv6Off) {
            val strict = strictPrivateDnsPolicy?.invoke()
                ?: throw VpnStartException("Missing Android encrypted-DNS policy snapshot")
            // Account for the existing Samsung OS publication workaround,
            // which adds DNS host routes outside ProtocolConfig.routes.
            val originalRoutes = original.routes.toList() + if (Build.BRAND == "samsung")
                original.dnsServers.map { Route(InetNetwork(it), true) } else emptyList()
            XrayDnsPublication.prepare(
                NativeDnsPlan.prepare(selected, originalRoutes, original.addresses),
                strict, lockdownEnabled(), networkDnsSnapshot, networkDnsIdentity, protect, networkDnsProtect)
        } else null
        val xrayConfig = if (publication == null) original
            else parseConfig(config, xrayJsonConfig, publication.aliases)

        var xrayJsonConfigString = xrayJsonConfig.toString()
        config.getString("hostName").let { hostName ->
            val ipAddress = parseInetAddress(hostName).ip
            if (hostName != ipAddress) {
                xrayJsonConfigString = xrayJsonConfigString.replace(hostName, ipAddress)
            }
        }

        nativeLifecycle.begin()
        dnsPublication = publication
        try {
            if (publication != null) {
                LibXray.registerNativeDNSController(object : NativeDNSController {
                    override fun bindDNS(fd: Long, token: String) = publication.bindSocket(fd, token)
                    override fun dnsFailed() { frontendFailed(publication) }
                }).isNotNullOrBlank { throw VpnStartException("Native DNS controller: $it") }
            }
            LibXray.prepareNativeDNS(publication?.raw ?: "").isNotNullOrBlank {
                throw VpnStartException("Native DNS preparation: $it")
            }
            start(xrayConfig, xrayJsonConfigString, vpnBuilder, protect)
            state.value = CONNECTED
            isRunning = true
        } catch (error: Exception) {
            val pending = nativeLifecycle.cleanup()
            if (pending == null) {
                publication?.retire()
                dnsPublication = null
            } else {
                onError("Xray native cleanup pending: $pending")
            }
            throw error
        }
    }

    private fun frontendFailed(publication: XrayDnsPublication) {
        // Called from Go. Enqueue and return: synchronous JNI cleanup here
        // would deadlock the native callback-join barrier.
        if (!publication.beginFailure()) return
        val cleanup = XrayDnsFailureCleanup(nativeLifecycle)
        failureScope.launch {
            while (true) {
                val retained = synchronized(nativeLock) {
                    cleanup.step(dnsPublication === publication,
                        { state.value = DISCONNECTING }, onError, ::retirementConfirmed)
                }
                if (!retained) return@launch
                delay(250)
            }
        }
    }

    private fun parseConfig(config: JSONObject, xrayJsonConfig: JSONObject,
                            managedDns: List<InetAddress>? = null): XrayConfig {
        return XrayConfig.build {
            addAddress(XrayConfig.DEFAULT_IPV4_ADDRESS)
            addAddress(XrayConfig.DEFAULT_IPV6_ADDRESS)

            if (managedDns != null) setManagedDnsServers(managedDns) else {
                config.optString("dns1").let {
                    if (it.isNotBlank()) addDnsServer(parseInetAddress(it))
                }
                config.optString("dns2").let {
                    if (it.isNotBlank()) addDnsServer(parseInetAddress(it))
                }
            }

            addRoute(InetNetwork("0.0.0.0", 0))
            // Preserve full IPv6 capture through the shared builder's legacy
            // ::/0 compatibility conversion, including ULA and NAT64.
            addRoute(InetNetwork("::", 1))
            addRoute(InetNetwork("8000::", 1))
            config.getString("hostName").let {
                excludeRoute(InetNetwork(parseInetAddress(it)))
            }

            config.optString("mtu").let {
                if (it.isNotBlank()) setMtu(it.toInt())
            }

            val inbounds = xrayJsonConfig.getJSONArray("inbounds")
            val socksIdx = findSocksInboundIndex(inbounds)
            if (socksIdx < 0) {
                throw BadConfigException("socks inbound not found")
            }
            val socksConfig = inbounds.getJSONObject(socksIdx)
            socksConfig.getInt("port").let { setSocksPort(it) }

            val socksSettings = socksConfig.optJSONObject("settings")
            val accounts = socksSettings?.optJSONArray("accounts")
            if (accounts != null && accounts.length() > 0) {
                val account = accounts.getJSONObject(0)
                setSocksUser(account.optString("user"))
                setSocksPass(account.optString("pass"))
            }

            configSplitTunneling(config)
            configAppSplitTunneling(config)
        }
    }

    private fun start(config: XrayConfig, configJson: String, vpnBuilder: Builder, protect: (Int) -> Boolean) {
        buildVpnInterface(config, vpnBuilder)

        DialerController { protect(it.toInt()) }.also {
            LibXray.registerDialerController(it).isNotNullOrBlank { err ->
                throw VpnStartException("Failed to register dialer controller: $err")
            }
            LibXray.registerListenerController(it).isNotNullOrBlank { err ->
                throw VpnStartException("Failed to register listener controller: $err")
            }
        }

        vpnBuilder.establish().use { tunFd ->
            if (tunFd == null) {
                throw VpnStartException("Create VPN interface: permission not granted or revoked")
            }
            Log.d(TAG, "Run tun2Socks")
            nativeLifecycle.admit()
            runTun2Socks(config, tunFd.detachFd())

            Log.d(TAG, "Run XRay")
            Log.i(TAG, "xray ${LibXray.xrayVersion()}")
            val assetsPath = context.getDir("assets", Context.MODE_PRIVATE).absolutePath
            LibXray.initXray(assetsPath)
            val geoDir = File(assetsPath, "geo").absolutePath
            val configPath = File(context.cacheDir, "config.json")
            Log.v(TAG, "xray.location.asset: $geoDir")
            Log.v(TAG, "config: $configPath")
            try {
                configPath.writeText(configJson)
            } catch (e: IOException) {
                throw VpnStartException("Failed to write xray config: ${e.message}")
            }
            LibXray.runXray(geoDir, configPath.absolutePath, config.maxMemory).isNotNullOrBlank { err ->
                throw VpnStartException("Failed to start xray: $err")
            }
        }
    }

    override fun stopVpn() {
        synchronized(nativeLock) {
            val pending = nativeLifecycle.cleanup()
            if (pending != null) {
                onError("Xray native cleanup pending: $pending")
                return
            }
            retirementConfirmed()
        }
    }

    private fun retirementConfirmed() {
        dnsPublication?.retire()
        dnsPublication = null
        isRunning = false
        releaseNetworkHooks()
        state.value = DISCONNECTED
    }

    override fun reconnectVpn(vpnBuilder: Builder, protect: (Int) -> Boolean) {
        synchronized(nativeLock) {
            if (!isRunning || !nativeLifecycle.ownsNativeResources)
                throw VpnStartException("Xray native connection is not active")
            state.value = CONNECTED
        }
    }

    private fun runTun2Socks(config: XrayConfig, fd: Int) {
        val proxyUrl = "socks5://${config.socksUser}:${config.socksPass}@127.0.0.1:${config.socksPort}"
        val tun2SocksConfig = Tun2SocksConfig().apply {
            mtu = config.mtu.toLong()
            proxy = proxyUrl
            device = "fd://$fd"
            logLevel = "warn"
        }
        LibXray.startTun2Socks(tun2SocksConfig, fd.toLong()).isNotNullOrBlank { err ->
            throw VpnStartException("Failed to start tun2socks: $err")
        }
    }

    // Ensures SOCKS5 auth is present on the socks inbound settings.
    // Re-uses existing credentials if already configured; otherwise generates random ones.
    private fun ensureInboundAuth(xrayConfig: JSONObject) {
        val inbounds = xrayConfig.optJSONArray("inbounds") ?: return
        val socksIdx = findSocksInboundIndex(inbounds)
        if (socksIdx < 0) return

        val inbound = inbounds.getJSONObject(socksIdx)
        inbound.put("port", acquireFreeLocalPort())
        val settings = inbound.optJSONObject("settings") ?: JSONObject().also { inbound.put("settings", it) }
        val accounts = settings.optJSONArray("accounts")
        if (accounts != null && accounts.length() > 0) {
            val account = accounts.getJSONObject(0)
            if (account.optString("user").isNotEmpty() && account.optString("pass").isNotEmpty()) {
                // Ensure auth mode is enforced even for imported configs that had accounts
                // but auth: "noauth" (or no auth field).
                settings.put("auth", "password")
                inbound.put("settings", settings)
                inbounds.put(socksIdx, inbound)
                return
            }
        }

        val user = UUID.randomUUID().toString().replace("-", "").substring(0, 16)
        val pass = UUID.randomUUID().toString().replace("-", "")
        settings.put("auth", "password")
        settings.put("accounts", JSONArray().put(JSONObject().put("user", user).put("pass", pass)))
        inbound.put("settings", settings)
        inbounds.put(socksIdx, inbound)
    }

    companion object {
        val instance: Xray by lazy { Xray() }
    }
}

private fun String?.isNotNullOrBlank(block: (String) -> Unit) {
    if (!this.isNullOrBlank()) {
        block(this)
    }
}
