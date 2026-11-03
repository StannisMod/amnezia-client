package org.amnezia.vpn.protocol.wireguard

import android.net.VpnService.Builder
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import org.amnezia.vpn.util.net.DomainEndpointRefresh
import org.amnezia.vpn.util.net.EndpointHealthPolicy
import android.os.SystemClock
import kotlinx.coroutines.SupervisorJob
import org.amnezia.awg.RoutingBackend
import org.amnezia.awg.RoutingHost
import org.json.JSONArray
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.amnezia.awg.GoBackend
import org.amnezia.vpn.protocol.Protocol
import org.amnezia.vpn.protocol.ProtocolConfig
import org.amnezia.vpn.protocol.ProtocolState.CONNECTED
import org.amnezia.vpn.protocol.ProtocolState.DISCONNECTED
import org.amnezia.vpn.protocol.Statistics
import org.amnezia.vpn.protocol.VpnException
import org.amnezia.vpn.protocol.VpnStartException
import org.amnezia.vpn.util.LibraryLoader.loadSharedLibrary
import org.amnezia.vpn.util.Log
import org.amnezia.vpn.util.asSequence
import org.amnezia.vpn.util.net.InetEndpoint
import org.amnezia.vpn.util.net.InetNetwork
import org.amnezia.vpn.util.net.parseInetAddress
import org.amnezia.vpn.util.optStringOrNull
import org.json.JSONObject

private const val TAG = "Wireguard"

open class Wireguard : Protocol() {
    private val endpointLock = Any()
    private var endpointCandidates = DomainEndpointRefresh.Candidates()
    private var endpointGeneration = 0L
    private var originalProfile: JSONObject? = null
    private var endpointRefreshJob: Job? = null
    private var endpointHealthJob: Job? = null
    private var endpointHealthGeneration = 0L
    private var endpointBackendEpoch = 0L

    private fun endpointHost(profile: JSONObject): String =
        profile.getJSONObject(profile.getString("protocol") + "_config_data").getString("hostName")

    private suspend fun refreshEndpoint(profile: JSONObject): JSONObject {
        val host = endpointHost(profile)
        if (!DomainEndpointRefresh.isDomain(host)) return JSONObject(profile.toString())
        val resolver = endpointResolver ?: throw VpnStartException("Underlying-network DNS is not configured")
        val candidates = synchronized(endpointLock) { endpointCandidates }
        val address = DomainEndpointRefresh.resolve(host, resolver, candidates = candidates)
        return JSONObject(profile.toString()).apply {
            put("hostName", address)
            getJSONObject(getString("protocol") + "_config_data").put("hostName", address)
        }
    }


    @Volatile private var routedHandle = -1L
    @Volatile private var routedConfig: JSONObject? = null
    private var routedStatusJob: Job? = null
    private val routedScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private fun startRouted(config: JSONObject, vpnBuilder: Builder, protect: (Int) -> Boolean) {
        if (lockdownEnabled()) {
            throw VpnStartException("Experimental domain routing is unavailable while Android VPN lockdown is enabled")
        }
        // Use the existing profile parser, including every AWG 3.1 parameter,
        // but never materialize the legacy site's cached IP exclusions.
        val splitDNS = if (config.has("sing_box_dns")) config.getJSONObject("sing_box_dns") else null
        val parseInput = JSONObject(config.toString()).apply {
            put("splitTunnelType", 0)
            if (splitDNS != null) { remove("dns1"); remove("dns2") }
        }
        val wg = parseConfig(parseInput)
        val transportType = config.getString("protocol")
        if (transportType != "awg" && transportType != "wireguard") throw VpnStartException("Unsupported routing adapter")
        val data = config.getJSONObject(transportType + "_config_data")
        val allowed = data.getJSONArray("allowed_ips")
        val allowedSet = (0 until allowed.length()).map { allowed.getString(it).trim() }.toSet()
        if ("0.0.0.0/0" !in allowedSet) {
            throw VpnStartException("Experimental domain routing requires an IPv4 default route in the VPN profile")
        }
        val parameters = JSONObject()
        val excluded = setOf("private_key", "public_key", "preshared_key", "replace_peers", "replace_allowed_ips", "allowed_ip", "endpoint", "persistent_keepalive_interval", "listen_port")
        for (line in wg.toWgUserspaceString().lineSequence()) {
            val key = line.substringBefore('=')
            if (line.contains('=') && key !in excluded) parameters.put(key, line.substringAfter('='))
        }
        val session = JSONObject().apply {
            put("cache_path", java.io.File(context.filesDir, "routing-fakeip-v1.db").absolutePath)
            put("rules", config.getJSONObject("sing_box_routing"))
            if (splitDNS != null) {
                put("dns", splitDNS)
            } else {
                val resolverValue = config.optString("dns1").ifBlank { config.optString("dns2") }
                if (resolverValue.isBlank()) throw VpnStartException("A numeric DNS resolver is required for domain routing")
                val resolver = parseInetAddress(resolverValue)
                val resolverIp = resolver.hostAddress?.substringBefore('%')
                    ?: throw VpnStartException("Invalid DNS resolver")
                put("resolver", if (resolverIp.contains(':')) "[$resolverIp]:53" else "$resolverIp:53")
                put("resolver_action", if (resolver.isLoopbackAddress) "direct" else config.optString("sing_box_dns_path", "vpn"))
            }
            put("vpn", JSONObject().apply {
                put("type", transportType)
                put(transportType, JSONObject().apply {
                    put("address", JSONArray(wg.addresses.map { it.address.hostAddress!!.substringBefore('%') }))
                    put("private_key", data.getString("client_priv_key"))
                    put("public_key", data.getString("server_pub_key"))
                    if (!data.optString("psk_key").isNullOrEmpty()) put("pre_shared_key", data.getString("psk_key"))
                    put("endpoint", wg.endpoint.toString())
                    put("allowed_ips", allowed)
                    put("mtu", wg.mtu)
                    // Preserve AWG 3.1 ranges; the shared native validator checks them.
                    if (transportType == "awg") {
                        put("keepalive", wg.persistentKeepalive ?: "0")
                        put("parameters", parameters)
                    } else {
                        if (parameters.length() != 0) throw VpnStartException("Obfuscated WireGuard requires the AWG adapter")
                        val keepalive = (wg.persistentKeepalive ?: "0").toIntOrNull()
                        if (keepalive == null || keepalive !in 0..65535) throw VpnStartException("Invalid WireGuard keepalive")
                        put("keepalive", keepalive)
                    }
                })
            })
        }.toString().toByteArray(Charsets.UTF_8)

        if (!RoutingBackend.validate(session)) {
            throw VpnStartException("Domain routing rules or resolver configuration are invalid")
        }

        val capture = ProtocolConfig.build(blockingMode = false) {
            addAddress(InetNetwork("172.19.0.1", 30))
            addAddress(InetNetwork("fdfe:dcba:9876::1", 126))
            addDnsServer(InetNetwork("172.19.0.2", 32).address)
            addRoute(InetNetwork("0.0.0.0", 0))
            // Capture ULA FakeIPs too, while leaving the legacy builder's
            // ::/0-to-2000::/3 compatibility transformation unchanged.
            addRoute(InetNetwork("::", 1))
            addRoute(InetNetwork("8000::", 1))
            setMtu(1280)
            configAppSplitTunneling(config)
        }
        stopRouted()
        routedConfig = JSONObject(config.toString())
        buildVpnInterface(capture, vpnBuilder)
        vpnBuilder.establish().use { descriptor ->
            if (descriptor == null) throw VpnStartException("Cannot establish the routed VPN interface")
            routedHandle = RoutingBackend.start(descriptor.detachFd(), session, RoutingHost(protect))
        }
        if (routedHandle <= 0) {
            routedHandle = -1L
            // Do not silently retry the legacy backend or expose VPN flows.
            throw VpnStartException("Domain routing startup failed; check the profile and routing rules")
        }
        ++endpointBackendEpoch
        val statusHandle = routedHandle
        routedStatusJob = routedScope.launch {
            var announced = false
            while (routedHandle == statusHandle) {
                // Lockdown may be enabled while a routed tunnel is active.
                // Stop rather than allowing protected DIRECT proxy sockets to
                // circumvent the user's OS policy. The OS keeps traffic blocked.
                if (lockdownEnabled()) {
                    stopRouted()
                    state.value = DISCONNECTED
                    onError("Experimental domain routing stopped because Android VPN lockdown is enabled")
                    break
                }
                if (!announced) {
                    val snapshot = RoutingBackend.stats(statusHandle) ?: break
                    if (routedHandle != statusHandle) break
                    if (snapshot[2] > 0) { state.value = CONNECTED; announced = true }
                }
                delay(1000)
            }
        }
    }

    private fun stopRouted() {
        routedStatusJob?.cancel()
        routedStatusJob = null
        val handle = routedHandle
        routedHandle = -1L
        if (handle > 0) RoutingBackend.stop(handle)
    }

    private var tunnelHandle: Int = -1
    private var config: WireguardConfig? = null // save config for reconnect
    protected open val ifName: String = "amn0"
    private lateinit var scope: CoroutineScope
    private var statusJob: Job? = null

    override val statistics: Statistics
        get() {
            if (routedConfig != null) {
                val counters = RoutingBackend.stats(routedHandle) ?: return Statistics.EMPTY_STATISTICS
                return Statistics.build { setRxBytes(counters[0]); setTxBytes(counters[1]) }
            }
            if (tunnelHandle == -1) return Statistics.EMPTY_STATISTICS
            val config = GoBackend.awgGetConfig(tunnelHandle) ?: return Statistics.EMPTY_STATISTICS
            return Statistics.build {
                var optsCount = 0
                config.splitToSequence("\n").forEach { line ->
                    with(line) {
                        when {
                            startsWith("rx_bytes=") -> setRxBytes(substring(9).toLong()).also { ++optsCount }
                            startsWith("tx_bytes=") -> setTxBytes(substring(9).toLong()).also { ++optsCount }
                            else -> {}
                        }
                    }
                    if (optsCount == 2) return@forEach
                }
            }
        }

    override fun internalInit() {
        synchronized(endpointLock) {
            ++endpointHealthGeneration
            endpointHealthJob?.cancel()
            endpointHealthJob = null
        }
        if (!isInitialized) loadSharedLibrary(context, "wg-go")
        if (this::scope.isInitialized) {
            scope.cancel()
        }
        scope = CoroutineScope(Dispatchers.IO)
    }

    override suspend fun startVpn(config: JSONObject, vpnBuilder: Builder, protect: (Int) -> Boolean) {
        val generation = synchronized(endpointLock) {
            endpointRefreshJob?.cancel()
            ++endpointHealthGeneration
            endpointHealthJob?.cancel()
            endpointCandidates = DomainEndpointRefresh.Candidates()
            originalProfile = JSONObject(config.toString())
            ++endpointGeneration
        }
        val resolved = refreshEndpoint(config)
        currentCoroutineContext().ensureActive()
        synchronized(endpointLock) {
            if (generation != endpointGeneration) return
            if (resolved.has("sing_box_routing")) {
                if (tunnelHandle != -1) turnOffVpn()
                startRouted(resolved, vpnBuilder, protect)
            } else {
                stopRouted()
                routedConfig = null
                val wireguardConfig = parseConfig(resolved)
                start(wireguardConfig, vpnBuilder, protect)
                this.config = wireguardConfig
            }
            startEndpointWatchdog(config)
        }
    }

    protected open fun parseConfig(config: JSONObject): WireguardConfig {
        val configData = config.getJSONObject("wireguard_config_data")
        return WireguardConfig.build {
            configWireguard(config, configData)
            configSplitTunneling(config)
            configAppSplitTunneling(config)
        }
    }

    protected fun WireguardConfig.Builder.configWireguard(config: JSONObject, configData: JSONObject) {
        configData.getString("client_ip").split(",").map { address ->
            InetNetwork.parse(address.trim())
        }.forEach(::addAddress)

        config.optStringOrNull("dns1")?.let { dns ->
            addDnsServer(parseInetAddress(dns.trim()))
        }

        config.optStringOrNull("dns2")?.let { dns ->
            addDnsServer(parseInetAddress(dns.trim()))
        }

        val defRoutes = hashSetOf(
            InetNetwork("0.0.0.0", 0),
            InetNetwork("::", 0)
        )
        val routes = hashSetOf<InetNetwork>()
        configData.getJSONArray("allowed_ips").asSequence<String>().map { route ->
            InetNetwork.parse(route.trim())
        }.forEach(routes::add)
        // if the allowed IPs list contains at least one non-default route, disable global split tunneling
        if (routes.any { it !in defRoutes }) disableSplitTunneling()
        addRoutes(routes)

        configData.optStringOrNull("mtu")?.let { setMtu(it.toInt()) }

        val host = configData.getString("hostName").let { parseInetAddress(it.trim()) }
        val port = configData.getInt("port")
        setEndpoint(InetEndpoint(host, port))

        if (configData.optBoolean("isObfuscationEnabled")) {
            setUseProtocolExtension(true)
            configExtensionParameters(configData)
        }

        configData.optStringOrNull("persistent_keep_alive")?.let { setPersistentKeepalive(it) }
        configData.getString("client_priv_key").let { setPrivateKeyHex(it.base64ToHex()) }
        configData.getString("server_pub_key").let { setPublicKeyHex(it.base64ToHex()) }
        configData.optStringOrNull("psk_key")?.let { setPreSharedKeyHex(it.base64ToHex()) }
    }

    protected fun WireguardConfig.Builder.configExtensionParameters(configData: JSONObject) {
        configData.optStringOrNull("Jc")?.let { setJc(it.toInt()) }
        configData.optStringOrNull("Jmin")?.let { setJmin(it.toInt()) }
        configData.optStringOrNull("Jmax")?.let { setJmax(it.toInt()) }
        configData.optStringOrNull("S1")?.let { setS1(it.toInt()) }
        configData.optStringOrNull("S2")?.let { setS2(it.toInt()) }
        configData.optStringOrNull("S3")?.let { setS3(it.toInt()) }
        configData.optStringOrNull("S4")?.let { setS4(it.toInt()) }
        configData.optStringOrNull("H1")?.trim()?.let { if (it.isNotEmpty()) setH1(it) }
        configData.optStringOrNull("H2")?.trim()?.let { if (it.isNotEmpty()) setH2(it) }
        configData.optStringOrNull("H3")?.trim()?.let { if (it.isNotEmpty()) setH3(it) }
        configData.optStringOrNull("H4")?.trim()?.let { if (it.isNotEmpty()) setH4(it) }
        configData.optStringOrNull("I1")?.let { setI1(it) }
        configData.optStringOrNull("I2")?.let { setI2(it) }
        configData.optStringOrNull("I3")?.let { setI3(it) }
        configData.optStringOrNull("I4")?.let { setI4(it) }
        configData.optStringOrNull("I5")?.let { setI5(it) }
        configData.optStringOrNull("HeaderProtectionKey")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setHeaderProtectionKey(it.base64ToHex()) }
        configData.optStringOrNull("ContentPaddingAddition")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setContentPaddingAddition(it) }
        configData.optStringOrNull("RekeyAfterTime")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setRekeyAfterTime(it) }
        configData.optStringOrNull("RekeyTimeout")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setRekeyTimeout(it) }
        configData.optStringOrNull("RejectAfterTime")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setRejectAfterTime(it) }
        configData.optStringOrNull("KeepaliveTimeout")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setKeepaliveTimeout(it) }
        configData.optStringOrNull("MaxHandshakeAttempts")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setMaxHandshakeAttempts(it) }
        configData.optStringOrNull("RandomTrailers")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setRandomTrailers(it) }
        configData.optStringOrNull("DisableCookies")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setDisableCookies(it) }
    }

    private fun start(
        config: WireguardConfig,
        vpnBuilder: Builder,
        protect: (Int) -> Boolean,
        stopExistingVpn: Boolean = false
    ) {
        if (!stopExistingVpn && tunnelHandle != -1) {
            Log.w(TAG, "Tunnel already up")
            return
        }

        buildVpnInterface(config, vpnBuilder)

        vpnBuilder.establish().use { tunFd ->
            if (stopExistingVpn && tunnelHandle != -1) {
                turnOffVpn()
            }
            if (tunFd == null) {
                throw VpnStartException("Create VPN interface: permission not granted or revoked")
            }
            Log.i(TAG, "awg-go backend ${GoBackend.awgVersion()}")
            tunnelHandle = GoBackend.awgTurnOn(ifName, tunFd.detachFd(), config.toWgUserspaceString())
        }

        if (tunnelHandle < 0) {
            tunnelHandle = -1
            throw VpnStartException("Wireguard tunnel creation error")
        }

        if (!protect(GoBackend.awgGetSocketV4(tunnelHandle)) || !protect(GoBackend.awgGetSocketV6(tunnelHandle))) {
            GoBackend.awgTurnOff(tunnelHandle)
            tunnelHandle = -1
            throw VpnStartException("Protect VPN interface: permission not granted or revoked")
        }
        ++endpointBackendEpoch
        launchStatusJob()
    }

    private fun launchStatusJob() {
        Log.d(TAG, "Launch status job")
        statusJob = scope.launch {
            while (true) {
                val lastHandshake = getLastHandshake()
                Log.v(TAG, "lastHandshake=$lastHandshake")
                if (lastHandshake == 0L) {
                    delay(1000)
                    continue
                }
                if (lastHandshake == -2L || lastHandshake > 0L) state.value = CONNECTED
                else if (lastHandshake == -1L) state.value = DISCONNECTED
                statusJob = null
                break
            }
        }
    }

    private fun getLastHandshake(): Long {
        if (tunnelHandle == -1) {
            Log.e(TAG, "Trying to get config of a non-existent tunnel")
            return -1
        }
        val config = GoBackend.awgGetConfig(tunnelHandle)
        if (config == null) {
            Log.e(TAG, "Failed to get tunnel config")
            return -2
        }
        val lastHandshake = config.lines().find { it.startsWith("last_handshake_time_sec=") }?.substring(24)?.toLong()
        if (lastHandshake == null) {
            Log.e(TAG, "Failed to get last_handshake_time_sec")
            return -2
        }
        return lastHandshake
    }

    private fun turnOffVpn() {
        statusJob?.cancel()
        statusJob = null
        val handleToClose = tunnelHandle
        tunnelHandle = -1
        GoBackend.awgTurnOff(handleToClose)
    }

    private fun startEndpointWatchdog(profile: JSONObject) {
        ++endpointHealthGeneration
        endpointHealthJob?.cancel()
        if (!DomainEndpointRefresh.isDomain(endpointHost(profile)) || endpointRecovery == null) return
        val generation = endpointHealthGeneration
        val data = profile.getJSONObject(profile.getString("protocol") + "_config_data")
        val health = EndpointHealthPolicy(EndpointHealthPolicy.staleBudget(
            data.optString("RekeyAfterTime"), data.optString("RejectAfterTime")))
        endpointHealthJob = scope.launch {
            while (true) {
                delay(5000)
                val action = synchronized(endpointLock) {
                    if (generation != endpointHealthGeneration) return@launch
                    val sample = if (routedHandle > 0) RoutingBackend.stats(routedHandle)?.let {
                        longArrayOf(it[2], it[1], it[0]) // handshake, tx, rx
                    } else if (tunnelHandle >= 0) GoBackend.awgGetConfig(tunnelHandle)?.let { text ->
                        val values = text.lineSequence().map { it.split('=', limit = 2) }
                            .filter { it.size == 2 }.associate { it[0] to it[1] }
                        longArrayOf(values["last_handshake_time_sec"]?.toLongOrNull() ?: 0,
                            values["tx_bytes"]?.toLongOrNull() ?: 0, values["rx_bytes"]?.toLongOrNull() ?: 0)
                    } else null
                    if (sample == null) health.sample(-endpointBackendEpoch, 0, 0, 0, SystemClock.elapsedRealtime())
                    else health.sample(endpointBackendEpoch, sample[0], sample[1], sample[2], SystemClock.elapsedRealtime())
                }
                when (action) {
                    EndpointHealthPolicy.Action.NONE -> Unit
                    EndpointHealthPolicy.Action.REFRESH -> endpointRecovery?.invoke {
                        synchronized(endpointLock) { generation == endpointHealthGeneration && originalProfile != null }
                    }
                    EndpointHealthPolicy.Action.EXHAUSTED -> {
                        if (synchronized(endpointLock) { generation == endpointHealthGeneration })
                            onError("VPN endpoint recovery exhausted; check the server and reconnect")
                        return@launch
                    }
                }
            }
        }
    }

    override fun stopVpn() = synchronized(endpointLock) {
        ++endpointGeneration
        ++endpointHealthGeneration
        endpointHealthJob?.cancel()
        endpointHealthJob = null
        endpointRefreshJob?.cancel()
        endpointRefreshJob = null
        originalProfile = null
        if (routedConfig != null) stopRouted()
        if (tunnelHandle != -1) turnOffVpn()
        state.value = DISCONNECTED
    }

    override fun reconnectVpn(vpnBuilder: Builder, protect: (Int) -> Boolean) {
        val snapshot = synchronized(endpointLock) { originalProfile?.let { JSONObject(it.toString()) } }
        if (snapshot != null && DomainEndpointRefresh.isDomain(endpointHost(snapshot))) {
            synchronized(endpointLock) {
                endpointRefreshJob?.cancel()
                val generation = ++endpointGeneration
                endpointRefreshJob = scope.launch {
                    try {
                        // Resolve first, retaining the existing capture/backend
                        // while the replacement network's DNS is unavailable.
                        val resolved = refreshEndpoint(snapshot)
                        currentCoroutineContext().ensureActive()
                        synchronized(endpointLock) {
                            if (generation != endpointGeneration) return@launch
                            if (resolved.has("sing_box_routing")) startRouted(resolved, vpnBuilder, protect)
                            else {
                                val parsed = parseConfig(resolved)
                                start(parsed, vpnBuilder, protect, true)
                                this@Wireguard.config = parsed
                            }
                        }
                    } catch (cancelled: CancellationException) { throw cancelled }
                    catch (_: Exception) {
                        if (generation == synchronized(endpointLock) { endpointGeneration })
                            onError("Could not refresh the VPN endpoint on the new network; reconnect or check DNS")
                    }
                }
            }
            return
        }
        routedConfig?.let { startRouted(it, vpnBuilder, protect); return }
        val config = this.config ?: throw VpnException("Reconnect config is empty")
        start(config, vpnBuilder, protect, true)
    }
}
