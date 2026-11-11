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
import org.amnezia.vpn.util.net.AwgCorePolicy
import org.amnezia.vpn.util.net.AndroidAppRoutingPolicy
import android.content.pm.PackageManager
import org.amnezia.vpn.util.net.UnderlayRecoveryState
import android.os.SystemClock
import android.os.Build
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
    private var routedRecoveryJob: Job? = null
    private val recoveryState = UnderlayRecoveryState()
    override fun connectionDiagnostics(): JSONObject {
        val shared = routedHandle
        val legacy = tunnelHandle
        return JSONObject().put("backend", if (shared > 0) "shared" else if (legacy >= 0) "legacy" else "stopped")
            .put("session_id", if (shared > 0) shared else legacy.toLong())
            .put("preserves_connections", shared > 0)
    }
    override fun updateApplicationPolicy(policy: JSONObject, expectedSession: Long): JSONObject = synchronized(endpointLock) {
        require(Build.VERSION.SDK_INT >= 29 && routedHandle > 0 && expectedSession > 0) { "Live application routing is unavailable" }
        require(connectionDiagnostics()?.optLong("session_id", -1) == expectedSession) { "VPN session changed" }
        val next = routedConfig?.let { JSONObject(it.toString()) } ?: error("No routed profile")
        require(next.optInt("appSplitTunnelType", 0) == 1) { "Live rules require an application include list" }
        next.put("android_app_routing", JSONObject(policy.toString()))
        require(AwgCorePolicy.platformSafe(Build.VERSION.SDK_INT, lockdownEnabled(), next)) { "Application policy is incompatible with Android VPN lockdown" }
        val resolved = AndroidAppRoutingPolicy.resolveForSession(next, Build.VERSION.SDK_INT, { name ->
            try { context.packageManager.getApplicationInfo(name, 0).uid }
            catch (_: PackageManager.NameNotFoundException) { null }
        }, { uid -> context.packageManager.getPackagesForUid(uid)?.toList() ?: emptyList() }) ?: error("No application policy")
        require(RoutingBackend.updateAndroidApplications(routedHandle, resolved.toString().toByteArray(Charsets.UTF_8))) { "Application routing update failed" }
        routedConfig = next
        originalProfile = originalProfile?.let { JSONObject(it.toString()).put("android_app_routing", JSONObject(policy.toString())) }
        originalProfile?.let { JSONObject(it.toString()) } ?: next
    }

    override val preservesConnections: Boolean get() = routedHandle > 0
    private val routedScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private fun startRouted(config: JSONObject, vpnBuilder: Builder, protect: (Int) -> Boolean) {
        if (!AwgCorePolicy.platformSafe(Build.VERSION.SDK_INT, lockdownEnabled(), config)) {
            throw VpnStartException(if (Build.VERSION.SDK_INT < 29) "DIRECT routing requires Android 10 or newer" else "DIRECT routing or network DNS is unavailable while Android VPN lockdown is enabled")
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
        val parameters = JSONObject()
        val excluded = setOf("private_key", "public_key", "preshared_key", "replace_peers", "replace_allowed_ips", "allowed_ip", "endpoint", "persistent_keepalive_interval", "listen_port")
        for (line in wg.toWgUserspaceString().lineSequence()) {
            val key = line.substringBefore('=')
            if (line.contains('=') && key !in excluded) parameters.put(key, line.substringAfter('='))
        }
        val adapterType = AwgCorePolicy.transportAdapter(transportType, parameters.length() != 0 || wg.persistentKeepalive?.contains('-') == true)
        val session = JSONObject().apply {
            AndroidAppRoutingPolicy.resolveForSession(config, Build.VERSION.SDK_INT, { name ->
                try { context.packageManager.getApplicationInfo(name, 0).uid }
                catch (_: PackageManager.NameNotFoundException) { null }
            }, { uid -> context.packageManager.getPackagesForUid(uid)?.toList() ?: emptyList() })?.let {
                put("android_applications", it)
            }
            put("cache_path", java.io.File(context.filesDir, "routing-fakeip-v1.db").absolutePath)
            put("rules", config.getJSONObject("sing_box_routing"))
            if (splitDNS != null) {
                put("dns", splitDNS)
                if (splitDNS.optBoolean("preserve_network_domains") || splitDNS.getJSONObject("policies").keys().asSequence().any {
                    splitDNS.getJSONObject("policies").getJSONObject(it).optString("source") == "network"
                }) put("network_dns", networkDnsSnapshot?.invoke() ?: throw VpnStartException("Underlying-network DNS is unavailable"))
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
                put("type", adapterType)
                put(adapterType, JSONObject().apply {
                    put("address", JSONArray(wg.addresses.map { it.address.hostAddress!!.substringBefore('%') }))
                    put("private_key", data.getString("client_priv_key"))
                    put("public_key", data.getString("server_pub_key"))
                    if (!data.optString("psk_key").isNullOrEmpty()) put("pre_shared_key", data.getString("psk_key"))
                    put("endpoint", wg.endpoint.toString())
                    put("allowed_ips", allowed)
                    put("mtu", wg.mtu)
                    data.optString("path_mtu_probe").takeIf { it.isNotBlank() }?.let { put("path_mtu_probe", it) }
                    // Preserve AWG 3.1 ranges; the shared native validator checks them.
                    if (adapterType == "awg") {
                        put("keepalive", wg.persistentKeepalive ?: "0")
                        put("parameters", parameters)
                    } else {
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
        val initialNetwork = underlayIdentity?.invoke()
        Log.i(TAG, "AWG backend: shared TCP/DNS core")
        routedConfig = JSONObject(config.toString())
        buildVpnInterface(capture, vpnBuilder)
        vpnBuilder.establish().use { descriptor ->
            if (descriptor == null) throw VpnStartException("Cannot establish the routed VPN interface")
            routedHandle = RoutingBackend.start(descriptor.detachFd(), session, RoutingHost(underlayProtect ?: protect, networkDnsProtect, context))
        }
        if (routedHandle <= 0) {
            routedHandle = -1L
            // Do not silently retry the legacy backend or expose VPN flows.
            throw VpnStartException("Domain routing startup failed; check the profile and routing rules")
        }
        recoveryState.start(routedHandle, initialNetwork, wg.endpoint.toString())
        ++endpointBackendEpoch
        val statusHandle = routedHandle
        routedStatusJob = routedScope.launch {
            var announced = false
            while (routedHandle == statusHandle) {
                // Lockdown may be enabled while a routed tunnel is active.
                // Stop rather than allowing protected DIRECT proxy sockets to
                // circumvent the user's OS policy. The OS keeps traffic blocked.
                if (!AwgCorePolicy.platformSafe(Build.VERSION.SDK_INT, lockdownEnabled(), config)) {
                    synchronized(endpointLock) { stopVpn() }
                    state.value = DISCONNECTED
                    onError("Experimental domain routing stopped because Android VPN lockdown is enabled")
                    break
                }
                val snapshot = RoutingBackend.stats(statusHandle)
                if (routedHandle != statusHandle) break
                if (snapshot == null) {
                    synchronized(endpointLock) {
                        if (routedHandle == statusHandle) {
                            stopVpn()
                            onError("VPN packet capture stopped; reconnect is required")
                        }
                    }
                    break
                }
                if (!announced && snapshot[2] > 0) { state.value = CONNECTED; announced = true }
                delay(1000)
            }
        }
        // Close the startup race: the usable physical path may have changed
        // while DNS/native startup ran before the handle became observable.
        requestRoutedRecovery(false)
    }

    private fun stopRouted() {
        routedRecoveryJob?.cancel()
        routedRecoveryJob = null
        recoveryState.stop()
        routedConfig = null
        routedStatusJob?.cancel()
        routedStatusJob = null
        val handle = routedHandle
        routedHandle = -1L
        if (handle > 0) RoutingBackend.stop(handle)
    }

    @Volatile private var tunnelHandle: Int = -1
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
        val prepared = AwgCorePolicy.prepare(config)
        val generation = synchronized(endpointLock) {
            endpointRefreshJob?.cancel()
            ++endpointHealthGeneration
            endpointHealthJob?.cancel()
            endpointCandidates = DomainEndpointRefresh.Candidates()
            originalProfile = JSONObject(prepared.toString())
            ++endpointGeneration
        }
        val resolved = refreshEndpoint(prepared)
        currentCoroutineContext().ensureActive()
        synchronized(endpointLock) {
            if (generation != endpointGeneration) return
            if (resolved.has("sing_box_routing")) {
                if (tunnelHandle != -1) turnOffVpn()
                startRouted(resolved, vpnBuilder, protect)
            } else {
                stopRouted()
                routedConfig = null
                Log.i(TAG, "AWG backend: legacy (explicit override)")
                val wireguardConfig = parseConfig(resolved)
                start(wireguardConfig, vpnBuilder, protect)
                this.config = wireguardConfig
            }
            startEndpointWatchdog(prepared)
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
        if ((routedHandle <= 0 && !DomainEndpointRefresh.isDomain(endpointHost(profile))) || endpointRecovery == null) return
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
                        if (synchronized(endpointLock) { generation == endpointHealthGeneration }) {
                            if (routedHandle > 0) {
                                // The retained recovery worker already retries
                                // with bounded backoff. An offline network is
                                // not a fatal error or a request to destroy TCP.
                                Log.w(TAG, "AWG peer unavailable; retaining TCP while waiting for network")
                            } else onError("VPN endpoint recovery exhausted; check the server and reconnect")
                        }
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
        releaseNetworkHooks()
        state.value = DISCONNECTED
    }

    override fun refreshVpn(vpnBuilder: Builder, protect: (Int) -> Boolean, force: Boolean) {
        if (routedHandle > 0) requestRoutedRecovery(force) else reconnectVpn(vpnBuilder, protect)
    }

    private fun requestRoutedRecovery(force: Boolean) = synchronized(endpointLock) {
        val handle = routedHandle
        val profile = originalProfile?.let { JSONObject(it.toString()) } ?: return@synchronized
        if (handle <= 0) return@synchronized
        val ticket = recoveryState.request(force) ?: return@synchronized
        routedRecoveryJob?.cancel()
        val refreshDns = !AwgCorePolicy.retainsVpnDns(profile)
        if (refreshDns) RoutingBackend.suspendNetworkDns(handle)
        routedRecoveryJob = routedScope.launch {
            var attempt = 0
            while (true) {
                currentCoroutineContext().ensureActive()
                try {
                    val identity = underlayIdentity?.invoke()
                        ?: throw VpnException("Underlying network is unavailable")
                    val decision = recoveryState.decide(ticket, identity) ?: return@launch
                    val reopen = decision.reopen
                    var endpoint = decision.endpoint
                    val before = RoutingBackend.stats(handle)
                    synchronized(endpointLock) {
                        if (!recoveryState.current(ticket) || handle != routedHandle) return@launch
                        if (!RoutingBackend.refresh(handle, endpoint, reopen)) {
                            recoveryState.transportFailed(ticket)
                            throw VpnException("Protected UDP refresh failed")
                        }
                        // Rebind to the cached peer before doing any DNS work:
                        // slow/broken bootstrap DNS must not stall a usable IP.
                        recoveryState.commitTransport(ticket, identity, endpoint)
                    }
                    if (refreshDns) {
                        val dns = profile.optJSONObject("sing_box_dns")
                        val needsNetwork = dns?.let { options ->
                            options.optBoolean("preserve_network_domains") ||
                                options.getJSONObject("policies").keys().asSequence().any {
                                    options.getJSONObject("policies").getJSONObject(it).optString("source") == "network"
                                }
                        } ?: false
                        val inventory = if (needsNetwork) networkDnsSnapshot?.invoke()
                            ?: throw VpnException("Network DNS is unavailable")
                        else JSONObject().put("links", JSONArray()).put("routing_domains_available", false)
                        currentCoroutineContext().ensureActive()
                        if (underlayIdentity?.invoke() != identity) continue
                        synchronized(endpointLock) {
                            if (!recoveryState.current(ticket) || handle != routedHandle) return@launch
                            if (!RoutingBackend.reloadNetworkDns(handle, inventory.toString().toByteArray(Charsets.UTF_8)))
                                throw VpnException("Network DNS refresh failed")
                        }
                    }
                    if (decision.verifyPeer) {
                        var authenticated = false
                        repeat(6) {
                            currentCoroutineContext().ensureActive()
                            if (!recoveryState.current(ticket)) return@launch
                            val now = RoutingBackend.stats(handle)
                            if (now != null && before != null && (now[0] > before[0] || now[2] > 0 && now[2] != before[2])) authenticated = true
                            if (!authenticated) {
                                delay(1000)
                                synchronized(endpointLock) {
                                    if (recoveryState.current(ticket) && handle == routedHandle)
                                        RoutingBackend.refresh(handle, endpoint, false)
                                }
                            }
                        }
                        if (authenticated) recoveryState.authenticated(ticket)
                        else {
                            // The original TCP state remains alive even if the
                            // peer's domain or the physical network is absent.
                            recoveryState.transportFailed(ticket)
                            if (DomainEndpointRefresh.isDomain(endpointHost(profile))) {
                                val resolver = endpointResolver ?: throw VpnException("Endpoint DNS is unavailable")
                                val address = DomainEndpointRefresh.resolve(endpointHost(profile), resolver,
                                    attempts = 1, timeoutMs = 5000, retryMs = 0, candidates = endpointCandidates)
                                val data = profile.getJSONObject(profile.getString("protocol") + "_config_data")
                                val replacement = InetEndpoint(parseInetAddress(address), data.getInt("port")).toString()
                                if (replacement != endpoint) synchronized(endpointLock) {
                                    if (!recoveryState.current(ticket) || handle != routedHandle) return@launch
                                    if (!RoutingBackend.refresh(handle, replacement, true)) {
                                        recoveryState.transportFailed(ticket)
                                        throw VpnException("Peer endpoint refresh failed")
                                    }
                                    endpoint = replacement
                                    recoveryState.commitTransport(ticket, identity, endpoint)
                                }
                            }
                            throw VpnException("Awaiting authenticated peer progress")
                        }
                    }
                    Log.i(TAG, "AWG network refreshed; TUN and TCP owner retained")
                    return@launch
                } catch (cancelled: CancellationException) { throw cancelled }
                catch (_: Exception) {
                    // Network absence is not a stop request. Keep the capture,
                    // flow stack and original TCP streams until explicit stop.
                    if (synchronized(endpointLock) { !recoveryState.current(ticket) || handle != routedHandle }) return@launch
                    if (attempt == 0) Log.i(TAG, "AWG waiting for network; existing TCP owner retained")
                    delay(minOf(30000L, 1000L shl minOf(attempt++, 5)))
                }
            }
        }
    }

    override fun reconnectVpn(vpnBuilder: Builder, protect: (Int) -> Boolean) {
        if (routedHandle > 0) { requestRoutedRecovery(false); return }
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
