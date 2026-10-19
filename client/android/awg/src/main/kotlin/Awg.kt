package org.amnezia.vpn.protocol.awg

import android.net.VpnService.Builder
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.amnezia.awg.RoutingBackend
import org.amnezia.awg.RoutingHost
import org.amnezia.vpn.protocol.ProtocolConfig
import org.amnezia.vpn.protocol.ProtocolState.CONNECTED
import org.amnezia.vpn.protocol.ProtocolState.DISCONNECTED
import org.amnezia.vpn.protocol.Statistics
import org.amnezia.vpn.protocol.VpnStartException
import org.amnezia.vpn.util.net.InetNetwork
import org.amnezia.vpn.util.net.parseInetAddress
import org.amnezia.vpn.protocol.wireguard.Wireguard
import org.amnezia.vpn.protocol.wireguard.WireguardConfig
import org.json.JSONArray
import org.json.JSONObject

class Awg : Wireguard() {

    override val ifName: String = "awg0"

    @Volatile private var routedHandle = -1L
    @Volatile private var routedConfig: JSONObject? = null
    private var routedStatusJob: Job? = null
    private val routedScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override val statistics: Statistics
        get() {
            if (routedConfig == null) return super.statistics
            val counters = RoutingBackend.stats(routedHandle) ?: return Statistics.EMPTY_STATISTICS
            return Statistics.build { setRxBytes(counters[0]); setTxBytes(counters[1]) }
        }

    override suspend fun startVpn(config: JSONObject, vpnBuilder: Builder, protect: (Int) -> Boolean) {
        if (config.has("sing_box_routing")) {
            if (routedConfig == null) super.stopVpn()
            startRouted(config, vpnBuilder, protect)
        } else {
            stopRouted()
            routedConfig = null
            super.startVpn(config, vpnBuilder, protect)
        }
    }

    private fun startRouted(config: JSONObject, vpnBuilder: Builder, protect: (Int) -> Boolean) {
        // Use the existing profile parser, including every AWG 3.1 parameter,
        // but never materialize the legacy site's cached IP exclusions.
        val parseInput = JSONObject(config.toString()).apply { put("splitTunnelType", 0) }
        val wg = parseConfig(parseInput)
        val data = config.getJSONObject("awg_config_data")
        val allowed = data.getJSONArray("allowed_ips")
        val allowedSet = (0 until allowed.length()).map { allowed.getString(it).trim() }.toSet()
        if ("0.0.0.0/0" !in allowedSet) {
            throw VpnStartException("Experimental domain routing requires an IPv4 default route in the AWG profile")
        }
        val parameters = JSONObject()
        val excluded = setOf("private_key", "public_key", "preshared_key", "replace_peers", "replace_allowed_ips", "allowed_ip", "endpoint", "persistent_keepalive_interval", "listen_port")
        for (line in wg.toWgUserspaceString().lineSequence()) {
            val key = line.substringBefore('=')
            if (line.contains('=') && key !in excluded) parameters.put(key, line.substringAfter('='))
        }
        val resolverValue = config.optString("dns1").ifBlank { config.optString("dns2") }
        if (resolverValue.isBlank()) throw VpnStartException("A numeric DNS resolver is required for domain routing")
        val resolver = parseInetAddress(resolverValue)
        val resolverIp = resolver.hostAddress?.substringBefore('%')
            ?: throw VpnStartException("Invalid DNS resolver")
        val resolverEndpoint = if (resolverIp.contains(':')) "[$resolverIp]:53" else "$resolverIp:53"
        val session = JSONObject().apply {
            put("rules", config.getJSONObject("sing_box_routing"))
            put("resolver", resolverEndpoint)
            put("resolver_action", if (resolver.isLoopbackAddress) "direct" else config.optString("sing_box_dns_path", "vpn"))
            put("awg", JSONObject().apply {
                put("address", JSONArray(wg.addresses.map { it.address.hostAddress!!.substringBefore('%') }))
                put("private_key", data.getString("client_priv_key"))
                put("public_key", data.getString("server_pub_key"))
                if (!data.optString("psk_key").isNullOrEmpty()) put("pre_shared_key", data.getString("psk_key"))
                put("endpoint", wg.endpoint.toString())
                put("allowed_ips", allowed)
                put("mtu", wg.mtu)
                put("keepalive", wg.persistentKeepalive?.toIntOrNull() ?: 0)
                put("parameters", parameters)
            })
        }.toString().toByteArray(Charsets.UTF_8)

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
        routedStatusJob = routedScope.launch {
            while (true) {
                val snapshot = RoutingBackend.stats(routedHandle) ?: break
                if (snapshot[2] > 0) { state.value = CONNECTED; break }
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

    override fun stopVpn() {
        if (routedConfig != null) { stopRouted(); state.value = DISCONNECTED }
        else super.stopVpn()
    }

    override fun reconnectVpn(vpnBuilder: Builder, protect: (Int) -> Boolean) {
        val config = routedConfig
        if (config != null) startRouted(config, vpnBuilder, protect)
        else super.reconnectVpn(vpnBuilder, protect)
    }

    override fun parseConfig(config: JSONObject): WireguardConfig {
        val configData = config.getJSONObject("awg_config_data")
        return WireguardConfig.build {
            setUseProtocolExtension(true)
            configExtensionParameters(configData)
            configWireguard(config, configData)
            configSplitTunneling(config)
            configAppSplitTunneling(config)
        }
    }
}
