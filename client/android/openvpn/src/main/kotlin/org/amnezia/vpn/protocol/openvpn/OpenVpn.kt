package org.amnezia.vpn.protocol.openvpn

import android.net.VpnService.Builder
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import net.openvpn.ovpn3.ClientAPI_Config
import org.amnezia.vpn.protocol.BadConfigException
import org.amnezia.vpn.protocol.Protocol
import org.amnezia.vpn.protocol.ProtocolState.DISCONNECTED
import org.amnezia.vpn.protocol.ProtocolState.DISCONNECTING
import org.amnezia.vpn.protocol.NativeDnsPlan
import org.amnezia.vpn.protocol.NativeDnsPublication
import org.amnezia.vpn.protocol.Route
import org.amnezia.vpn.protocol.Statistics
import org.amnezia.vpn.protocol.VpnStartException
import org.amnezia.vpn.util.LibraryLoader.loadSharedLibrary
import org.amnezia.vpn.util.net.InetNetwork
import org.amnezia.vpn.util.net.getLocalNetworks
import org.amnezia.vpn.util.net.parseInetAddress
import org.json.JSONObject
import android.os.Build
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicBoolean

open class OpenVpn : Protocol() {

    private val publicationLock = Any()
    @Volatile private var nativeOwner: NativeOwner? = null
    private lateinit var scope: CoroutineScope
    override val hasPendingNativeCleanup: Boolean get() = nativeOwner != null

    private inner class NativeOwner(
        val config: JSONObject,
        val ipv6Off: Boolean,
        val remoteAddress: InetNetwork
    ) {
        @Volatile var client: OpenVpnClient? = null
        @Volatile var stopping = false
        @Volatile var nativeExited = true
        @Volatile var preparing = true
        @Volatile var publication: OpenVpnPublication? = null
        @Volatile var currentDns: OpenVpnDnsNetwork? = null
        val bindings = OpenVpnDnsBindings()
        val watchers = ConcurrentHashMap.newKeySet<OpenVpnPublication>()
        val dnsPublications = ConcurrentHashMap.newKeySet<NativeDnsPublication>()
        val cleanupRunning = AtomicBoolean(false)
        val errors = ConcurrentLinkedQueue<String>()
        var lastPending: String? = null
        val lifecycle = OpenVpnNativeLifecycle(
            { client?.stop() }, { nativeExited },
            {
                client?.amnezia_dns_stop()
                bindings.allNativeJoined()
                dnsPublications.forEach { it.retire() }
                dnsPublications.clear()
                watchers.forEach { it.close() }
                watchers.clear()
            },
            { client?.amnezia_dns_release_policy() ?: true },
            { !preparing }
        )
        fun builder() = OpenVpnConfig.Builder().apply {
            excludeRoute(remoteAddress)
            configPluggableTransport(this, config)
            configSplitTunneling(config)
            configAppSplitTunneling(config)
        }
    }

    override val statistics: Statistics
        get() {
            synchronized(publicationLock) { nativeOwner?.client?.let { client ->
                val stats = client.transport_stats()
                return Statistics.build {
                    setRxBytes(stats.bytesIn)
                    setTxBytes(stats.bytesOut)
                }
            } }
            return Statistics.EMPTY_STATISTICS
        }

    override fun internalInit() {
        check(nativeOwner == null) { "Previous OpenVPN native cleanup is pending" }
        if (!isInitialized) {
            loadSharedLibrary(context, "ovpn3")
            loadSharedLibrary(context, "ovpnutil")
        }
        if (this::scope.isInitialized) {
            scope.cancel()
        }
        scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    }

    override suspend fun startVpn(config: JSONObject, vpnBuilder: Builder, protect: (Int) -> Boolean) {
        synchronized(publicationLock) {
            if (nativeOwner != null) throw VpnStartException("Previous OpenVPN native owner has not retired")
            val pinned = JSONObject(config.toString())
            val off = !pinned.optBoolean("ipv6_enabled", true)
            if (off && strictPrivateDnsPolicy?.invoke() != false)
                throw BadConfigException("IPv6 OFF OpenVPN is incompatible with missing/strict encrypted DNS policy")
            val remote = pinned.getString("hostName")
            val remoteAddress = InetNetwork(if (off) openVpnIpv4Endpoint(remote) else parseInetAddress(remote))
            val owner = NativeOwner(pinned, off, remoteAddress)
            nativeOwner = owner
            owner.lifecycle.begin()
            try {
                val client = OpenVpnClient(
                    configBuilder = owner.builder(), state = state,
                    getLocalNetworks = { ipv6 -> getLocalNetworks(context, ipv6) },
                    establish = makeEstablish(owner, vpnBuilder, protect),
                    protect = protect, onError = { owner.errors.add(it) },
                    builderFactory = owner::builder, ipv6Off = off,
                    permitConnected = { nativeOwner === owner && !owner.stopping &&
                        (!off || (owner.currentDns?.current == true && owner.bindings.hasNativeBindings)) },
                    permitDisconnected = { false },
                    currentOwner = { nativeOwner === owner },
                    nativeFailure = { fail(owner) },
                    dnsBind = owner.bindings::bind,
                    dnsFailed = owner.bindings::failed,
                    dnsRetired = owner.bindings::retired,
                    dnsTunnelAllowed = { owner.currentDns?.permitTunnel() == true }
                )
                owner.client = client
                if (!client.amnezia_dns_policy(off))
                    throw VpnStartException("OpenVPN native transport/DNS policy is still owned")
                val openVpnConfig = parseConfig(pinned)
                val evalConfig = client.eval_config(openVpnConfig)
                if (evalConfig.error) {
                    throw BadConfigException("OpenVPN config parse error: ${evalConfig.message}")
                }
                if (owner.stopping) throw VpnStartException("OpenVPN native preparation cancelled")

                owner.nativeExited = false
                owner.lifecycle.admit()
                scope.launch {
                    try {
                        if (!owner.stopping) {
                            val status = client.connect()
                            if (status.error) owner.errors.add("OpenVpn connect() error: ${status.status}: ${status.message}")
                        }
                    } catch (error: Exception) {
                        owner.errors.add("OpenVPN native worker failed: ${error.message}")
                    } finally {
                        owner.nativeExited = true
                        fail(owner)
                    }
                }
            } catch (error: Exception) {
                fail(owner)
                throw error
            } finally { owner.preparing = false }
        }
    }

    override fun stopVpn() {
        nativeOwner?.let(::fail)
    }

    override fun reconnectVpn(vpnBuilder: Builder, protect: (Int) -> Boolean) {
        nativeOwner?.let { owner ->
            if (!owner.stopping) {
                owner.client?.establish = makeEstablish(owner, vpnBuilder, protect)
                owner.client?.reconnect(0)
            }
        }
    }

    protected open fun parseConfig(config: JSONObject): ClientAPI_Config {
        val openVpnConfig = ClientAPI_Config()
        openVpnConfig.content = config.getJSONObject("openvpn_config_data").getString("config")
        return openVpnConfig
    }

    protected open fun configPluggableTransport(configBuilder: OpenVpnConfig.Builder, config: JSONObject) {}

    private fun makeEstablish(owner: NativeOwner, vpnBuilder: Builder,
                              protect: (Int) -> Boolean): (OpenVpnConfig.Builder) -> Int = { configBuilder ->
        val tracker = OpenVpnPublication(context.getSystemService(android.net.ConnectivityManager::class.java))
        synchronized(publicationLock) {
            if (nativeOwner !== owner || owner.stopping) {
                tracker.close()
                throw VpnStartException("OpenVPN capture publication cancelled")
            }
            owner.publication = tracker
            owner.watchers.add(tracker)
        }
        var dns: OpenVpnDnsNetwork? = null
        var managed: NativeDnsPublication? = null
        try {
            val client = owner.client ?: throw VpnStartException("Missing native OpenVPN owner")
            val original = configBuilder.build()
            if (owner.ipv6Off) {
                val strict = strictPrivateDnsPolicy
                    ?: throw VpnStartException("Missing Android encrypted-DNS policy snapshot")
                val originalRoutes = original.routes.toList() + if (Build.BRAND == "samsung")
                    original.dnsServers.map { Route(InetNetwork(it), true) } else emptyList()
                val selected = NativeDnsPublication.prepare(
                    NativeDnsPlan.prepareSelected(client.selectedDns, originalRoutes, original.addresses),
                    strict(), lockdownEnabled(), networkDnsSnapshot, networkDnsIdentity, protect, networkDnsProtect)
                managed = selected
                owner.dnsPublications.add(selected)
                val network = OpenVpnDnsNetwork(selected, strict) { nativeOwner === owner && !owner.stopping }
                dns = network
                owner.currentDns = network
                val generation = OpenVpnDnsBindings.Generation(
                    network::bind,
                    {
                        selected.beginFailure()
                        // Go callback: enqueue only; never synchronously reenter
                        // stop/join JNI while the callback itself is retained.
                        if (owner.currentDns === network && nativeOwner === owner) {
                            owner.errors.add("OpenVPN native DNS frontend failed")
                            fail(owner)
                        }
                    },
                    {
                        selected.retire()
                        owner.dnsPublications.remove(selected)
                        tracker.close()
                        owner.watchers.remove(tracker)
                    }
                )
                for (binding in selected.bindings) {
                    val handle = if (binding.scope == org.amnezia.vpn.protocol.NativeDnsScope.TUNNEL) {
                        val source = original.addresses.filter { it.address.address.size == 4 }.singleOrNull()
                            ?: throw VpnStartException("Missing unambiguous original OpenVPN DNS tunnel source")
                        client.amnezia_dns_prepare_tunnel(
                            binding.endpoint.substringBefore(':'), source.address.hostAddress, original.mtu,
                            binding.upstream, binding.transport.wire, binding.serverName, binding.httpsUrl)
                    } else client.amnezia_dns_prepare_selected(
                        binding.endpoint.substringBefore(':'), binding.upstream,
                        binding.transport.wire, binding.serverName, binding.httpsUrl)
                    owner.bindings.register(handle, generation, binding)
                }
                configBuilder.setManagedDnsServers(selected.aliases)
                configBuilder.setSearchDomains(client.selectedSearchDomains)
            }
            if (owner.stopping) throw VpnStartException("OpenVPN DNS publication cancelled")
            val finalConfig = configBuilder.build()
            buildVpnInterface(finalConfig, vpnBuilder)
            vpnBuilder.establish().use { tunFd ->
                if (tunFd == null)
                    throw VpnStartException("Create VPN interface: permission not granted or revoked")
                val capture = tracker.await(tunFd, finalConfig, managed?.aliases)
                dns?.publish(capture)
                if (owner.stopping) throw VpnStartException("OpenVPN native admission cancelled")
                tunFd.detachFd()
            }
        } finally {
            if (owner.publication === tracker) owner.publication = null
            if (!owner.ipv6Off) {
                tracker.close()
                owner.watchers.remove(tracker)
            }
            // OFF's callback tracker and original-network publication remain
            // retained until native retirement, including partial preparation.
        }
    }

    private fun fail(owner: NativeOwner) {
        if (nativeOwner !== owner) return
        owner.stopping = true
        owner.publication?.cancel()
        if (!owner.cleanupRunning.compareAndSet(false, true)) return
        scope.launch {
            try {
                while (nativeOwner === owner) {
                    state.value = DISCONNECTING
                    // Never hold the protocol/UI lock across a native join or
                    // public Android Network.bindSocket callback.
                    val pending = owner.lifecycle.cleanup()
                    if (pending == null) {
                        synchronized(publicationLock) {
                            if (nativeOwner === owner) {
                                owner.client?.delete()
                                owner.client = null
                                // No native error is published as a terminal
                                // event before worker/DNS/policy retirement.
                                while (true) onError(owner.errors.poll() ?: break)
                                nativeOwner = null
                                releaseNetworkHooks()
                                state.value = DISCONNECTED
                            }
                        }
                        return@launch
                    }
                    if (pending != owner.lastPending) {
                        owner.lastPending = pending
                        onError("OpenVPN native cleanup pending: $pending")
                    }
                    delay(250)
                }
            } finally { owner.cleanupRunning.set(false) }
        }
    }
}
