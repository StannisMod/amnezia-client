package org.amnezia.vpn.protocol.openvpn

import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.ParcelFileDescriptor
import org.amnezia.vpn.protocol.VpnStartException
import java.io.File
import java.net.InetAddress
import java.util.concurrent.TimeUnit

// ConnectivityService exposes its new LinkProperties before updateRoutes()
// finishes. Its LinkProperties callback, unlike a getter/poll, follows netd's
// route installation. Observe the final TUN, not a provisional guard network.
internal class OpenVpnPublication(private val manager: ConnectivityManager) : AutoCloseable {
    private val lock = Object()
    private val state = TunPublicationState(manager.allNetworks.associate {
        it.networkHandle to manager.getLinkProperties(it)?.interfaceName
    })
    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onLinkPropertiesChanged(network: Network, links: LinkProperties) {
            synchronized(lock) {
                state.publish(network.networkHandle, TunPublicationSnapshot(
                    links.interfaceName,
                    links.linkAddresses.map { prefix(it.address, it.prefixLength) }.toSet(),
                    links.routes.map { prefix(it.destination.address, it.destination.prefixLength) }.toSet(),
                    links.dnsServers.map { it.hostAddress?.substringBefore('%').orEmpty() }
                ))
                lock.notifyAll()
            }
        }

        override fun onLost(network: Network) {
            synchronized(lock) { state.lost(network.networkHandle) }
        }
    }

    init {
        manager.registerNetworkCallback(NetworkRequest.Builder()
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .addTransportType(NetworkCapabilities.TRANSPORT_VPN).build(), callback)
    }

    fun await(fd: ParcelFileDescriptor, config: OpenVpnConfig,
              managedDns: List<InetAddress>? = null): PublishedOpenVpnTun {
        val name = File("/proc/self/fdinfo/${fd.fd}").useLines { lines ->
            lines.firstOrNull { it.startsWith("iff:") }?.substringAfter(':')?.trim()?.takeIf { it.isNotEmpty() }
        } ?: throw VpnStartException("Cannot identify the final OpenVPN capture interface")
        val addresses = config.addresses.map { prefix(it.address, it.mask) }.toSet()
        val routes = config.routes.filter { it.include }
            .map { prefix(it.inetNetwork.address, it.inetNetwork.mask) }.toSet()
        val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
        val selectedDns = managedDns?.map { it.hostAddress?.substringBefore('%').orEmpty() }
        synchronized(lock) {
            while (true) {
                state.readyNetwork(name, addresses, routes, selectedDns)?.let { handle ->
                    return PublishedOpenVpnTun(Network.fromNetworkHandle(handle), name) {
                        synchronized(lock) { state.current(handle, name, addresses, routes, selectedDns) }
                    }
                }
                if (state.cancelled) throw VpnStartException("OpenVPN capture publication cancelled")
                val remaining = until - System.nanoTime()
                if (remaining <= 0)
                    throw VpnStartException("Android did not publish the final OpenVPN capture routes")
                TimeUnit.NANOSECONDS.timedWait(lock, remaining)
            }
        }
    }

    fun cancel() {
        synchronized(lock) {
            state.cancel()
            lock.notifyAll()
        }
    }

    override fun close() {
        cancel()
        try { manager.unregisterNetworkCallback(callback) }
        catch (_: IllegalArgumentException) { /* Already removed by the framework. */ }
    }

    private fun prefix(address: InetAddress, length: Int) =
        "${address.hostAddress?.substringBefore('%')}/$length"
}

internal data class TunPublicationSnapshot(
    val interfaceName: String?,
    val addresses: Set<String>,
    val routes: Set<String>,
    val dnsServers: List<String> = emptyList()
)

internal class PublishedOpenVpnTun(
    val network: Network,
    val interfaceName: String,
    val current: () -> Boolean
)

internal class TunPublicationState(private val previousInterfaces: Map<Long, String?>) {
    private val updates = mutableMapOf<Long, TunPublicationSnapshot>()
    private val lost = mutableSetOf<Long>()
    var cancelled = false
        private set

    fun publish(network: Long, snapshot: TunPublicationSnapshot) {
        if (network !in lost) updates[network] = snapshot
    }
    fun lost(network: Long) { updates.remove(network); lost += network }
    fun cancel() { cancelled = true }

    fun ready(name: String, addresses: Set<String>, routes: Set<String>): Boolean =
        readyNetwork(name, addresses, routes) != null

    fun readyNetwork(name: String, addresses: Set<String>, routes: Set<String>,
                     dnsServers: List<String>? = null): Long? =
        if (cancelled) null else updates.keys.filter { current(it, name, addresses, routes, dnsServers) }.singleOrNull()

    fun current(network: Long, name: String, addresses: Set<String>, routes: Set<String>,
                dnsServers: List<String>? = null): Boolean {
        val snapshot = updates[network] ?: return false
        return !cancelled && network !in lost && previousInterfaces[network] != name &&
            snapshot.interfaceName == name && snapshot.addresses.containsAll(addresses) &&
            snapshot.routes.containsAll(routes) && (dnsServers == null || snapshot.dnsServers == dnsServers)
    }
}
