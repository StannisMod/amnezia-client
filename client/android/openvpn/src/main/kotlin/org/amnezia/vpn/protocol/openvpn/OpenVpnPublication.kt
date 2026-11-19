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
                    links.routes.map { prefix(it.destination.address, it.destination.prefixLength) }.toSet()
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

    fun await(fd: ParcelFileDescriptor, config: OpenVpnConfig) {
        val name = File("/proc/self/fdinfo/${fd.fd}").useLines { lines ->
            lines.firstOrNull { it.startsWith("iff:") }?.substringAfter(':')?.trim()?.takeIf { it.isNotEmpty() }
        } ?: throw VpnStartException("Cannot identify the final OpenVPN capture interface")
        val addresses = config.addresses.map { prefix(it.address, it.mask) }.toSet()
        val routes = config.routes.filter { it.include }
            .map { prefix(it.inetNetwork.address, it.inetNetwork.mask) }.toSet()
        val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
        synchronized(lock) {
            while (!state.ready(name, addresses, routes)) {
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
        try { manager.unregisterNetworkCallback(callback) }
        catch (_: IllegalArgumentException) { /* Already removed by the framework. */ }
    }

    private fun prefix(address: InetAddress, length: Int) =
        "${address.hostAddress?.substringBefore('%')}/$length"
}

internal data class TunPublicationSnapshot(
    val interfaceName: String?,
    val addresses: Set<String>,
    val routes: Set<String>
)

internal class TunPublicationState(private val previousInterfaces: Map<Long, String?>) {
    private val updates = mutableMapOf<Long, TunPublicationSnapshot>()
    var cancelled = false
        private set

    fun publish(network: Long, snapshot: TunPublicationSnapshot) { updates[network] = snapshot }
    fun lost(network: Long) { updates.remove(network) }
    fun cancel() { cancelled = true }

    fun ready(name: String, addresses: Set<String>, routes: Set<String>): Boolean =
        !cancelled && updates.any { (network, snapshot) ->
            previousInterfaces[network] != name && snapshot.interfaceName == name &&
                snapshot.addresses.containsAll(addresses) && snapshot.routes.containsAll(routes)
        }
}
