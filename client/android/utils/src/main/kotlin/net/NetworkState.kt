package org.amnezia.vpn.util.net

import android.content.Context
import android.net.ConnectivityManager
import android.net.ConnectivityManager.NetworkCallback
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET
import android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED
import android.net.NetworkRequest
import android.net.LinkProperties
import android.os.ParcelFileDescriptor
import android.os.Build
import android.os.Handler
import androidx.core.content.getSystemService
import kotlin.LazyThreadSafetyMode.NONE
import kotlinx.coroutines.delay
import org.amnezia.vpn.util.Log
import org.json.JSONObject
import org.json.JSONArray
import java.util.concurrent.ConcurrentHashMap
import java.net.Inet6Address
import java.net.NetworkInterface

private const val TAG = "NetworkState"

class NetworkState(
    private val context: Context,
    private val onNetworkChange: () -> Unit
) {
    private val lostNetworks = ConcurrentHashMap.newKeySet<Network>()
    private val state = ValidatedNetworkState<Network>()
    private var isListenerBound = false
    private val dnsNetworks = ConcurrentHashMap<String, Network>()
    private val pathFingerprints = ConcurrentHashMap<Network, String>()
    private val dnsFingerprints = ConcurrentHashMap<Network, String>()
    @Volatile private var preferredDnsNetwork: Network? = null

    private fun dnsFingerprint(properties: LinkProperties): String = listOf(
        properties.interfaceName, properties.dnsServers.joinToString { it.hostAddress ?: "" },
        properties.domains, properties.isPrivateDnsActive, properties.privateDnsServerName
    ).joinToString("|")

    fun dnsSnapshot(): JSONObject {
        val available = connectivityManager.allNetworks.mapNotNull { network ->
            if (network in lostNetworks) return@mapNotNull null
            val capabilities = connectivityManager.getNetworkCapabilities(network) ?: return@mapNotNull null
            if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) ||
                !capabilities.hasCapability(NET_CAPABILITY_INTERNET)) return@mapNotNull null
            val properties = connectivityManager.getLinkProperties(network) ?: return@mapNotNull null
            if (properties.dnsServers.isEmpty()) return@mapNotNull null
            Triple(network, properties, capabilities.hasCapability(NET_CAPABILITY_VALIDATED))
        }.sortedBy { it.first.networkHandle }
        val active = connectivityManager.activeNetwork
        val preferred = available.firstOrNull { it.first == active }
            ?: available.firstOrNull { it.first == preferredDnsNetwork }
            ?: available.filter { it.third }.singleOrNull()
        preferredDnsNetwork = preferred?.first
        val links = JSONArray()
        for ((network, properties, _) in available) {
            val token = "android-${network.networkHandle}"
            val privateName = properties.privateDnsServerName
            val addresses = if (properties.isPrivateDnsActive && privateName != null)
                network.getAllByName(privateName).toList() else properties.dnsServers
            val servers = JSONArray()
            for (address in addresses) {
                if (address.isLoopbackAddress || address.isAnyLocalAddress || address.isMulticastAddress) continue
                servers.put(JSONObject().apply {
                    val ip = address.hostAddress?.substringBefore('%')
                    val scope = if (address is Inet6Address && address.isLinkLocalAddress)
                        address.scopeId.takeIf { it > 0 } ?: properties.interfaceName?.let { NetworkInterface.getByName(it)?.index }
                        else null
                    put("address", if (scope != null) "$ip%$scope" else ip)
                    if (properties.isPrivateDnsActive) {
                        put("transport", "tls")
                        put("port", 853)
                        if (privateName != null) put("server_name", privateName)
                        else put("opportunistic_tls", true)
                    }
                })
            }
            if (servers.length() == 0) continue
            dnsNetworks[token] = network
            dnsFingerprints[network] = dnsFingerprint(properties)
            links.put(JSONObject().apply {
                put("id", token); put("interface", token); put("name", properties.interfaceName ?: token)
                put("default", network == preferred?.first); put("servers", servers)
                // Search suffixes are not per-domain DNS routing rules.
                put("search_domains", JSONArray(properties.domains?.split(Regex("[,\\s]+"))?.filter { it.isNotBlank() } ?: emptyList<String>()))
            })
        }
        return JSONObject().put("links", links).put("routing_domains_available", false)
    }

    private fun pathFingerprint(properties: LinkProperties): String = listOf(
        properties.interfaceName, properties.linkAddresses.map { it.toString() }.sorted().joinToString(),
        properties.routes.map { it.toString() }.sorted().joinToString(), properties.mtu
    ).joinToString("|")

    private fun selectedUnderlay(): Network? {
        val available = connectivityManager.allNetworks.filter { network ->
            val caps = connectivityManager.getNetworkCapabilities(network)
            network !in lostNetworks && caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) == true &&
                caps.hasCapability(NET_CAPABILITY_INTERNET)
        }
        val chosen = connectivityManager.activeNetwork?.takeIf { it in available }
            ?: preferredDnsNetwork?.takeIf { it in available }
            ?: available.firstOrNull { connectivityManager.getNetworkCapabilities(it)?.hasCapability(NET_CAPABILITY_VALIDATED) == true }
            ?: available.firstOrNull()
        if (chosen != null) preferredDnsNetwork = chosen
        return chosen
    }

    fun underlayIdentity(): String? {
        val network = selectedUnderlay() ?: return null
        val properties = connectivityManager.getLinkProperties(network) ?: return null
        val fingerprint = pathFingerprint(properties)
        pathFingerprints[network] = fingerprint
        return "${network.networkHandle}|$fingerprint"
    }

    fun bindVpnSocket(fd: Int): Boolean = try {
        val network = selectedUnderlay()
        // A protected, initially unbound encrypted UDP socket can wait for
        // the first usable network; the listener will refresh it on recovery.
        if (network == null) true else {
            ParcelFileDescriptor.fromFd(fd).use { network.bindSocket(it.fileDescriptor) }
            true
        }
    } catch (_: Exception) { false }

    fun bindDnsSocket(fd: Int, token: String): Boolean {
        return try {
            val network = dnsNetworks[token] ?: return false
            ParcelFileDescriptor.fromFd(fd).use { network.bindSocket(it.fileDescriptor) }
            true
        } catch (_: Exception) { false }
    }

    private val handler: Handler by lazy(NONE) {
        Handler(context.mainLooper)
    }

    private val connectivityManager: ConnectivityManager by lazy {
        context.getSystemService<ConnectivityManager>()!!
    }

    private val networkRequest: NetworkRequest by lazy(NONE) {
        NetworkRequest.Builder()
            .addCapability(NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
    }

    private val networkCallback: NetworkCallback by lazy(NONE) {
        object : NetworkCallback() {
            override fun onAvailable(network: Network) {
                lostNetworks.remove(network)
                Log.v(TAG, "onAvailable: $network")
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                Log.v(TAG, "onCapabilitiesChanged: $network, $networkCapabilities")
                if (networkCapabilities.hasCapability(NET_CAPABILITY_VALIDATED)) preferredDnsNetwork = network
                checkNetworkState(network, networkCapabilities)
            }

            private fun checkNetworkState(network: Network, networkCapabilities: NetworkCapabilities) {
                if (state.update(network, networkCapabilities.hasCapability(NET_CAPABILITY_VALIDATED))) {
                    onNetworkChange()
                }
            }

            override fun onBlockedStatusChanged(network: Network, blocked: Boolean) {
                Log.v(TAG, "onBlockedStatusChanged: $network, $blocked")
            }

            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                val current = dnsFingerprint(linkProperties)
                val previous = dnsFingerprints.put(network, current)
                val path = pathFingerprint(linkProperties)
                val oldPath = pathFingerprints.put(network, path)
                if (network == preferredDnsNetwork &&
                    ((previous != null && current != previous) || (oldPath != null && oldPath != path))) onNetworkChange()
            }

            override fun onLost(network: Network) {
                Log.v(TAG, "onLost: $network")
                lostNetworks.add(network)
                state.lost(network)
                dnsNetworks.entries.removeAll { it.value == network }
                dnsFingerprints.remove(network)
                pathFingerprints.remove(network)
                if (preferredDnsNetwork == network) { preferredDnsNetwork = null; onNetworkChange() }
            }
        }
    }

    fun resolveEndpoint(host: String): List<java.net.InetAddress> {
        val networks = connectivityManager.allNetworks.mapNotNull { network ->
            if (network in lostNetworks) return@mapNotNull null
            val capabilities = connectivityManager.getNetworkCapabilities(network) ?: return@mapNotNull null
            if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) ||
                !capabilities.hasCapability(NET_CAPABILITY_INTERNET)) return@mapNotNull null
            network to capabilities.hasCapability(NET_CAPABILITY_VALIDATED)
        }.sortedByDescending { it.second }
        for ((network, _) in networks) {
            try {
                val addresses = network.getAllByName(host).toList()
                if (addresses.isNotEmpty()) return addresses
            } catch (_: java.net.UnknownHostException) {
                // A replacement network can become usable before its DNS does.
            }
        }
        throw java.net.UnknownHostException("VPN endpoint DNS is unavailable on the underlying networks")
    }

    suspend fun bindNetworkListener() {
        if (isListenerBound) return
        Log.d(TAG, "Bind network listener")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            connectivityManager.registerBestMatchingNetworkCallback(networkRequest, networkCallback, handler)
        } else {
            val numberAttempts = 300
            var attemptCount = 0
            while(true) {
                try {
                    connectivityManager.requestNetwork(networkRequest, networkCallback, handler)
                    break
                } catch (e: SecurityException) {
                    Log.e(TAG, "Failed to bind network listener: $e")
                    // Android 11 bug: https://issuetracker.google.com/issues/175055271
                    if (e.message?.startsWith("Package android does not belong to") == true) {
                        if (++attemptCount > numberAttempts) {
                            throw e
                        }
                        delay(1000)
                        continue
                    } else {
                        throw e
                    }
                }
            }
        }
        isListenerBound = true
    }

    fun unbindNetworkListener() {
        if (!isListenerBound) return
        Log.d(TAG, "Unbind network listener")
        connectivityManager.unregisterNetworkCallback(networkCallback)
        isListenerBound = false
        state.reset()
        lostNetworks.clear()
        dnsNetworks.clear()
        dnsFingerprints.clear()
        pathFingerprints.clear()
        preferredDnsNetwork = null
    }
}
