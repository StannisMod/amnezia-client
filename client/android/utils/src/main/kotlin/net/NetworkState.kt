package org.amnezia.vpn.util.net

import android.content.Context
import android.net.ConnectivityManager
import android.net.ConnectivityManager.NetworkCallback
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET
import android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED
import android.net.NetworkRequest
import android.os.Build
import android.os.Handler
import androidx.core.content.getSystemService
import kotlin.LazyThreadSafetyMode.NONE
import kotlinx.coroutines.delay
import org.amnezia.vpn.util.Log

private const val TAG = "NetworkState"

class NetworkState(
    private val context: Context,
    private val onNetworkChange: () -> Unit
) {
    private val state = ValidatedNetworkState<Network>()
    private var isListenerBound = false

    private val handler: Handler by lazy(NONE) {
        Handler(context.mainLooper)
    }

    private val connectivityManager: ConnectivityManager by lazy {
        context.getSystemService<ConnectivityManager>()!!
    }

    private val networkRequest: NetworkRequest by lazy(NONE) {
        NetworkRequest.Builder()
            .addCapability(NET_CAPABILITY_INTERNET)
            .build()
    }

    private val networkCallback: NetworkCallback by lazy(NONE) {
        object : NetworkCallback() {
            override fun onAvailable(network: Network) {
                Log.v(TAG, "onAvailable: $network")
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                Log.v(TAG, "onCapabilitiesChanged: $network, $networkCapabilities")
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

            override fun onLost(network: Network) {
                Log.v(TAG, "onLost: $network")
                state.lost(network)
            }
        }
    }

    fun resolveEndpoint(host: String): List<java.net.InetAddress> {
        val networks = connectivityManager.allNetworks.mapNotNull { network ->
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
    }
}
