package org.amnezia.awg

import androidx.annotation.Keep
import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import java.net.InetSocketAddress
import java.net.NetworkInterface
import org.json.JSONArray
import org.json.JSONObject

// Implemented inside the existing libwg-go.so. Never load a second Go library.
@Keep
object RoutingBackend {
    external fun validate(config: ByteArray): Boolean
    external fun buildInfo(): ByteArray

    // Native code consumes tunFd on success and on every failed-start path.
    external fun start(tunFd: Int, config: ByteArray, host: RoutingHost): Long
    // Consumes tunFd on success and failure; caller must detach exactly once.
    external fun replaceCapture(handle: Long, tunFd: Int): Boolean
    external fun stop(handle: Long)
    external fun stats(handle: Long): LongArray?
    external fun diagnostics(handle: Long): ByteArray?
    external fun refresh(handle: Long, endpoint: String?, reopen: Boolean): Boolean
    external fun reloadNetworkDns(handle: Long, snapshot: ByteArray): Boolean
    external fun updateAndroidApplications(handle: Long, policy: ByteArray): Boolean
    external fun suspendNetworkDns(handle: Long)
}

@Keep
class RoutingHost(private val protect: (Int) -> Boolean, private val bindDns: ((Int, String) -> Boolean)? = null, context: Context? = null) {
    private val connectivity = context?.applicationContext?.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager

    @Keep
    fun connectionOwnerUid(protocol: Int, source: String, sourcePort: Int, destination: String, destinationPort: Int): Int {
        if (Build.VERSION.SDK_INT < 29 || connectivity == null) return -1
        if ((protocol != 6 && protocol != 17) || sourcePort !in 1..65535 || destinationPort !in 1..65535) return -1
        return try {
            connectivity.getConnectionOwnerUid(protocol, InetSocketAddress(source, sourcePort), InetSocketAddress(destination, destinationPort))
        } catch (_: SecurityException) { -1 }
          catch (_: IllegalArgumentException) { -1 }
    }
    @Keep
    fun protectSocket(fd: Int): Boolean = protect(fd)
    @Keep
    fun protectSocketOnInterface(fd: Int, name: String): Boolean = protect(fd) && (bindDns?.invoke(fd, name) ?: false)

    @Keep
    fun interfacesJson(): ByteArray {
        val interfaces = JSONArray()
        val nativeInterfaces = NetworkInterface.getNetworkInterfaces()
        while (nativeInterfaces != null && nativeInterfaces.hasMoreElements()) {
            val iface = nativeInterfaces.nextElement()
            val addresses = JSONArray()
            for (address in iface.interfaceAddresses) {
                val ip = address.address.hostAddress?.substringBefore('%') ?: continue
                addresses.put("$ip/${address.networkPrefixLength}")
            }
            // Flags use Go net.Flags, not Linux IFF_* numeric values.
            var flags = 0
            if (iface.isUp) flags = flags or 1 or 16
            if (iface.isLoopback) flags = flags or 4
            if (iface.supportsMulticast()) flags = flags or 8
            interfaces.put(JSONObject().apply {
                put("index", iface.index)
                put("name", iface.name)
                put("mtu", iface.mtu)
                put("flags", flags)
                put("addresses", addresses)
            })
        }
        return interfaces.toString().toByteArray(Charsets.UTF_8)
    }
}
