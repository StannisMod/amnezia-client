package org.amnezia.awg

import androidx.annotation.Keep
import java.net.NetworkInterface
import org.json.JSONArray
import org.json.JSONObject

// Implemented inside the existing libwg-go.so. Never load a second Go library.
@Keep
object RoutingBackend {
    // Native code consumes tunFd on success and on every failed-start path.
    external fun start(tunFd: Int, config: ByteArray, host: RoutingHost): Long
    external fun stop(handle: Long)
    external fun stats(handle: Long): LongArray?
}

@Keep
class RoutingHost(private val protect: (Int) -> Boolean) {
    @Keep
    fun protectSocket(fd: Int): Boolean = protect(fd)

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
