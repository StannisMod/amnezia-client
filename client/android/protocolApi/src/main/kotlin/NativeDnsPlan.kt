package org.amnezia.vpn.protocol

import java.net.InetAddress
import org.amnezia.vpn.util.net.InetNetwork

/** A resolver occurrence, not a deduplicated resolver pool. */
data class NativeDnsBinding(
    val endpoint: String,
    val upstream: String,
    val scope: NativeDnsScope,
    val transport: NativeDnsTransport = NativeDnsTransport.PLAIN,
    val serverName: String = "",
    val httpsUrl: String = ""
)

enum class NativeDnsScope { TUNNEL, DIRECT, IPV6_UNAVAILABLE }
enum class NativeDnsTransport(val wire: String) { PLAIN("plain"), TLS("tls"), HTTPS("https") }
data class NativeDnsServer(
    val address: String,
    val port: Int = 53,
    val transport: NativeDnsTransport = NativeDnsTransport.PLAIN,
    val serverName: String = "",
    val httpsUrl: String = ""
)

/**
 * Compute scope from the ORIGINAL final native routes, before adding managed
 * DNS capture. In particular, a DNS-only alias route cannot turn an originally
 * bypassed resolver into a tunnel resolver.
 *
 * This class does not select an underlay or open sockets. DIRECT bindings need
 * a separately pinned original network; missing scope must fail closed.
 */
class NativeDnsPlan private constructor(val bindings: List<NativeDnsBinding>) {
    companion object {
        fun prepare(
            selectedServers: List<String>,
            originalRoutes: Collection<Route>,
            originalAddresses: Collection<InetNetwork> = emptyList(),
            selectedPorts: List<Int> = List(selectedServers.size) { 53 }
        ): NativeDnsPlan {
            if (selectedServers.isEmpty() || selectedServers.size > 16)
                throw BadConfigException("Native DNS requires explicit selected resolvers")
            if (selectedPorts.size != selectedServers.size || selectedPorts.any { it !in 1..65535 })
                throw BadConfigException("Native DNS requires exact valid selected resolver ports")
            return prepareSelected(selectedServers.mapIndexed { i, address ->
                NativeDnsServer(address, selectedPorts[i])
            }, originalRoutes, originalAddresses)
        }

        fun prepareSelected(
            selectedServers: List<NativeDnsServer>,
            originalRoutes: Collection<Route>,
            originalAddresses: Collection<InetNetwork> = emptyList()
        ): NativeDnsPlan {
            if (selectedServers.isEmpty() || selectedServers.size > 16 ||
                selectedServers.any { it.port !in 1..65535 })
                throw BadConfigException("Native DNS requires explicit valid selected resolvers")
            if (selectedServers.any {
                    (it.transport == NativeDnsTransport.PLAIN && (it.serverName.isNotEmpty() || it.httpsUrl.isNotEmpty())) ||
                    (it.transport == NativeDnsTransport.TLS && it.httpsUrl.isNotEmpty()) ||
                    (it.transport == NativeDnsTransport.HTTPS && it.httpsUrl.isEmpty())
                }) throw BadConfigException("Unrepresentable native DNS security metadata")
            val servers = selectedServers.map { numericAddress(it.address) }
            val endpoints = servers.indices.map { "198.19.255.${it + 1}" }
            val occupied = servers + originalAddresses.map { it.address }
            if (endpoints.any { endpoint -> occupied.any { it == numericAddress(endpoint) } })
                throw BadConfigException("Native DNS capture address collides with original configuration")
            // Snapshot the route decision now; never re-evaluate against alias
            // capture or a later/default network during forwarding.
            val routes = originalRoutes.toList()
            val bindings = servers.mapIndexed { index, address ->
                val selected = selectedServers[index]
                val ipv6 = selected.address.contains(':')
                val scope = if (ipv6) NativeDnsScope.IPV6_UNAVAILABLE else scope(address, routes)
                val port = selected.port
                val upstream = if (ipv6) "[${address.hostAddress}]:$port" else "${address.hostAddress}:$port"
                NativeDnsBinding("${endpoints[index]}:53", upstream, scope,
                    selected.transport, selected.serverName, selected.httpsUrl)
            }
            return NativeDnsPlan(bindings)
        }

        private fun scope(address: InetAddress, routes: List<Route>): NativeDnsScope {
            val matches = routes.filter { contains(it.inetNetwork, address) }
            val longest = matches.maxOfOrNull { it.inetNetwork.mask }
                ?: return NativeDnsScope.DIRECT
            val decisions = matches.filter { it.inetNetwork.mask == longest }.map { it.include }.distinct()
            if (decisions.size != 1)
                throw BadConfigException("Conflicting native DNS routes")
            return if (decisions.single()) NativeDnsScope.TUNNEL else NativeDnsScope.DIRECT
        }

        private fun contains(network: InetNetwork, address: InetAddress): Boolean {
            val prefix = network.address.address
            val target = address.address
            if (prefix.size != target.size) return false
            if (network.mask !in 0..prefix.size * 8)
                throw BadConfigException("Invalid native DNS route prefix")
            for (bit in 0 until network.mask) {
                val mask = 1 shl (7 - bit % 8)
                if ((prefix[bit / 8].toInt() and mask) != (target[bit / 8].toInt() and mask))
                    return false
            }
            return true
        }

        private fun numericAddress(text: String): InetAddress {
            // InetAddress.getByName is allowed ONLY after proving numeric
            // syntax. No hostname lookup/bootstrap/default resolver is allowed.
            val ipv4 = text.split('.').let { parts ->
                parts.size == 4 && parts.all {
                    it.isNotEmpty() && it.all(Char::isDigit) &&
                        it.toIntOrNull()?.let { value -> value in 0..255 && value.toString() == it } == true
                }
            }
            val ipv6 = ':' in text && text.all { it in "0123456789abcdefABCDEF:." }
            if (!ipv4 && !ipv6)
                throw BadConfigException("Native DNS resolver must be an unscoped numeric address")
            val address = try { InetAddress.getByName(text) } catch (_: Exception) {
                throw BadConfigException("Invalid native DNS resolver address")
            }
            // Java canonicalizes mapped IPv6 to Inet4Address; allowing that
            // conversion would silently authorize transport under explicit OFF.
            if (ipv6 && address.address.size != 16)
                throw BadConfigException("Mapped IPv6 native DNS is not representable")
            if (address.isAnyLocalAddress || address.isMulticastAddress || address.isLoopbackAddress)
                throw BadConfigException("Invalid native DNS resolver endpoint")
            return address
        }
    }
}
