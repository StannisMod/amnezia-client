package org.amnezia.vpn.protocol

import android.net.ProxyInfo
import android.os.Build
import androidx.annotation.RequiresApi
import java.net.InetAddress
import java.net.Inet4Address
import org.amnezia.vpn.util.net.InetNetwork
import org.amnezia.vpn.util.net.IpRange
import org.amnezia.vpn.util.net.IpRangeSet

open class ProtocolConfig protected constructor(
    val addresses: Set<InetNetwork>,
    val dnsServers: Set<InetAddress>,
    val searchDomain: String?,
    val routes: Set<Route>,
    val includedAddresses: Set<InetNetwork>,
    val excludedAddresses: Set<InetNetwork>,
    val includedApplications: Set<String>,
    val excludedApplications: Set<String>,
    val httpProxy: ProxyInfo?,
    val allowAllAF: Boolean,
    val blockingMode: Boolean,
    val mtu: Int,
    val searchDomains: List<String> = listOfNotNull(searchDomain)
) {

    protected constructor(builder: Builder) : this(
        builder.addresses,
        builder.publishedDnsServers,
        builder.searchDomain,
        builder.routes,
        builder.includedAddresses,
        builder.excludedAddresses,
        builder.includedApplications,
        builder.excludedApplications,
        builder.httpProxy,
        builder.allowAllAF,
        builder.blockingMode,
        builder.mtu,
        builder.publishedSearchDomains.toList()
    )

    open class Builder(blockingMode: Boolean) {
        internal val addresses: MutableSet<InetNetwork> = hashSetOf()
        internal val dnsServers: MutableSet<InetAddress> = hashSetOf()
        private var managedDnsServers: Set<InetAddress>? = null
        internal val publishedDnsServers: Set<InetAddress>
            get() = managedDnsServers ?: dnsServers
        internal val routes: MutableSet<Route> = mutableSetOf()
        internal val includedAddresses: MutableSet<InetNetwork> = hashSetOf()
        internal val excludedAddresses: MutableSet<InetNetwork> = hashSetOf()
        internal val includedApplications: MutableSet<String> = hashSetOf()
        internal val excludedApplications: MutableSet<String> = hashSetOf()

        internal var searchDomain: String? = null
            private set
        private var managedSearchDomains: List<String>? = null
        internal val publishedSearchDomains: List<String>
            get() = managedSearchDomains ?: listOfNotNull(searchDomain)

        internal var httpProxy: ProxyInfo? = null
            private set

        internal var allowAllAF: Boolean = false
            private set

        internal var blockingMode: Boolean = blockingMode
            private set

        internal var allowSplitTunneling: Boolean = true
            private set

        private var fullIpv6CaptureRequired: Boolean = false

        fun requireFullIpv6Capture() = apply { fullIpv6CaptureRequired = true }

        open var mtu: Int = 0
            protected set

        fun addAddress(addr: InetNetwork) = apply { this.addresses += addr }
        fun addAddresses(addresses: Collection<InetNetwork>) = apply { this.addresses += addresses }
        fun clearAddresses() = apply { this.addresses.clear() }

        fun addDnsServer(dnsServer: InetAddress) = apply { this.dnsServers += dnsServer }
        fun addDnsServers(dnsServers: Collection<InetAddress>) = apply { this.dnsServers += dnsServers }

        /** Call only after a native DNS owner has prepared these endpoints. */
        fun setManagedDnsServers(servers: Collection<InetAddress>) = apply {
            if (servers.isEmpty() || servers.size > 16 || servers.toSet().size != servers.size ||
                servers.any { it !is Inet4Address || it.isAnyLocalAddress ||
                    it.isLoopbackAddress || it.isMulticastAddress })
                throw BadConfigException("Invalid managed native DNS capture endpoints")
            managedDnsServers = servers.toCollection(linkedSetOf())
        }

        fun setSearchDomain(domain: String) = apply {
            this.searchDomain = domain
            managedSearchDomains = null
        }
        fun setSearchDomains(domains: Collection<String>) = apply {
            managedSearchDomains = domains.toList()
            searchDomain = domains.lastOrNull()
        }

        fun addRoute(route: InetNetwork) = apply { this.routes += Route(route, true) }
        fun addRoutes(routes: Collection<InetNetwork>) = apply { this.routes += routes.map { Route(it, true) } }

        fun excludeRoute(route: InetNetwork) = apply { this.routes += Route(route, false) }
        fun excludeRoutes(routes: Collection<InetNetwork>) = apply { this.routes += routes.map { Route(it, false) } }

        fun removeRoute(route: InetNetwork) = apply { this.routes.removeIf { it.inetNetwork == route } }
        fun clearRoutes() = apply { this.routes.clear() }

        fun prependRoutes(block: Builder.() -> Unit) = apply {
            val savedRoutes = mutableListOf<Route>().apply { addAll(routes) }
            routes.clear()
            block()
            routes.addAll(savedRoutes)
        }

        fun includeAddress(addr: InetNetwork) = apply { this.includedAddresses += addr }
        fun includeAddresses(addresses: Collection<InetNetwork>) = apply { this.includedAddresses += addresses }

        fun excludeAddress(addr: InetNetwork) = apply { this.excludedAddresses += addr }
        fun excludeAddresses(addresses: Collection<InetNetwork>) = apply { this.excludedAddresses += addresses }

        fun includeApplication(application: String) = apply { this.includedApplications += application }
        fun includeApplications(applications: Collection<String>) = apply { this.includedApplications += applications }

        fun excludeApplication(application: String) = apply { this.excludedApplications += application }
        fun excludeApplications(applications: Collection<String>) = apply { this.excludedApplications += applications }

        @RequiresApi(Build.VERSION_CODES.Q)
        fun setHttpProxy(httpProxy: ProxyInfo) = apply { this.httpProxy = httpProxy }

        fun setAllowAllAF(allowAllAF: Boolean) = apply { this.allowAllAF = allowAllAF }

        fun setBlockingMode(blockingMode: Boolean) = apply { this.blockingMode = blockingMode }

        fun disableSplitTunneling() = apply { this.allowSplitTunneling = false }

        fun setMtu(mtu: Int) = apply { this.mtu = mtu }

        private fun processSplitTunneling() {
            if (includedAddresses.isNotEmpty() && excludedAddresses.isNotEmpty()) {
                throw BadConfigException("Config contains addresses for inclusive and exclusive split tunneling at the same time")
            }

            if (includedAddresses.isNotEmpty()) {
                // remove default routes, if any
                removeRoute(InetNetwork("0.0.0.0", 0))
                removeRoute(InetNetwork("::", 0))
                removeRoute(InetNetwork("2000::", 3))
                removeRoute(InetNetwork("::", 1))
                removeRoute(InetNetwork("8000::", 1))
                prependRoutes {
                    addRoutes(includedAddresses)
                }
            } else if (excludedAddresses.isNotEmpty()) {
                prependRoutes {
                    addRoute(InetNetwork("0.0.0.0", 0))
                    addRoute(InetNetwork("::", 0))
                    excludeRoutes(excludedAddresses)
                }
            }
        }

        private fun processRoutes() {
            // for older versions of Android, build a list of subnets without excluded routes
            // and add them to routes
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU && routes.any { !it.include }) {
                val ipRangeSet = IpRangeSet()
                routes.forEach {
                    if (it.include) ipRangeSet.add(IpRange(it.inetNetwork))
                    else ipRangeSet.remove(IpRange(it.inetNetwork))
                }
                ipRangeSet.remove(IpRange("127.0.0.0", 8))
                // Loopback belongs to the kernel's local table. Subtracting
                // ::1 needlessly fragments an IPv6 default into many routes.
                routes.clear()
                ipRangeSet.subnets().forEach(::addRoute)
            }
            // filter ipv4 and ipv6 loopback addresses
            val ipv6Loopback = InetNetwork("::1", 128)
            routes.removeIf {
                it.include &&
                    if (it.inetNetwork.isIpv4) it.inetNetwork.address.address[0] == 127.toByte()
                    else it.inetNetwork == ipv6Loopback
            }
        }

        private fun validate() {
            val errorMessage = StringBuilder()

            with(errorMessage) {
                if (addresses.isEmpty()) appendLine("VPN interface network address not specified.")
                if (routes.isEmpty()) appendLine("VPN interface route not specified.")
                if (mtu == 0) appendLine("MTU not set.")
            }

            if (errorMessage.isNotEmpty()) throw BadConfigException(errorMessage.toString())
        }

        protected fun configBuild() {
            processSplitTunneling()
            // DNS-only capture must survive include-only routing and explicit
            // exclusions of the reserved endpoints. Never replace other native
            // routes or infer upstream scope from these newly added routes.
            managedDnsServers?.forEach { endpoint ->
                val route = InetNetwork(endpoint)
                removeRoute(route)
                addRoute(route)
            }
            if (fullIpv6CaptureRequired) {
                // OFF is an enforcement policy, not a destination include
                // rule. Install it after split processing removes defaults.
                routes.removeIf { it.inetNetwork.isIpv6 }
                addRoute(InetNetwork("::", 1))
                addRoute(InetNetwork("8000::", 1))
            }
            processRoutes()
            validate()
        }

        open fun build(): ProtocolConfig = configBuild().run { ProtocolConfig(this@Builder) }
    }

    companion object {
        inline fun build(blockingMode: Boolean, block: Builder.() -> Unit): ProtocolConfig =
            Builder(blockingMode).apply(block).build()
    }
}

data class Route(val inetNetwork: InetNetwork, val include: Boolean)
