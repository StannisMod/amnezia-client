package org.amnezia.vpn.protocol.openvpn

import java.net.InetAddress
import org.amnezia.vpn.protocol.NativeDnsPlan
import org.amnezia.vpn.protocol.NativeDnsPublication
import org.amnezia.vpn.protocol.Route
import org.amnezia.vpn.util.net.InetNetwork
import org.junit.Assert.*
import org.junit.Test

class OpenVpnDnsNetworkTest {
    @Test fun tunnelDnsCannotFallbackToProtectedOrVpnBoundOsSockets() {
        var osBindings = 0
        val plan = NativeDnsPlan.prepare(listOf("10.8.0.1"),
            listOf(Route(InetNetwork(InetAddress.getByName("0.0.0.0"), 0), true)))
        val publication = NativeDnsPublication.prepare(plan, false, false, null, null,
            { osBindings++; true }, { _, _ -> osBindings++; true })
        val network = OpenVpnDnsNetwork(publication, { false }, { true })
        assertFalse(network.bind(plan.bindings.single(), 42))
        assertFalse(network.permitTunnel()) // No current capture publication yet.
        assertEquals(0, osBindings)
    }
}
