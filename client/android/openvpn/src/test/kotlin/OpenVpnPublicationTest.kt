package org.amnezia.vpn.protocol.openvpn

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OpenVpnPublicationTest {
    private val addresses = setOf("10.76.0.2/24")
    private val routes = setOf("0.0.0.0/0", "fd00::/8")
    private fun snapshot(name: String, published: Set<String> = routes) =
        TunPublicationSnapshot(name, addresses, published)

    @Test fun getterWithoutPublicationCannotReleaseTheTunnel() {
        assertFalse(TunPublicationState(emptyMap()).ready("tun0", addresses, routes))
    }

    @Test fun ipv4OnlyPublicationDoesNotReleasePendingIpv6Routes() {
        val state = TunPublicationState(emptyMap())
        state.publish(100, snapshot("tun0", setOf("0.0.0.0/0")))
        assertFalse(state.ready("tun0", addresses, routes))
        state.publish(100, snapshot("tun0"))
        assertTrue(state.ready("tun0", addresses, routes))
    }

    @Test fun staleAgentCannotPublishAReusedInterfaceName() {
        val state = TunPublicationState(mapOf(100L to "tun0"))
        state.publish(100, snapshot("tun0"))
        assertFalse(state.ready("tun0", addresses, routes))
        state.publish(101, snapshot("tun0"))
        assertTrue(state.ready("tun0", addresses, routes))
    }

    @Test fun reusedAgentCanPublishTheNewFinalInterface() {
        val state = TunPublicationState(mapOf(100L to "tun0"))
        state.publish(100, snapshot("tun0"))
        assertFalse(state.ready("tun1", addresses, routes))
        state.publish(100, snapshot("tun1"))
        assertTrue(state.ready("tun1", addresses, routes))
    }

    @Test fun provisionalInterfaceAndLostNetworkCannotReleaseTheTunnel() {
        val state = TunPublicationState(emptyMap())
        state.publish(100, snapshot("tun-guard"))
        assertFalse(state.ready("tun0", addresses, routes))
        state.publish(101, snapshot("tun0"))
        state.lost(101)
        assertFalse(state.ready("tun0", addresses, routes))
    }

    @Test fun cancellationCannotBeOverriddenByALatePublication() {
        val state = TunPublicationState(emptyMap())
        state.cancel()
        state.publish(100, snapshot("tun0"))
        assertTrue(state.cancelled)
        assertFalse(state.ready("tun0", addresses, routes))
    }
    @Test fun ambiguousNativeNetworkCannotAuthorizeDnsSocketBinding() {
        val state = TunPublicationState(emptyMap())
        state.publish(100, snapshot("tun0"))
        state.publish(101, snapshot("tun0"))
        assertFalse(state.ready("tun0", addresses, routes))
        state.lost(100)
        assertTrue(state.ready("tun0", addresses, routes))
    }
    @Test fun dnsPublicationMustMatchExactOrderedGenerationAliases() {
        val state = TunPublicationState(emptyMap())
        val dns = listOf("198.19.255.1", "198.19.255.2")
        state.publish(100, snapshot("tun0"))
        assertFalse(state.current(100, "tun0", addresses, routes, dns))
        state.publish(100, TunPublicationSnapshot("tun0", addresses, routes, dns.reversed()))
        assertFalse(state.current(100, "tun0", addresses, routes, dns))
        state.publish(100, TunPublicationSnapshot("tun0", addresses, routes, dns))
        assertTrue(state.current(100, "tun0", addresses, routes, dns))
        state.publish(100, TunPublicationSnapshot("tun0", addresses, routes, dns.take(1)))
        assertFalse(state.current(100, "tun0", addresses, routes, dns))
    }
    @Test fun lostNetworkHandleCannotReviveFromLateCallbacks() {
        val state = TunPublicationState(emptyMap())
        state.publish(100, snapshot("tun0"))
        assertTrue(state.current(100, "tun0", addresses, routes))
        state.lost(100)
        state.publish(100, snapshot("tun0"))
        assertFalse(state.current(100, "tun0", addresses, routes))
        state.publish(101, snapshot("tun0"))
        assertTrue(state.current(101, "tun0", addresses, routes))
    }
}
