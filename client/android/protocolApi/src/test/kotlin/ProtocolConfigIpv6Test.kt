package org.amnezia.vpn.protocol

import org.amnezia.vpn.util.net.InetNetwork
import java.math.BigInteger
import java.net.InetAddress
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ProtocolConfigIpv6Test {
    private fun config(block: ProtocolConfig.Builder.() -> Unit): ProtocolConfig = ProtocolConfig.build(false) {
        addAddress(InetNetwork("10.77.0.2", 32))
        addAddress(InetNetwork("fd77::2", 128))
        setMtu(1280)
        block()
    }

    private fun ProtocolConfig.captures(address: String): Boolean {
        val ip = InetAddress.getByName(address).address
        return routes.any {
            val prefix = it.inetNetwork.address.address
            val shift = ip.size * 8 - it.inetNetwork.mask
            it.include && prefix.size == ip.size &&
                BigInteger(1, ip).shiftRight(shift) == BigInteger(1, prefix).shiftRight(shift)
        }
    }

    @Test fun fullTunnelIncludesGlobalUniqueLocalAndNat64() {
        val result = config { addRoute(InetNetwork("::", 0)) }
        for (address in listOf("2001:db8::1", "fd88::1", "64:ff9b::c000:201"))
            assertTrue(address, result.captures(address))
    }

    @Test fun excludingIpv4EndpointKeepsAllSelectedIpv6() {
        // The local JVM Android stub uses the pre-API33 exclusion compiler.
        val result = config {
            addRoute(InetNetwork("::", 0))
            excludeAddress(InetNetwork("198.51.100.1", 32))
        }
        for (address in listOf("2001:db8::1", "fd88::1", "64:ff9b::c000:201"))
            assertTrue(address, result.captures(address))
        assertFalse(result.captures("198.51.100.1"))
    }

    @Test fun includingIpv4OnlyDoesNotCaptureIpv6() {
        val result = config {
            addRoute(InetNetwork("::", 0))
            includeAddress(InetNetwork("192.0.2.0", 24))
        }
        assertTrue(result.captures("192.0.2.1"))
        for (address in listOf("2001:db8::1", "fd88::1", "64:ff9b::c000:201"))
            assertFalse(address, result.captures(address))
    }
}
