package org.amnezia.vpn.protocol.openvpn

import org.amnezia.vpn.protocol.BadConfigException
import org.junit.Assert.*
import org.junit.Test

class OpenVpnEndpointTest {
    @Test fun numericEndpointDoesNotNeedAnyBootstrapLookup() {
        assertEquals("192.0.2.1", openVpnIpv4Endpoint("192.0.2.1").hostAddress)
        assertEquals("127.0.0.1", openVpnIpv4Endpoint("127.0.0.1").hostAddress)
    }
    @Test fun hostnamesAndEveryIpv6RepresentationFailBeforeResolution() {
        for (text in listOf("selected.invalid", "fd77::1", "::ffff:192.0.2.1", "192.00.2.1", "192.0.2.256")) {
            try { openVpnIpv4Endpoint(text); fail("admitted $text") }
            catch (_: BadConfigException) {}
        }
    }
}
