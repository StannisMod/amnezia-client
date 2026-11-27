package org.amnezia.vpn.util.net

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class IpRangeSetTest {
    @Test fun excludingIpv4EndpointKeepsIpv6Capture() {
        val ranges = IpRangeSet()
        for (subnet in listOf("0.0.0.0/0", "::/1", "8000::/1")) ranges.add(IpRange(InetNetwork.parse(subnet)))
        for (subnet in listOf("10.0.2.2/32", "127.0.0.0/8", "::1/128")) ranges.remove(IpRange(InetNetwork.parse(subnet)))
        val result = ranges.subnets().map(::IpRange)
        fun covered(address: String): Boolean {
            val ip = IpAddress(address)
            return result.any { it.start <= ip && ip <= it.end }
        }
        for (address in listOf("198.51.100.2", "2001:db8:42::2", "fd42:4242::2", "64:ff9b::c000:201")) assertTrue(address, covered(address))
        for (address in listOf("10.0.2.2", "127.0.0.1", "::1")) assertFalse(address, covered(address))
    }
}
