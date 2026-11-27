package org.amnezia.vpn.protocol

import org.amnezia.vpn.util.net.InetNetwork
import org.junit.Assert.*
import org.junit.Test
import java.net.InetAddress

class NativeDnsPlanTest {
    @Test fun encryptedIdentityAndTemplateStayWithExactResolverOccurrence() {
        val template = "https://selected.example:8443/original-path{?dns}"
        val plan = NativeDnsPlan.prepareSelected(listOf(
            NativeDnsServer("192.0.2.53", 853, NativeDnsTransport.TLS, "selected.example"),
            NativeDnsServer("192.0.2.53", 8443, NativeDnsTransport.HTTPS, "selected.example", template),
            NativeDnsServer("fd77::53", 853, NativeDnsTransport.TLS, "ipv6.example")
        ), listOf(route("0.0.0.0/0")))
        assertEquals(listOf(NativeDnsTransport.TLS, NativeDnsTransport.HTTPS, NativeDnsTransport.TLS),
            plan.bindings.map { it.transport })
        assertEquals(listOf("selected.example", "selected.example", "ipv6.example"), plan.bindings.map { it.serverName })
        assertEquals(template, plan.bindings[1].httpsUrl)
        assertEquals(NativeDnsScope.IPV6_UNAVAILABLE, plan.bindings[2].scope)
        val publication = NativeDnsPublication.prepare(plan, false, false, null, null, { false }, null)
        val selected = org.json.JSONObject(publication.raw).getJSONArray("bindings")
        assertEquals("tls", selected.getJSONObject(0).getString("transport"))
        assertEquals(template, selected.getJSONObject(1).getString("https_url"))
        assertEquals("unavailable", selected.getJSONObject(2).getString("scope"))
    }
    @Test fun contradictorySecurityMetadataCannotBecomePlaintext() {
        for (server in listOf(
            NativeDnsServer("192.0.2.53", serverName = "selected.example"),
            NativeDnsServer("192.0.2.53", transport = NativeDnsTransport.HTTPS),
            NativeDnsServer("192.0.2.53", transport = NativeDnsTransport.TLS, httpsUrl = "https://selected.example/dns-query")
        )) {
            try { NativeDnsPlan.prepareSelected(listOf(server), emptyList()); fail("Erased $server") }
            catch (_: BadConfigException) {}
        }
    }
    @Test fun selectedPortsRetainOccurrenceOrderAndUnavailableIpv6() {
        val plan = NativeDnsPlan.prepare(
            listOf("192.0.2.53", "192.0.2.53", "fd77::53"), listOf(route("0.0.0.0/0")),
            selectedPorts = listOf(5353, 5300, 853))
        assertEquals(listOf("192.0.2.53:5353", "192.0.2.53:5300"), plan.bindings.take(2).map { it.upstream })
        assertTrue(plan.bindings[2].upstream.endsWith("]:853"))
        assertEquals(NativeDnsScope.IPV6_UNAVAILABLE, plan.bindings[2].scope)
        assertEquals(3, plan.bindings.map { it.endpoint }.distinct().size)
    }
    @Test fun invalidOrMisalignedPortMetadataCannotBecomeDefault53() {
        for (ports in listOf(emptyList(), listOf(0), listOf(-1), listOf(65536), listOf(53, 5353))) {
            try {
                NativeDnsPlan.prepare(listOf("192.0.2.53"), emptyList(), selectedPorts = ports)
                fail("Admitted invalid port metadata $ports")
            } catch (_: BadConfigException) {}
        }
    }
    private fun route(network: String, include: Boolean = true) =
        Route(InetNetwork.parse(network), include)

    @Test fun fullTunnelRetainsEveryResolverOccurrence() {
        val plan = NativeDnsPlan.prepare(listOf("192.0.2.53", "192.0.2.53"),
            listOf(route("0.0.0.0/0")))
        assertEquals(listOf("198.19.255.1:53", "198.19.255.2:53"), plan.bindings.map { it.endpoint })
        assertEquals(listOf("192.0.2.53:53", "192.0.2.53:53"), plan.bindings.map { it.upstream })
        assertTrue(plan.bindings.all { it.scope == NativeDnsScope.TUNNEL })
    }

    @Test fun longestPrefixRetainsExcludedDnsAndIncludedException() {
        val routes = listOf(route("0.0.0.0/0"), route("192.0.2.0/24", false),
            route("192.0.2.54/32"))
        val plan = NativeDnsPlan.prepare(listOf("192.0.2.53", "192.0.2.54"), routes)
        assertEquals(listOf(NativeDnsScope.DIRECT, NativeDnsScope.TUNNEL), plan.bindings.map { it.scope })
        assertEquals(3, routes.size)
    }

    @Test fun includeOnlyDoesNotMigrateDnsToTunnel() {
        val plan = NativeDnsPlan.prepare(listOf("192.0.2.53"), listOf(route("203.0.113.0/24")))
        assertEquals(NativeDnsScope.DIRECT, plan.bindings.single().scope)
    }

    @Test fun ipv6OnlyRemainsRepresentedButUnavailable() {
        val plan = NativeDnsPlan.prepare(listOf("fd77::53", "192.0.2.53"),
            listOf(route("0.0.0.0/0"), route("::/1"), route("8000::/1")))
        assertEquals(NativeDnsScope.IPV6_UNAVAILABLE, plan.bindings[0].scope)
        assertTrue(plan.bindings[0].upstream.startsWith("["))
        assertEquals(NativeDnsScope.TUNNEL, plan.bindings[1].scope)
    }

    @Test fun malformedNumericInputNeverUsesAResolver() {
        for (server in listOf("resolver.test", "127.0.0.1", "0.0.0.0", "224.0.0.1",
            "192.000.2.53", "::", "::1", "ff02::1", "fe80::53%3", "::ffff:192.0.2.53")) {
            try {
                NativeDnsPlan.prepare(listOf(server), listOf(route("0.0.0.0/0")))
                fail("Accepted $server")
            } catch (_: BadConfigException) { }
        }
    }

    @Test fun collisionAndAmbiguousScopeAreRefused() {
        for (servers in listOf(emptyList(), listOf("198.19.255.1"), List(17) { "192.0.2.53" })) {
            try {
                NativeDnsPlan.prepare(servers, listOf(route("0.0.0.0/0")))
                fail("Accepted invalid resolver inventory")
            } catch (_: BadConfigException) { }
        }
        try {
            NativeDnsPlan.prepare(listOf("192.0.2.53"),
                listOf(route("192.0.2.0/24"), route("192.0.2.0/24", false)))
            fail("Accepted conflicting route scope")
        } catch (_: BadConfigException) { }
        try {
            NativeDnsPlan.prepare(listOf("192.0.2.53"), listOf(route("0.0.0.0/0")),
                listOf(InetNetwork("198.19.255.1", 32)))
            fail("Accepted assigned-address collision")
        } catch (_: BadConfigException) { }
    }

    @Test fun managedCaptureSurvivesIncludeOnlyWithoutMigratingResolver() {
        val original = ProtocolConfig.build(false) {
            addAddress(InetNetwork("10.77.0.1", 32))
            addRoute(InetNetwork("0.0.0.0", 0))
            includeAddress(InetNetwork("203.0.113.0", 24))
            addDnsServer(InetAddress.getByName("192.0.2.53"))
            setMtu(1280)
        }
        val plan = NativeDnsPlan.prepare(listOf("192.0.2.53"), original.routes, original.addresses)
        assertEquals(NativeDnsScope.DIRECT, plan.bindings.single().scope)
        val alias = InetAddress.getByName("198.19.255.1")
        val managed = ProtocolConfig.build(false) {
            addAddress(InetNetwork("10.77.0.1", 32))
            addRoute(InetNetwork("0.0.0.0", 0))
            includeAddress(InetNetwork("203.0.113.0", 24))
            addDnsServer(InetAddress.getByName("192.0.2.53"))
            setManagedDnsServers(listOf(alias))
            setMtu(1280)
        }
        assertEquals(listOf(alias), managed.dnsServers.toList())
        assertTrue(managed.routes.contains(Route(InetNetwork(alias), true)))
        assertEquals(original.routes, managed.routes.filter { it.inetNetwork != InetNetwork(alias) }.toSet())
        assertEquals(NativeDnsScope.DIRECT,
            NativeDnsPlan.prepare(listOf("192.0.2.53"), managed.routes).bindings.single().scope)
    }

    @Test fun managedPublicationOrderAndIpv4OnlyAdmission() {
        val first = InetAddress.getByName("198.19.255.2")
        val second = InetAddress.getByName("198.19.255.1")
        val managed = ProtocolConfig.build(false) {
            addAddress(InetNetwork("10.77.0.1", 32))
            addRoute(InetNetwork("0.0.0.0", 0))
            setManagedDnsServers(listOf(first, second))
            setMtu(1280)
        }
        assertEquals(listOf(first, second), managed.dnsServers.toList())
        for (servers in listOf(emptyList(), listOf(first, first),
            listOf(InetAddress.getByName("fd77::53")))) {
            try {
                ProtocolConfig.Builder(false).setManagedDnsServers(servers)
                fail("Accepted ambiguous/non-IPv4 managed capture")
            } catch (_: BadConfigException) { }
        }
    }
}
