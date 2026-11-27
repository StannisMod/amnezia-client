package org.amnezia.vpn.protocol.xray

import org.amnezia.vpn.protocol.BadConfigException
import org.amnezia.vpn.protocol.NativeDnsPlan
import org.amnezia.vpn.protocol.Route
import org.amnezia.vpn.util.net.InetNetwork
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class XrayDnsPublicationTest {
    private fun directPlan() = NativeDnsPlan.prepare(listOf("192.0.2.53"), emptyList())
    private fun snapshot(transport: String = "udp") = JSONObject(
        """{"links":[{"id":"android-original","default":true,"servers":[{"transport":"$transport"}]}]}""")

    @Test fun tunnelOccurrencesHaveDistinctAliasesWithoutNetworkSubstitution() {
        val plan = NativeDnsPlan.prepare(listOf("192.0.2.53", "192.0.2.53"),
            listOf(Route(InetNetwork("0.0.0.0", 0), true)))
        val publication = XrayDnsPublication.prepare(plan, false, false,
            { error("tunnel DNS must not select an underlay") }, null, { false }, null)
        val bindings = JSONObject(publication.raw).getJSONArray("bindings")
        assertEquals(2, bindings.length())
        assertEquals("tunnel", bindings.getJSONObject(0).getString("scope"))
        assertEquals(bindings.getJSONObject(0).getString("upstream"), bindings.getJSONObject(1).getString("upstream"))
        assertNotEquals(publication.aliases[0], publication.aliases[1])
        assertEquals(plan.bindings, publication.bindings)
    }
    @Test fun directBindingPinsOriginalTokenAndGeneration() {
        var identity = "original-generation"
        val calls = mutableListOf<String>()
        val publication = XrayDnsPublication.prepare(directPlan(), false, false,
            { snapshot() }, { identity }, { calls += "protect:$it"; true },
            { fd, token -> calls += "$fd:$token"; true })
        assertTrue(publication.bindSocket(42, "android-original"))
        assertEquals(listOf("protect:42", "42:android-original"), calls)
        identity = "replacement-generation"
        assertFalse(publication.bindSocket(43, "android-original"))
        assertEquals(2, calls.size)
    }
    @Test fun failedProtectionNeverBindsOrFallsBack() {
        var bound = false
        val publication = XrayDnsPublication.prepare(directPlan(), false, false,
            { snapshot() }, { "original" }, { false }, { _, _ -> bound = true; true })
        assertFalse(publication.bindSocket(42, "android-original"))
        assertFalse(bound)
    }
    @Test fun strictEncryptedDnsIsRejectedBeforeAnySnapshotOrBootstrap() {
        try {
            XrayDnsPublication.prepare(directPlan(), true, false,
                { error("encrypted provider bootstrap must not run") }, { "original" }, { true }, { _, _ -> true })
            fail("downgraded strict encrypted DNS")
        } catch (_: BadConfigException) { }
    }
    @Test fun encryptedDirectMetadataCannotBecomePlaintext() {
        for (transport in listOf("tls", "https", "unknown")) {
            try {
                XrayDnsPublication.prepare(directPlan(), false, false,
                    { snapshot(transport) }, { "original" }, { true }, { _, _ -> true })
                fail("stripped $transport metadata")
            } catch (_: BadConfigException) { }
        }
    }
    @Test fun lockdownAmbiguityAndPreparationRaceFailClosed() {
        for (lockdown in listOf(true, false)) {
            try {
                XrayDnsPublication.prepare(directPlan(), false, lockdown,
                    { JSONObject("""{"links":[]}""") }, { "original" }, { true }, { _, _ -> true })
                fail("invented original network")
            } catch (_: BadConfigException) { }
        }
        var generation = 0
        try {
            XrayDnsPublication.prepare(directPlan(), false, false,
                { snapshot() }, { "generation-${generation++}" }, { true }, { _, _ -> true })
            fail("accepted a changed original network")
        } catch (_: BadConfigException) { }
    }
    @Test fun retiredAndMismatchedCallbacksCannotBind() {
        val publication = XrayDnsPublication.prepare(directPlan(), false, false,
            { snapshot() }, { "original" }, { true }, { _, _ -> true })
        assertFalse(publication.bindSocket(-1, "android-original"))
        assertFalse(publication.bindSocket(42, "android-other"))
        publication.retire()
        assertFalse(publication.bindSocket(42, "android-original"))
    }
    @Test fun frontendFailureIsAdmittedOnceAndImmediatelyBlocksNewDnsSockets() {
        var bound = 0
        val publication = XrayDnsPublication.prepare(directPlan(), false, false,
            { snapshot() }, { "original" }, { true }, { _, _ -> bound++; true })
        assertTrue(publication.beginFailure())
        assertFalse(publication.beginFailure())
        assertFalse(publication.bindSocket(42, "android-original"))
        assertFalse(publication.bindDirectSocket(43))
        assertEquals(0, bound)
        publication.retire()
        assertFalse(publication.beginFailure())
    }
    @Test fun sharedDirectSocketAdapterUsesTheSameCapturedNetworkContract() {
        var identity = "original"
        val calls = mutableListOf<String>()
        val publication = XrayDnsPublication.prepare(directPlan(), false, false,
            { snapshot() }, { identity }, { calls += "protect:$it"; true },
            { fd, token -> calls += "$fd:$token"; true })
        assertTrue(publication.bindDirectSocket(42))
        assertEquals(listOf("protect:42", "42:android-original"), calls)
        identity = "changed"
        assertFalse(publication.bindDirectSocket(43))
        assertEquals(2, calls.size)
        publication.retire()
        assertFalse(publication.bindDirectSocket(44))
    }
}
