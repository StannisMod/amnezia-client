package org.amnezia.vpn.protocol.openvpn

import org.junit.Assert.*
import org.junit.Test

class OpenVpnNativeLifecycleTest {
    @Test fun configurationMustReturnBeforeAnyRollbackOrNativeDelete() {
        var preparing = true
        var touched = false
        val owner = OpenVpnNativeLifecycle({ fail("worker not admitted") }, { false },
            { touched = true }, { true }, { !preparing })
        owner.begin()
        assertNotNull(owner.cleanup())
        assertFalse(touched)
        assertTrue(owner.ownsNativeResources)
        preparing = false
        assertNull(owner.cleanup())
        assertTrue(touched)
    }
    @Test fun nativeWorkerMustJoinBeforeDnsOrPolicyRetirement() {
        var joined = false
        val calls = mutableListOf<String>()
        val owner = OpenVpnNativeLifecycle({ calls += "stop" }, { joined },
            { calls += "dns" }, { calls += "policy"; true })
        owner.begin(); owner.admit()
        assertNotNull(owner.cleanup())
        assertTrue(owner.ownsNativeResources)
        assertEquals(listOf("stop"), calls)
        assertNotNull(owner.cleanup()) // Stop before native admission may have been ignored.
        assertEquals(listOf("stop", "stop"), calls)
        joined = true
        assertNull(owner.cleanup())
        assertFalse(owner.ownsNativeResources)
        assertEquals(listOf("stop", "stop", "dns", "policy"), calls)
        assertNull(owner.cleanup())
        assertEquals(4, calls.size)
    }

    @Test fun failedPolicyReleaseRetainsOwnerWithoutRepeatingConfirmedDnsJoin() {
        var policyReady = false
        var dnsJoins = 0
        val owner = OpenVpnNativeLifecycle({ fail("native worker already joined") }, { true },
            { dnsJoins++ }, { policyReady })
        owner.begin(); owner.admit()
        assertNotNull(owner.cleanup())
        assertTrue(owner.ownsNativeResources)
        assertNotNull(owner.cleanup())
        assertEquals(1, dnsJoins)
        policyReady = true
        assertNull(owner.cleanup())
        assertEquals(1, dnsJoins)
    }

    @Test fun preparationRollbackDoesNotInventAnEngineJoin() {
        val calls = mutableListOf<String>()
        val owner = OpenVpnNativeLifecycle({ fail("unadmitted worker stop") },
            { fail("unadmitted worker join"); false },
            { calls += "dns" }, { calls += "policy"; true })
        owner.begin()
        assertNull(owner.cleanup())
        assertEquals(listOf("dns", "policy"), calls)
        assertFalse(owner.ownsNativeResources)
    }

    @Test fun exceptionsAndReplacementCannotDiscardPendingOwner() {
        var failJoin = true
        val owner = OpenVpnNativeLifecycle({}, { true },
            { if (failJoin) error("native callback still owned") }, { true })
        owner.begin(); owner.admit()
        assertEquals("native callback still owned", owner.cleanup())
        assertTrue(owner.ownsNativeResources)
        try { owner.begin(); fail("replacement admitted") } catch (_: IllegalStateException) {}
        failJoin = false
        assertNull(owner.cleanup())
        owner.begin()
        assertTrue(owner.ownsNativeResources)
        assertNull(owner.cleanup())
    }
}
