package org.amnezia.vpn.protocol.xray

import org.junit.Assert.*
import org.junit.Test

class XrayNativeLifecycleTest {
    @Test fun preparedRollbackDoesNotStopAnUnadmittedEngine() {
        val calls = mutableListOf<String>()
        val owner = XrayNativeLifecycle({ calls += "tun"; null }, { calls += "engine"; null },
            { calls += "dns"; null })
        owner.begin()
        assertNull(owner.cleanup())
        assertEquals(listOf("dns"), calls)
        assertFalse(owner.ownsNativeResources)
    }
    @Test fun teardownJoinsTunnelBeforeStoppingXrayAndReleasingDns() {
        val calls = mutableListOf<String>()
        val owner = XrayNativeLifecycle({ calls += "tun"; null }, { calls += "engine"; null },
            { calls += "dns"; null })
        owner.begin(); owner.admit()
        assertNull(owner.cleanup())
        assertNull(owner.cleanup())
        assertEquals(listOf("tun", "engine", "dns"), calls)
    }
    @Test fun failedTunnelJoinRetainsOwnerAndBlocksReplacement() {
        var pending = true
        val calls = mutableListOf<String>()
        val owner = XrayNativeLifecycle({ calls += "tun"; if (pending) "join pending" else null },
            { calls += "engine"; null }, { calls += "dns"; null })
        owner.begin(); owner.admit()
        assertEquals("join pending", owner.cleanup())
        assertTrue(owner.ownsNativeResources)
        assertEquals(listOf("tun"), calls)
        try { owner.begin(); fail("replaced pending owner") } catch (_: IllegalStateException) { }
        pending = false
        assertNull(owner.cleanup())
        assertEquals(listOf("tun", "tun", "engine", "dns"), calls)
    }
    @Test fun joinedTunnelIsNotReopenedWhileEngineStopRetries() {
        var pending = true
        val calls = mutableListOf<String>()
        val owner = XrayNativeLifecycle({ calls += "tun"; null },
            { calls += "engine"; if (pending) "engine pending" else null }, { calls += "dns"; null })
        owner.begin(); owner.admit()
        assertEquals("engine pending", owner.cleanup())
        pending = false
        assertNull(owner.cleanup())
        assertEquals(listOf("tun", "engine", "engine", "dns"), calls)
    }
    @Test fun finalDnsFailureDoesNotEmitOwnerRetirement() {
        var pending = true
        var joins = 0
        val owner = XrayNativeLifecycle({ joins++; null }, { joins++; null },
            { if (pending) "dns pending" else null })
        owner.begin(); owner.admit()
        assertEquals("dns pending", owner.cleanup())
        assertTrue(owner.ownsNativeResources)
        pending = false
        assertNull(owner.cleanup())
        assertEquals(2, joins)
    }
    @Test fun nativeExceptionsRemainPendingAndRetryable() {
        var pending = true
        val owner = XrayNativeLifecycle({ if (pending) error("native failure") else null }, { null }, { null })
        owner.begin(); owner.admit()
        assertEquals("native failure", owner.cleanup())
        assertTrue(owner.ownsNativeResources)
        pending = false
        assertNull(owner.cleanup())
    }
    @Test fun frontendFailureRetainsDisconnectingUntilConfirmedNativeJoin() {
        var pending = true
        val calls = mutableListOf<String>()
        val reports = mutableListOf<String>()
        var state = "CONNECTED"
        val owner = XrayNativeLifecycle({ calls += "tun"; if (pending) "join pending" else null },
            { calls += "engine"; null }, { calls += "dns"; null })
        owner.begin(); owner.admit()
        val failure = XrayDnsFailureCleanup(owner)
        fun step() = failure.step(true, { state = "DISCONNECTING" }, reports::add,
            { state = "DISCONNECTED" })
        assertTrue(step())
        assertTrue(step())
        assertTrue(owner.ownsNativeResources)
        assertEquals("DISCONNECTING", state)
        assertEquals(listOf("tun", "tun"), calls)
        assertEquals(2, reports.size) // failure and one distinct pending reason
        pending = false
        assertFalse(step())
        assertEquals(listOf("tun", "tun", "tun", "engine", "dns"), calls)
        assertEquals("DISCONNECTED", state)
    }
    @Test fun staleFrontendEventCannotCleanUpReplacementGeneration() {
        var stops = 0
        val owner = XrayNativeLifecycle({ stops++; null }, { stops++; null }, { stops++; null })
        owner.begin(); owner.admit()
        val stale = XrayDnsFailureCleanup(owner)
        assertFalse(stale.step(false, { fail("stale disconnect") }, { fail("stale report") },
            { fail("stale retirement") }))
        assertEquals(0, stops)
        assertTrue(owner.ownsNativeResources)
        assertNull(owner.cleanup())
    }
}
