package org.amnezia.vpn.protocol.openvpn

import org.amnezia.vpn.protocol.NativeDnsBinding
import org.amnezia.vpn.protocol.NativeDnsScope
import org.junit.Assert.*
import org.junit.Test

class OpenVpnDnsBindingsTest {
    private fun binding(alias: Int) = NativeDnsBinding("198.19.255.$alias:53",
        "192.0.2.53:53", NativeDnsScope.DIRECT)

    @Test fun duplicateResolversRetainDistinctOrderedNativeAssociations() {
        val owner = OpenVpnDnsBindings()
        val calls = mutableListOf<String>()
        val generation = OpenVpnDnsBindings.Generation(
            { binding, fd -> calls += "${binding.endpoint}:$fd"; true }, {}, {})
        owner.register(10, generation, binding(1))
        owner.register(11, generation, binding(2))
        assertTrue(owner.bind(11, 42))
        assertTrue(owner.bind(10, 43))
        assertEquals(listOf("198.19.255.2:53:42", "198.19.255.1:53:43"), calls)
        assertFalse(owner.bind(12, 44))
        assertFalse(owner.bind(10, -1))
        assertTrue(owner.hasNativeBindings)
    }

    @Test fun frontendFailureImmediatelyFencesItsWholeGenerationExactlyOnce() {
        val owner = OpenVpnDnsBindings()
        var failures = 0
        var binds = 0
        val generation = OpenVpnDnsBindings.Generation({ _, _ -> binds++; true }, { failures++ }, {})
        owner.register(10, generation, binding(1))
        owner.register(11, generation, binding(2))
        owner.failed(10); owner.failed(11)
        assertEquals(1, failures)
        assertFalse(owner.bind(10, 42))
        assertFalse(owner.bind(11, 43))
        assertEquals(0, binds)
        assertTrue(owner.hasNativeBindings) // Failure is not confirmed retirement.
    }

    @Test fun retiredAndStaleCallbacksCannotAlterTheNextGeneration() {
        val owner = OpenVpnDnsBindings()
        var retired = 0
        var nextFailed = 0
        val old = OpenVpnDnsBindings.Generation({ _, _ -> true }, {}, { retired++ })
        owner.register(10, old, binding(1))
        owner.retired(10)
        assertEquals(1, retired)
        val next = OpenVpnDnsBindings.Generation({ _, _ -> true }, { nextFailed++ }, { retired++ })
        owner.register(11, next, binding(1))
        owner.failed(10); owner.retired(10)
        assertTrue(owner.bind(11, 42))
        assertEquals(0, nextFailed)
        try { owner.register(10, next, binding(2)); fail("reused native handle admitted") }
        catch (_: IllegalStateException) {}
        owner.retired(11)
        assertEquals(2, retired)
        assertFalse(owner.hasNativeBindings)
    }

    @Test fun everyScopeMustRetireBeforeDroppingItsPublication() {
        val owner = OpenVpnDnsBindings()
        var retired = 0
        val generation = OpenVpnDnsBindings.Generation({ _, _ -> true }, {}, { retired++ })
        owner.register(10, generation, binding(1))
        owner.register(11, generation, binding(2))
        owner.retired(10)
        assertEquals(0, retired)
        assertFalse(owner.bind(10, 42))
        assertTrue(owner.bind(11, 43))
        owner.allNativeJoined()
        assertEquals(1, retired)
        assertFalse(owner.bind(11, 44))
        owner.retired(11); owner.allNativeJoined()
        assertEquals(1, retired)
    }
}
