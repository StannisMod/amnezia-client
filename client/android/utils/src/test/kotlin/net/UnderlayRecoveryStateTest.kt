package org.amnezia.vpn.util.net

import org.junit.Assert.*
import org.junit.Test

class UnderlayRecoveryStateTest {
    @Test fun hintsProbeHealthyPathButHandoverReopensOnlyTransport() {
        val state = UnderlayRecoveryState()
        state.start(7, "wifi", "192.0.2.1:443")
        val ticket = state.request(false)!!
        assertFalse(state.decide(ticket, "wifi")!!.reopen)
        assertTrue(state.decide(ticket, "cell")!!.reopen)
        assertEquals(7L, ticket.handle)
        assertTrue(state.commitTransport(ticket, "cell", "192.0.2.2:443"))
        val dnsRetry = state.request(false)!!
        assertFalse(state.decide(dnsRetry, "cell")!!.reopen)
        assertEquals("192.0.2.2:443", state.decide(dnsRetry, "cell")!!.endpoint)
    }
    @Test fun supersededDnsCannotCommitOrResurrectExplicitlyStoppedTunnel() {
        val state = UnderlayRecoveryState()
        state.start(7, "wifi", "192.0.2.1:443")
        val old = state.request(false)!!
        val replacement = state.request(false)!!
        assertNull(state.decide(old, "cell"))
        assertFalse(state.commitTransport(old, "cell", "192.0.2.99:443"))
        state.stop()
        assertFalse(state.current(replacement))
        assertNull(state.request(true))
        state.start(8, "wifi", "192.0.2.3:443")
        assertFalse(state.current(replacement))
    }
    @Test fun failedOrForcedRefreshIsNotLostWhenAnotherHintCancelsItsWorker() {
        val state = UnderlayRecoveryState()
        state.start(7, "wifi", "192.0.2.1:443")
        state.request(true)
        val next = state.request(false)!!
        assertTrue(state.decide(next, "wifi")!!.reopen)
        state.commitTransport(next, "wifi", "192.0.2.1:443")
        val failed = state.request(false)!!
        state.transportFailed(failed)
        assertTrue(state.decide(state.request(false)!!, "wifi")!!.reopen)
    }
    @Test fun peerVerificationSurvivesDnsHintsWithoutReopeningWorkingSocket() {
        val state = UnderlayRecoveryState()
        state.start(7, "wifi", "192.0.2.1:443")
        val moving = state.request(false)!!
        assertTrue(state.decide(moving, "cell")!!.verifyPeer)
        state.commitTransport(moving, "cell", "192.0.2.1:443")
        val dnsHint = state.request(false)!!
        assertFalse(state.decide(dnsHint, "cell")!!.reopen)
        assertTrue(state.decide(dnsHint, "cell")!!.verifyPeer)
        state.authenticated(moving)
        assertTrue(state.decide(dnsHint, "cell")!!.verifyPeer)
        state.authenticated(dnsHint)
        assertFalse(state.decide(dnsHint, "cell")!!.verifyPeer)
    }

}
