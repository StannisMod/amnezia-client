package org.amnezia.vpn.util.net

import org.junit.Assert.*
import org.junit.Test

class ValidatedNetworkStateTest {
    @Test fun initialCallbackDoesNotRestartAnAlreadyConnectedSession() {
        val state = ValidatedNetworkState<String>()
        assertFalse(state.update("wifi", true))
        assertFalse(state.update("wifi", true))
    }
    @Test fun sameNetworkValidationLossThenRecoveryRestartsOnce() {
        val state = ValidatedNetworkState<String>()
        state.update("wifi", true)
        assertFalse(state.update("wifi", false))
        assertTrue(state.update("wifi", true))
        assertFalse(state.update("wifi", true))
    }
    @Test fun lostNetworkCanRecoverWithTheSameIdentity() {
        val state = ValidatedNetworkState<String>()
        state.update("wifi", true)
        state.lost("wifi")
        assertTrue(state.update("wifi", true))
    }
    @Test fun staleLossDoesNotInvalidateTheReplacementNetwork() {
        val state = ValidatedNetworkState<String>()
        state.update("wifi", true)
        assertTrue(state.update("mobile", true))
        state.lost("wifi")
        assertFalse(state.update("mobile", true))
    }
    @Test fun replacementWaitsForValidationAndResetClearsIdentity() {
        val state = ValidatedNetworkState<String>()
        state.update("wifi", true)
        assertFalse(state.update("mobile", false))
        assertTrue(state.update("mobile", true))
        state.reset()
        assertFalse(state.update("new-wifi", true))
    }
}
