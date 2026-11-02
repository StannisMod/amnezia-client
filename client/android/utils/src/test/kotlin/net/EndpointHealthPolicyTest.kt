package org.amnezia.vpn.util.net

import java.net.InetAddress
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.amnezia.vpn.util.net.EndpointHealthPolicy.Action.*

class EndpointHealthPolicyTest {
    @Test fun idleAndHealthyTrafficDoNotReconnect() {
        val health = EndpointHealthPolicy(staleMs = 10000)
        assertEquals(NONE, health.sample(1, 100, 10, 10, 0))
        for (now in 5000L..100000L step 5000L) assertEquals(NONE, health.sample(1, 100, 10, 10, now))
        assertEquals(NONE, health.sample(1, 100, 20, 10, 105000))
        assertEquals(NONE, health.sample(1, 101, 30, 10, 110000)) // Rekey is progress.
        assertEquals(NONE, health.sample(1, 101, 40, 20, 115000)) // Receive is progress.
    }
    @Test fun sameNetworkOutageRefreshesDomainToNewIp() = runBlocking {
        val health = EndpointHealthPolicy(staleMs = 10000)
        val savedHost = "vpn.example.org"
        health.sample(1, 100, 10, 10, 0)
        assertEquals(NONE, health.sample(1, 100, 20, 10, 5000))
        assertEquals(NONE, health.sample(1, 100, 30, 10, 10000))
        assertEquals(REFRESH, health.sample(1, 100, 40, 10, 15000))
        // No network-change event: a watchdog decision initiates fresh DNS.
        val newIp = DomainEndpointRefresh.resolve(savedHost, {
            listOf(InetAddress.getByName("192.0.2.99"))
        }, retryMs = 0)
        assertEquals("192.0.2.99", newIp)
        assertEquals("vpn.example.org", savedHost)
        assertEquals(NONE, health.sample(2, 0, 0, 0, 20000))
        assertEquals(NONE, health.sample(2, 101, 10, 10, 25000)) // New endpoint handshook.
    }
    @Test fun firstSendAfterSleepGetsAFullGracePeriod() {
        val health = EndpointHealthPolicy(staleMs = 10000)
        health.sample(1, 100, 10, 10, 0)
        health.sample(1, 100, 20, 10, 5000)
        assertEquals(NONE, health.sample(1, 100, 30, 10, 60000))
        assertEquals(NONE, health.sample(1, 100, 40, 10, 65000))
        assertEquals(NONE, health.sample(1, 100, 50, 10, 70000))
        assertEquals(REFRESH, health.sample(1, 100, 60, 10, 75000))
    }
    @Test fun failedHandshakesHaveAFiniteRecoveryBudget() {
        val health = EndpointHealthPolicy()
        var epoch = 1L
        var refreshes = 0
        var errors = 0
        for (now in 0L..1000000L step 5000L) {
            when (health.sample(epoch, 0, 0, 0, now)) {
                REFRESH -> { ++refreshes; ++epoch }
                EXHAUSTED -> ++errors
                NONE -> Unit
            }
        }
        assertEquals(6, refreshes)
        assertEquals(1, errors)
    }
    @Test fun legacyPeerMustShowProgressAfterAnEndpointUpdate() {
        val health = EndpointHealthPolicy(staleMs = 10000)
        var action = NONE
        for (now in 0L..15000L step 5000L) action = health.sample(1, 100, now / 100 + 10, 10, now)
        assertEquals(REFRESH, action)
        // Legacy adapter updates a peer in place: its old handshake is NOT a
        // successful replacement handshake, and must not reset the budget.
        for (now in 20000L..190000L step 5000L) assertEquals(NONE, health.sample(1, 100, now, 10, now))
        assertEquals(REFRESH, health.sample(1, 100, 195000, 10, 195000))
        assertEquals(NONE, health.sample(1, 101, 200000, 20, 200000))
    }
    @Test fun longerAwgTimersExtendTheStaleWindow() {
        assertEquals(240000L, EndpointHealthPolicy.staleBudget(null, "invalid"))
        assertEquals(1230000L, EndpointHealthPolicy.staleBudget("120-600", "180"))
        assertEquals(240000L, EndpointHealthPolicy.staleBudget("-2", "9999999"))
    }
}
