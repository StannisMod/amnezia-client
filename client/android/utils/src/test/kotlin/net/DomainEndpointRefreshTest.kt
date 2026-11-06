package org.amnezia.vpn.util.net

import java.net.InetAddress
import java.net.UnknownHostException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.*
import org.junit.Test

class DomainEndpointRefreshTest {
    @Test fun triesEveryAddressDespiteDnsReordering() = runBlocking {
        val candidates = DomainEndpointRefresh.Candidates()
        val a = InetAddress.getByName("192.0.2.1")
        val b = InetAddress.getByName("192.0.2.2")
        val v6 = InetAddress.getByName("2001:db8::1")
        suspend fun next(answers: List<InetAddress>) = DomainEndpointRefresh.resolve("vpn.example.org", { answers }, candidates = candidates)
        assertEquals("192.0.2.1", next(listOf(v6, a, b, a)))
        assertEquals("192.0.2.2", next(listOf(b, a, v6)))
        assertEquals("2001:db8:0:0:0:0:0:1", next(listOf(a, v6, b)))
        val published = InetAddress.getByName("192.0.2.3")
        assertEquals("192.0.2.3", next(listOf(a, published)))
        candidates.clear()
        assertEquals("192.0.2.1", next(listOf(a, b)))
    }
    @Test fun distinguishesHostFromNumericEndpoints() {
        assertTrue(DomainEndpointRefresh.isDomain("vpn.example.org"))
        assertFalse(DomainEndpointRefresh.isDomain("192.0.2.1"))
        assertFalse(DomainEndpointRefresh.isDomain("2001:db8::1"))
    }
    @Test fun retriesUnderlayDnsAndPreservesOriginalHost() = runBlocking {
        var queries = 0
        val original = "vpn.example.org"
        val address = DomainEndpointRefresh.resolve(original, { host ->
            assertEquals(original, host)
            if (++queries == 1) throw UnknownHostException()
            listOf(InetAddress.getByName("2001:db8::1"), InetAddress.getByName("192.0.2.9"))
        }, retryMs = 0)
        assertEquals("192.0.2.9", address)
        assertEquals(2, queries)
        assertEquals("vpn.example.org", original)
    }
    @Test fun retryBudgetIsFinite() = runBlocking {
        var queries = 0
        try {
            DomainEndpointRefresh.resolve("vpn.example.org", { ++queries; throw UnknownHostException() }, retryMs = 0)
            fail("DNS exhaustion must be reported")
        } catch (_: UnknownHostException) { assertEquals(6, queries) }
    }
    @Test fun timeoutCanRetryOnTheReplacementNetwork() = runBlocking {
        val queries = AtomicInteger()
        val address = DomainEndpointRefresh.resolve("vpn.example.org", {
            if (queries.incrementAndGet() == 1) Thread.sleep(10000)
            listOf(InetAddress.getByName("192.0.2.2"))
        }, timeoutMs = 30, retryMs = 0)
        assertEquals("192.0.2.2", address)
        assertEquals(2, queries.get())
    }
    @Test fun disconnectDoesNotWaitForAnUninterruptibleResolver() = runBlocking {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        var delivered = false
        val job = launch {
            DomainEndpointRefresh.resolve("vpn.example.org", {
                entered.countDown()
                while (release.count != 0L) {
                    try { release.await() } catch (_: InterruptedException) { /* emulate platform DNS */ }
                }
                listOf(InetAddress.getByName("192.0.2.1"))
            })
            delivered = true
        }
        try {
            withTimeout(2000) { while (entered.count != 0L) delay(1) }
            withTimeout(500) { job.cancelAndJoin() }
            assertFalse(delivered)
        } finally { release.countDown() }
    }
    @Test fun cancellationCannotDeliverAnOldLookup() = runBlocking {
        val entered = CountDownLatch(1)
        var delivered = false
        val job = launch {
            DomainEndpointRefresh.resolve("vpn.example.org", {
                entered.countDown()
                CountDownLatch(1).await()
                listOf(InetAddress.getByName("192.0.2.1"))
            })
            delivered = true
        }
        withTimeout(2000) { while (entered.count != 0L) delay(1) }
        job.cancelAndJoin()
        assertFalse(delivered)
    }
}
