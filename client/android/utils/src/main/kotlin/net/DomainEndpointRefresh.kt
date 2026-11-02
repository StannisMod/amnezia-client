package org.amnezia.vpn.util.net

import java.net.InetAddress
import java.net.UnknownHostException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.withTimeout

// Resolve only the peer, never destination-rule domains. The caller supplies a
// resolver explicitly bound to a non-VPN network and keeps the saved host intact.
object DomainEndpointRefresh {
    // Network.getAllByName can ignore thread interruption. Do not attach that
    // blocking call to a VPN lifetime Job: disconnect must not wait for DNS.
    private val dnsWorkers = ThreadPoolExecutor(2, 2, 0L, TimeUnit.MILLISECONDS,
        LinkedBlockingQueue<Runnable>(), { task -> Thread(task, "vpn-endpoint-dns").apply { isDaemon = true } })

    private suspend fun lookup(host: String, resolver: (String) -> List<InetAddress>): List<InetAddress> =
        suspendCancellableCoroutine { continuation ->
            val future = dnsWorkers.submit {
                try { continuation.resume(resolver(host)) }
                catch (error: Exception) {
                    if (continuation.isActive) continuation.resumeWithException(error)
                }
            }
            continuation.invokeOnCancellation { future.cancel(true); dnsWorkers.purge() }
        }

    fun isDomain(host: String): Boolean = ':' !in host &&
        !Regex("^[0-9.]+$").matches(host.trim())

    // Remember attempted answers, rather than indexing a potentially reordered
    // DNS response. A newly published address is preferred over already tried IPs.
    class Candidates {
        private val tried = linkedSetOf<String>()
        @Synchronized fun clear() { tried.clear() }
        @Synchronized fun select(addresses: List<InetAddress>): String? {
            val usable = addresses.sortedBy { if (it.address.size == 4) 0 else 1 }
                .mapNotNull { it.hostAddress }.filter { '%' !in it }.distinct().take(16)
            if (usable.isEmpty()) return null
            val next = usable.firstOrNull { it !in tried } ?: usable.first().also { tried.clear() }
            tried.add(next)
            return next
        }
    }

    suspend fun resolve(
        host: String,
        resolver: (String) -> List<InetAddress>,
        attempts: Int = 6,
        timeoutMs: Long = 15000,
        retryMs: Long = 1000,
        candidates: Candidates = Candidates()
    ): String {
        require(attempts in 1..6 && timeoutMs > 0 && retryMs >= 0)
        repeat(attempts) { attempt ->
            currentCoroutineContext().ensureActive()
            try {
                val addresses = withTimeout(timeoutMs) {
                    lookup(host, resolver)
                }
                currentCoroutineContext().ensureActive()
                candidates.select(addresses)?.let { return it }
            } catch (_: TimeoutCancellationException) {
                currentCoroutineContext().ensureActive()
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: UnknownHostException) { /* Underlay may still be acquiring DNS. */ }
            if (attempt + 1 < attempts) delay(minOf(30000L, retryMs * (1L shl attempt)))
        }
        throw UnknownHostException("VPN endpoint DNS retries exhausted")
    }
}
