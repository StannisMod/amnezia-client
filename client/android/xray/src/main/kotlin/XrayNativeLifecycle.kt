package org.amnezia.vpn.protocol.xray

/** Confirm each native boundary once; a timeout/error is not owner retirement. */
internal class XrayNativeLifecycle(
    private val stopTunnel: () -> String?,
    private val stopEngine: () -> String?,
    private val cancelPreparedDns: () -> String?
) {
    @Volatile var ownsNativeResources = false
        private set
    private var admitted = false
    private var tunnelJoined = false
    private var engineJoined = false

    @Synchronized fun begin() {
        check(!ownsNativeResources) { "Previous Xray native cleanup is pending" }
        ownsNativeResources = true
        admitted = false
        tunnelJoined = false
        engineJoined = false
    }

    @Synchronized fun admit() {
        check(ownsNativeResources) { "Missing Xray native generation" }
        admitted = true
    }

    @Synchronized fun cleanup(): String? {
        if (!ownsNativeResources) return null
        if (admitted && !tunnelJoined) {
            confirm(stopTunnel)?.let { return it }
            tunnelJoined = true
        }
        if (admitted && !engineJoined) {
            confirm(stopEngine)?.let { return it }
            engineJoined = true
        }
        confirm(cancelPreparedDns)?.let { return it }
        ownsNativeResources = false
        return null
    }

    private fun confirm(operation: () -> String?): String? = try {
        operation()?.takeIf { it.isNotBlank() }
    } catch (error: Exception) { error.message ?: error.toString() }
}

/** One failed generation. Caller serializes steps with native start/stop. */
internal class XrayDnsFailureCleanup(private val owner: XrayNativeLifecycle) {
    private var reported = false
    private var lastPending: String? = null

    fun step(currentGeneration: Boolean, disconnecting: () -> Unit,
             report: (String) -> Unit, retire: () -> Unit): Boolean {
        if (!currentGeneration || !owner.ownsNativeResources) return false
        disconnecting()
        if (!reported) {
            report("Xray native DNS frontend failed")
            reported = true
        }
        val pending = owner.cleanup()
        if (pending == null) {
            retire()
            return false
        }
        if (lastPending != pending) {
            report("Xray native cleanup pending: $pending")
            lastPending = pending
        }
        return true
    }
}
