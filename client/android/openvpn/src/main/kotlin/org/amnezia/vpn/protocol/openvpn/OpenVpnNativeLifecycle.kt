package org.amnezia.vpn.protocol.openvpn

/** A stop request is not a joined native worker or a retired DNS/policy owner. */
internal class OpenVpnNativeLifecycle(
    private val requestStop: () -> Unit,
    private val nativeJoined: () -> Boolean,
    private val stopDns: () -> Unit,
    private val releasePolicy: () -> Boolean,
    private val preparationJoined: () -> Boolean = { true }
) {
    @Volatile var ownsNativeResources = false
        private set
    private var admitted = false
    private var dnsJoined = false

    @Synchronized fun begin() {
        check(!ownsNativeResources) { "Previous OpenVPN native cleanup is pending" }
        ownsNativeResources = true
        admitted = false
        dnsJoined = false
    }

    @Synchronized fun admit() {
        check(ownsNativeResources) { "Missing OpenVPN native generation" }
        admitted = true
    }

    @Synchronized fun cleanup(): String? {
        if (!ownsNativeResources) return null
        try {
            if (!preparationJoined()) return "OpenVPN native preparation join pending"
            if (admitted && !nativeJoined()) {
                // Native stop is documented to act only after connect starts.
                // Retry while join is unconfirmed, including a stop/start race;
                // never kill a still-pending worker or reset its ownership.
                requestStop()
                return "OpenVPN native worker join pending"
            }
            if (!dnsJoined) {
                stopDns()
                dnsJoined = true
            }
            // Includes detached native bootstrap workers and in-flight Cloak
            // dials, not merely absence of current DNS listeners.
            if (!releasePolicy()) return "OpenVPN native DNS/transport policy retirement pending"
        } catch (error: Exception) {
            return error.message ?: error.toString()
        }
        ownsNativeResources = false
        return null
    }
}
