package org.amnezia.vpn.util.net

// Callback state is kept independently of Android APIs so loss/recovery and
// callback ordering can be tested without a device. Call on the listener thread.
internal class ValidatedNetworkState<T> {
    private var current: T? = null
    private var validated = false

    fun update(network: T, nowValidated: Boolean): Boolean {
        val initial = current == null
        val changed = current != network
        val wasValidated = validated
        current = network
        validated = nowValidated
        return !initial && nowValidated && (changed || !wasValidated)
    }

    fun lost(network: T) {
        if (current == network) validated = false
    }

    fun reset() {
        current = null
        validated = false
    }
}
