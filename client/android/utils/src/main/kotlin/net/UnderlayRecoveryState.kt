package org.amnezia.vpn.util.net

/** A network hint owns a generation, never the lifetime of the packet tunnel. */
class UnderlayRecoveryState {
    data class Ticket(val generation: Long, val handle: Long)
    data class Decision(val reopen: Boolean, val endpoint: String?, val verifyPeer: Boolean)
    private var generation = 0L
    private var handle = -1L
    private var network: String? = null
    private var endpoint: String? = null
    private var force = false
    private var peerCheck = false

    @Synchronized fun start(owner: Long, identity: String?, target: String) {
        require(owner > 0)
        generation++; handle = owner; network = identity; endpoint = target; force = false; peerCheck = false
    }
    @Synchronized fun stop() { generation++; handle = -1; network = null; endpoint = null; force = false; peerCheck = false }
    @Synchronized fun request(reopen: Boolean): Ticket? {
        if (handle <= 0) return null
        force = force || reopen
        peerCheck = true
        return Ticket(++generation, handle)
    }
    @Synchronized fun current(ticket: Ticket): Boolean = ticket.handle == handle && ticket.generation == generation
    @Synchronized fun decide(ticket: Ticket, identity: String): Decision? =
        if (current(ticket)) Decision(force || identity != network, endpoint, peerCheck || identity != network) else null
    @Synchronized fun transportFailed(ticket: Ticket) { if (current(ticket)) { force = true; peerCheck = true } }
    @Synchronized fun authenticated(ticket: Ticket) { if (current(ticket)) peerCheck = false }
    @Synchronized fun commitTransport(ticket: Ticket, identity: String, target: String?): Boolean {
        if (!current(ticket)) return false
        peerCheck = peerCheck || identity != network
        network = identity; endpoint = target; force = false
        return true
    }
}
