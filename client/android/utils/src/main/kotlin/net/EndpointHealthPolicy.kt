package org.amnezia.vpn.util.net

// Monotonic timestamps and peer counters only: testable without Android/native
// handles. A new backend epoch is not healthy until it has a real handshake.
class EndpointHealthPolicy(var staleMs: Long = 240000, private val maxAttempts: Int = 6) {
    enum class Action { NONE, REFRESH, EXHAUSTED }
    private var epoch: Long? = null
    private var handshake = 0L
    private var tx = 0L
    private var rx = 0L
    private var lastSample: Long? = null
    private var pendingSince: Long? = null
    private var deadline: Long? = null
    private var attempts = 0
    private var exhausted = false

    fun sample(backend: Long, handshake: Long, tx: Long, rx: Long, now: Long): Action {
        if (exhausted) return Action.NONE
        val changed = epoch != backend
        val gap = lastSample?.let { now < it || now - it > 30000 } ?: false
        if (changed) { epoch = backend; pendingSince = null; deadline = now + 45000 }
        val evidence = handshake > 0 && (changed || handshake != this.handshake || rx > this.rx)
        if (evidence) { attempts = 0; deadline = null; pendingSince = null }
        else if (gap) {
            pendingSince = null
            if (deadline != null) deadline = now + 45000
        }
        val sending = !changed && !gap && tx > this.tx
        if (!evidence && deadline == null && sending && pendingSince == null) pendingSince = now
        val due = deadline?.let { now >= it } ?: (sending && pendingSince?.let { now - it >= staleMs } == true)
        this.handshake = handshake
        this.tx = tx
        this.rx = rx
        lastSample = now
        if (!due) return Action.NONE
        if (attempts >= maxAttempts) { exhausted = true; return Action.EXHAUSTED }
        ++attempts
        pendingSince = null
        // Covers six bounded DNS attempts plus the replacement handshake.
        deadline = now + 180000
        return Action.REFRESH
    }

    companion object {
        fun staleBudget(rekey: String?, reject: String?): Long = listOfNotNull(rekey, reject)
            .mapNotNull { it.substringAfterLast('-').trim().toLongOrNull() }
            .filter { it in 1..86400 }
            .fold(240000L) { budget, seconds -> maxOf(budget, (2 * seconds + 30) * 1000) }
    }
}
