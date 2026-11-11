package org.amnezia.vpn.util.net

/** Main-thread queue; IO work carries a token rather than mutating queue state. */
class ApplicationPackageRefreshQueue {
    data class Worker internal constructor(val session: Long, internal val generation: Long)
    data class Request internal constructor(val worker: Worker, val packageName: String, val refreshCapture: Boolean)
    private var session = -1L
    private var generation = 0L
    private val pending = linkedMapOf<String, Boolean>()

    /** Returns true when an existing worker belongs to a different session. */
    fun offer(session: Long, packageName: String, refreshCapture: Boolean): Boolean {
        require(session > 0 && packageName.isNotBlank())
        val changed = this.session != session
        if (changed) {
            this.session = session
            ++generation
            pending.clear()
        }
        pending[packageName] = refreshCapture || pending[packageName] == true
        return changed
    }

    fun start(session: Long): Worker {
        require(session == this.session)
        return Worker(session, ++generation)
    }

    fun take(worker: Worker): Request? {
        if (!owns(worker) || pending.isEmpty()) return null
        val name = pending.keys.first()
        return Request(worker, name, pending.remove(name) == true)
    }

    /** An error from a retired worker cannot enqueue work in its replacement. */
    fun retry(request: Request): Boolean {
        if (!owns(request.worker)) return false
        pending[request.packageName] = request.refreshCapture || pending[request.packageName] == true
        return true
    }

    fun finish(worker: Worker): Boolean {
        if (!owns(worker)) return false
        pending.clear()
        ++generation
        return true
    }

    fun clear() {
        pending.clear()
        session = -1L
        ++generation
    }

    private fun owns(worker: Worker) = session == worker.session && generation == worker.generation
}
