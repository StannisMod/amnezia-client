package org.amnezia.vpn.util.net

import org.junit.Assert.*
import org.junit.Test

class ApplicationPackageRefreshQueueTest {
    @Test fun installArrivingDuringRemovalIsNotLost() {
        val queue=ApplicationPackageRefreshQueue()
        queue.offer(1,"app.one",false)
        val worker=queue.start(1)
        val removal=queue.take(worker)!!
        assertFalse(removal.refreshCapture)
        queue.offer(1,"app.one",true)
        queue.offer(1,"app.two",false)
        // The removal's failure must not downgrade the newer install request.
        assertTrue(queue.retry(removal))
        val install=queue.take(worker)!!
        assertEquals("app.one",install.packageName)
        assertTrue(install.refreshCapture)
        assertEquals("app.two",queue.take(worker)!!.packageName)
        assertNull(queue.take(worker))
    }

    @Test fun staleRetryAndCleanupCannotAffectAnotherSession() {
        val queue=ApplicationPackageRefreshQueue()
        queue.offer(1,"old.app",true)
        val oldWorker=queue.start(1)
        val oldRequest=queue.take(oldWorker)!!
        assertTrue(queue.offer(2,"new.app",true))
        val newWorker=queue.start(2)
        assertFalse(queue.retry(oldRequest))
        assertFalse(queue.finish(oldWorker))
        assertNull(queue.take(oldWorker))
        assertEquals("new.app",queue.take(newWorker)!!.packageName)
    }

    @Test fun retiredWorkerCannotClearNewWorkInSameSession() {
        val queue=ApplicationPackageRefreshQueue()
        queue.offer(1,"first.app",false)
        val retired=queue.start(1)
        assertTrue(queue.finish(retired))
        assertFalse(queue.offer(1,"second.app",true))
        val replacement=queue.start(1)
        assertFalse(queue.finish(retired))
        assertEquals("second.app",queue.take(replacement)!!.packageName)
        queue.clear()
        assertNull(queue.take(replacement))
        assertFalse(queue.finish(replacement))
    }
}
