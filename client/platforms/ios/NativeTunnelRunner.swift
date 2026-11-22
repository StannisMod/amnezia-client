import Foundation

// Readiness and Stop belong to the same native run. In particular, an early
// Stop must not be sent to an uninitialized backend or complete before its
// reader has returned. No polling or sleeps are used.
final class NativeTunnelRunner {
    enum RunError: Error { case alreadyRunning, stopped, backend(Int32), unexpectedExit }
    private struct Session {
        let id: UInt64
        let started: (Error?) -> Void
        let exited: (Error?) -> Void
        let quit: () -> Void
        var ready = false
        var stopping = false
        var quitSent = false
        var startCompleted = false
        var stops: [() -> Void] = []
    }
    private let lock = NSLock()
    private var session: Session?
    private var next: UInt64 = 0

    func start(run: @escaping () -> Int32, quit: @escaping () -> Void,
               started: @escaping (Error?) -> Void, exited: @escaping (Error?) -> Void) {
        lock.lock()
        guard session == nil else { lock.unlock(); started(RunError.alreadyRunning); return }
        next &+= 1
        let id = next
        session = Session(id: id, started: started, exited: exited, quit: quit)
        lock.unlock()
        DispatchQueue.global().async { self.finished(id: id, result: run()) }
    }

    func ready() {
        lock.lock()
        guard var current = session, !current.ready else { lock.unlock(); return }
        current.ready = true
        current.startCompleted = true
        let quit = current.stopping && !current.quitSent ? current.quit : nil
        if quit != nil { current.quitSent = true }
        session = current
        lock.unlock()
        current.started(current.stopping ? RunError.stopped : nil)
        quit?()
    }

    func stop(completion: @escaping () -> Void) {
        lock.lock()
        guard var current = session else { lock.unlock(); completion(); return }
        current.stopping = true
        current.stops.append(completion)
        let quit = current.ready && !current.quitSent ? current.quit : nil
        if quit != nil { current.quitSent = true }
        session = current
        lock.unlock()
        quit?()
    }

    private func finished(id: UInt64, result: Int32) {
        lock.lock()
        guard let current = session, current.id == id else { lock.unlock(); return }
        session = nil
        lock.unlock()
        let error: Error? = result < 0 ? RunError.backend(result) :
            (current.stopping ? nil : RunError.unexpectedExit)
        if !current.startCompleted { current.started(current.stopping ? RunError.stopped : error) }
        current.exited(error)
        for completion in current.stops { completion() }
    }
}
