import Foundation

// All retained policy lives in Go. In particular, no callback captures an
// unretained provider, and Stop joins native bind callbacks before retiring it.
final class NativeXraySockets {
    private let lock = NSLock()
    private var handle: Int64 = -1

    func start(index: UInt32, blockIPv6: Bool) throws {
        lock.lock()
        defer { lock.unlock() }
        guard handle <= 0 else { throw NativeDNSGuard.StartError.unavailable }
        let started = AmneziaNativeXraySocketsStart(index, blockIPv6 ? 1 : 0)
        guard started > 0 else { throw NativeDNSGuard.StartError.unavailable }
        handle = started
    }

    func update(index: UInt32) {
        lock.lock()
        defer { lock.unlock() }
        if handle > 0 { AmneziaNativeXraySocketsUpdate(handle, index) }
    }

    func stop() {
        lock.lock()
        defer { lock.unlock() }
        if handle > 0 {
            AmneziaNativeXraySocketsStop(handle)
            handle = -1
        }
    }
}
