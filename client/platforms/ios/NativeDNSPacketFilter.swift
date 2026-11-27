import Foundation

// The native Go TUN reader invokes this synchronously. No second packetFlow
// reader is created. Data is a borrowed view for this callback only; retained
// DNS packets are copied by the existing DNS Feed bridge.
final class NativeDNSPacketFilter {
    private let filter: (Data) -> Bool
    private let lock = NSCondition()
    private var handle: Int64 = -1
    private var stopping = false
    private static let dispatch: AmneziaPacketFilter = { context, bytes, size in
        guard let context, let bytes, size > 0, size <= 65535 else { return 1 }
        let owner = Unmanaged<NativeDNSPacketFilter>.fromOpaque(context).takeUnretainedValue()
        let packet = Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: bytes),
                          count: Int(size), deallocator: .none)
        return owner.filter(packet) ? 1 : 0
    }
    private static let release: AmneziaHostRelease = { context in
        if let context { Unmanaged<NativeDNSPacketFilter>.fromOpaque(context).release() }
    }
    init(filter: @escaping (Data) -> Bool) throws {
        self.filter = filter
        let context = Unmanaged.passRetained(self).toOpaque()
        let started = AmneziaNativePacketFilterStart(context, Self.dispatch, Self.release)
        guard started > 0 else { throw NativeDNSGuard.StartError.unavailable }
        handle = started
    }
    // Called after stopping the native backend, never inline from dispatch.
    func stop() {
        lock.lock()
        while stopping { lock.wait() }
        let stopped = handle
        guard stopped > 0 else { lock.unlock(); return }
        handle = -1
        stopping = true
        lock.unlock()
        AmneziaNativePacketFilterStop(stopped)
        lock.lock()
        stopping = false
        lock.broadcast()
        lock.unlock()
    }
}
