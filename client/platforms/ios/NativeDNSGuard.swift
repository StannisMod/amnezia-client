import Foundation

enum NativeDNSTransport: Int32 {
    case udp = 0
    case tcp = 1
}

protocol NativeDNSOperation: AnyObject {
    // Cancels this request only, not other requests sharing its resolver.
    func cancel()
}

// The native adapter supplies one explicit resolver/path. It may deliver
// candidate replies until accepted/cancelled; it must never select a fallback.
typealias NativeDNSExchange = (Data, NativeDNSTransport, TimeInterval,
                              @escaping (Result<Data, Error>) -> Void) throws -> NativeDNSOperation

// One managed-DNS endpoint; no packetFlow reader or application flow proxy.
// The connection owner must stop it before dropping its last reference.
final class NativeDNSGuard {
    enum Disposition: Int32 { case failed = -1, native = 0, dns = 1 }
    enum StartError: Error { case unavailable }

    private let queue = DispatchQueue(label: "org.amnezia.native-dns")
    private let handleLock = NSLock()
    private var handle: Int64 = -1
    private var initializing = true
    private var failedDuringStart = false
    private var stopped = false
    private var requests: [UInt64: NativeDNSOperation] = [:]
    private let writePacket: (Data) -> Bool
    private let exchange: NativeDNSExchange
    private let failure: () -> Void

    private var currentHandle: Int64 {
        handleLock.lock()
        defer { handleLock.unlock() }
        return handle
    }

    private func setHandle(_ value: Int64) {
        handleLock.lock()
        handle = value
        handleLock.unlock()
    }

    private func publishStart(_ value: Int64) -> Bool {
        handleLock.lock()
        defer { handleLock.unlock() }
        initializing = false
        guard !failedDuringStart else { return false }
        handle = value
        return true
    }

    private func recordFailure(_ value: Int64) -> Bool {
        handleLock.lock()
        defer { handleLock.unlock() }
        if initializing {
            failedDuringStart = true
            return false
        }
        return handle == value
    }

    private static let writer: AmneziaPacketWriter = { context, bytes, size in
        guard let context, let bytes, size > 0, size <= 65535 else { return 0 }
        let owner = Unmanaged<NativeDNSGuard>.fromOpaque(context).takeUnretainedValue()
        return owner.writePacket(Data(bytes: bytes, count: Int(size))) ? 1 : 0
    }

    private static let dispatch: AmneziaDNSDispatch = { context, handle, token, network, bytes, size, timeout in
        guard let context, let bytes, size >= 12, size <= 65535, timeout > 0,
              let transport = NativeDNSTransport(rawValue: network) else { return 0 }
        let owner = Unmanaged<NativeDNSGuard>.fromOpaque(context).takeUnretainedValue()
        let query = Data(bytes: bytes, count: Int(size))
        owner.queue.async {
            owner.begin(handle: handle, token: token, query: query, transport: transport,
                        timeout: TimeInterval(timeout) / 1000)
        }
        return 1
    }

    private static let cancel: AmneziaDNSCancel = { context, handle, token in
        guard let context else { return }
        let owner = Unmanaged<NativeDNSGuard>.fromOpaque(context).takeUnretainedValue()
        owner.queue.async {
            guard owner.currentHandle == handle else { return }
            owner.requests.removeValue(forKey: token)?.cancel()
        }
    }

    private static let failed: AmneziaDNSFailure = { context, handle in
        guard let context else { return }
        let owner = Unmanaged<NativeDNSGuard>.fromOpaque(context).takeUnretainedValue()
        guard owner.recordFailure(handle) else { return }
        // Never call native Stop inline from a native callback.
        owner.queue.async {
            guard !owner.stopped, owner.currentHandle == handle else { return }
            owner.failure()
        }
    }

    private static let release: AmneziaHostRelease = { context in
        if let context { Unmanaged<NativeDNSGuard>.fromOpaque(context).release() }
    }

    init(address: String, writer: @escaping (Data) -> Bool, exchange: @escaping NativeDNSExchange,
         failure: @escaping () -> Void) throws {
        self.writePacket = writer
        self.exchange = exchange
        self.failure = failure
        let context = Unmanaged.passRetained(self).toOpaque()
        // Start consumes the retained context even on failure.
        let started = address.withCString {
            AmneziaNativeDNSStart(UnsafeMutablePointer(mutating: $0), context, Self.writer,
                                 Self.dispatch, Self.cancel, Self.failed, Self.release)
        }
        guard started > 0 else { throw StartError.unavailable }
        guard publishStart(started) else {
            AmneziaNativeDNSStop(started)
            throw StartError.unavailable
        }
    }

    func feed(_ packet: Data) -> Disposition {
        let handle = currentHandle
        guard handle > 0, !packet.isEmpty, packet.count <= 65535 else { return .failed }
        return packet.withUnsafeBytes { raw in
            let result = AmneziaNativeDNSFeed(handle,
                UnsafeMutablePointer(mutating: raw.bindMemory(to: UInt8.self).baseAddress),
                Int32(packet.count))
            return Disposition(rawValue: result) ?? .failed
        }
    }

    private func begin(handle: Int64, token: UInt64, query: Data,
                       transport: NativeDNSTransport, timeout: TimeInterval) {
        guard !stopped, currentHandle == handle else { return }
        guard requests[token] == nil else {
            requests.removeValue(forKey: token)?.cancel()
            _ = AmneziaNativeDNSReject(handle, token)
            return
        }
        do {
            let operation = try exchange(query, transport, timeout) { [weak self] result in
                guard let self else { return }
                self.queue.async { self.finish(handle: handle, token: token, result: result) }
            }
            requests[token] = operation
        } catch {
            _ = AmneziaNativeDNSReject(handle, token)
        }
    }

    private func finish(handle: Int64, token: UInt64, result: Result<Data, Error>) {
        guard !stopped, currentHandle == handle, let operation = requests[token] else { return }
        switch result {
        case .success(let wire):
            guard wire.count >= 12, wire.count <= 65535 else { return }
            let accepted = wire.withUnsafeBytes { raw in
                AmneziaNativeDNSComplete(handle, token,
                    UnsafeMutablePointer(mutating: raw.bindMemory(to: UInt8.self).baseAddress),
                    Int32(wire.count))
            }
            // A mismatched/spurious reply does not cancel a valid pending
            // exchange; the native scope can still deliver the original reply.
            if accepted == 1 {
                requests.removeValue(forKey: token)
                operation.cancel()
            }
        case .failure:
            requests.removeValue(forKey: token)
            operation.cancel()
            _ = AmneziaNativeDNSReject(handle, token)
        }
    }

    func stop(completion: @escaping () -> Void) {
        queue.async {
            guard !self.stopped else { completion(); return }
            self.stopped = true
            let handle = self.currentHandle
            self.setHandle(-1)
            let pending = Array(self.requests.values)
            self.requests.removeAll()
            for request in pending { request.cancel() }
            if handle > 0 { AmneziaNativeDNSStop(handle) }
            completion()
        }
    }
}
