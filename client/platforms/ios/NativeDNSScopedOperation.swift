import Foundation
import Network
import NetworkExtension

// Route lookup runs outside the guard's callback queue. Stop can invalidate an
// operation even while it is queued or the bounded local kernel lookup runs.
final class NativeDNSScopedOperation: NativeDNSOperation {
    private static let lookupQueue = DispatchQueue(label: "org.amnezia.native-dns-route")
    private let lock = NSLock()
    private var cancelled = false
    private var inner: NativeDNSOperation?

    init(provider: NEPacketTunnelProvider, server: String, tunnelAddresses: [String],
         interface: @escaping (UInt32) -> Network.NWInterface?,
         query: Data, transport: NativeDNSTransport, timeout: TimeInterval,
         completion: @escaping (Result<Data, Error>) -> Void) throws {
        _ = try NativeDNSResolver.validateIPv4Server(server)
        let deadline = DispatchTime.now() + timeout
        Self.lookupQueue.async { [self, weak provider] in
            lock.lock()
            let invalid = cancelled
            lock.unlock()
            guard !invalid else { return }
            do {
                guard let provider else { throw NativeDNSResolverError.scopeUnavailable }
                let index = try NativeDNSRoute.interfaceIndex(server: server)
                let scope: NativeDNSResolver.Scope
                if server.hasPrefix("127.") {
                    scope = .loopback
                } else if #available(iOS 18.0, macOS 15.0, *), let virtual = provider.virtualInterface {
                    if UInt32(virtual.index) == index {
                        scope = .tunnel
                    } else if let physical = interface(index) {
                        scope = .interface(physical)
                    } else { throw NativeDNSResolverError.scopeUnavailable }
                } else if NativeDNSRoute.interfaceOwnsIPv4(index: index, addresses: tunnelAddresses) {
                    scope = .tunnel
                } else if let physical = interface(index) {
                    scope = .interface(physical)
                } else { throw NativeDNSResolverError.scopeUnavailable }
                let now = DispatchTime.now().uptimeNanoseconds
                guard now < deadline.uptimeNanoseconds else { throw NativeDNSResolverError.timedOut }
                let remaining = TimeInterval(deadline.uptimeNanoseconds - now) / 1_000_000_000
                let resolver = try NativeDNSResolver(provider: provider, server: server, scope: scope)
                lock.lock()
                defer { lock.unlock() }
                guard !cancelled else { return }
                inner = try resolver.exchange(query, transport: transport, timeout: remaining, completion: completion)
            } catch {
                lock.lock()
                let deliver = !cancelled
                lock.unlock()
                if deliver { completion(.failure(error)) }
            }
        }
    }

    func cancel() {
        lock.lock()
        cancelled = true
        let operation = inner
        inner = nil
        lock.unlock()
        operation?.cancel()
    }
}
