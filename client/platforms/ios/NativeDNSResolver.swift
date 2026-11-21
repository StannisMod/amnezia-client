import Foundation
import Network
import NetworkExtension
import Darwin

enum NativeDNSResolverError: Error {
    case invalidServer, scopeUnavailable, timedOut, invalidReply, closed
}

// Resolver scope is supplied by the connection's original DNS/routing policy.
// No default-network or alternate-resolver fallback exists.
final class NativeDNSResolver {
    enum Scope {
        case tunnel
        case interface(Network.NWInterface)
        case loopback
    }

    private weak var provider: NEPacketTunnelProvider?
    private let server: String
    private let scope: Scope

    // This resolver belongs to the IPv6-OFF DNS frontend, not the ON path.
    // DNS transport gets no IPv6 exception, even for a tunnel-scoped server.
    static func validateIPv4Server(_ server: String) throws -> in_addr {
        guard !server.isEmpty, !server.utf8.contains(0) else {
            throw NativeDNSResolverError.invalidServer
        }
        if server.contains(":") { throw NativeDNSResolverError.scopeUnavailable }
        var address = in_addr()
        guard server.withCString({ inet_pton(AF_INET, $0, &address) }) == 1 else {
            throw NativeDNSResolverError.invalidServer
        }
        let unicast = withUnsafeBytes(of: address.s_addr) { bytes in
            bytes[0] != 0 && bytes[0] < 224
        }
        guard unicast else { throw NativeDNSResolverError.invalidServer }
        return address
    }

    init(provider: NEPacketTunnelProvider, server: String, scope: Scope) throws {
        let address = try Self.validateIPv4Server(server)
        if case .loopback = scope {
            guard withUnsafeBytes(of: address.s_addr, { $0[0] == 127 }) else {
                throw NativeDNSResolverError.invalidServer
            }
        }
        self.provider = provider
        self.server = server
        self.scope = scope
    }

    func exchange(_ query: Data, transport: NativeDNSTransport, timeout: TimeInterval,
                  completion: @escaping (Result<Data, Error>) -> Void) throws -> NativeDNSOperation {
        guard query.count >= 12, query.count <= 65535, timeout > 0, timeout <= 5,
              let provider else { throw NativeDNSResolverError.scopeUnavailable }
        switch scope {
        case .interface(let interface):
            return NativeDNSNetworkOperation(server: server, interface: interface, query: query,
                                             transport: transport, timeout: timeout, completion: completion)
        case .loopback:
            return NativeDNSNetworkOperation(server: server, interface: nil, query: query,
                                             transport: transport, timeout: timeout, completion: completion)
        case .tunnel:
            if #available(iOS 18.0, macOS 15.0, *) {
                guard let interface = provider.virtualInterface else { throw NativeDNSResolverError.scopeUnavailable }
                return NativeDNSNetworkOperation(server: server, interface: interface, query: query,
                                                 transport: transport, timeout: timeout, completion: completion)
            } else {
                return NativeDNSLegacyOperation(provider: provider, server: server, query: query,
                                                transport: transport, timeout: timeout, completion: completion)
            }
        }
    }
}

final class NativeDNSNetworkOperation: NativeDNSOperation {
    private let queue = DispatchQueue(label: "org.amnezia.native-dns-network")
    private let key = DispatchSpecificKey<Bool>()
    private let connection: Network.NWConnection
    private let query: Data
    private let transport: NativeDNSTransport
    private let completion: (Result<Data, Error>) -> Void
    private var timeout: DispatchWorkItem?
    private var retry: DispatchWorkItem?
    private var started = false
    private var finished = false
    private var attempts = 0

    init(server: String, interface: Network.NWInterface?, port: UInt16 = 53, query: Data, transport: NativeDNSTransport,
         timeout: TimeInterval, completion: @escaping (Result<Data, Error>) -> Void) {
        precondition(port > 0)
        let parameters = transport == .udp ? Network.NWParameters.udp : Network.NWParameters.tcp
        parameters.requiredInterface = interface
        self.connection = Network.NWConnection(host: Network.NWEndpoint.Host(server),
                                               port: Network.NWEndpoint.Port(rawValue: port)!, using: parameters)
        self.query = query
        self.transport = transport
        self.completion = completion
        queue.setSpecific(key: key, value: true)
        let deadline = DispatchTime.now() + timeout
        let timer = DispatchWorkItem { [weak self] in self?.fail(NativeDNSResolverError.timedOut) }
        self.timeout = timer
        connection.stateUpdateHandler = { [weak self] state in
            guard let self, !self.finished else { return }
            switch state {
            case .ready:
                guard !self.started else { return }
                self.started = true
                if self.transport == .udp {
                    self.receiveUDP()
                    self.sendUDP()
                } else {
                    self.sendTCP()
                }
            case .failed(let error): self.fail(error)
            case .cancelled: self.fail(NativeDNSResolverError.closed)
            default: break
            }
        }
        queue.asyncAfter(deadline: deadline, execute: timer)
        queue.async { [weak self] in
            guard let self, !self.finished else { return }
            guard DispatchTime.now() < deadline else { self.fail(NativeDNSResolverError.timedOut); return }
            self.connection.start(queue: self.queue)
        }
    }

    private func sendUDP() {
        guard !finished, attempts < 3 else { return }
        guard case .ready = connection.state else { scheduleRetry(); return }
        attempts += 1
        connection.send(content: query, completion: .contentProcessed { [weak self] error in
            guard let self, !self.finished else { return }
            if let error { self.fail(error) } else { self.scheduleRetry() }
        })
    }

    private func scheduleRetry() {
        // Retransmit ordinary queries only, on this exact connection/path.
        guard !finished, attempts < 3, query[query.startIndex + 2] & 0x78 == 0 else { return }
        let work = DispatchWorkItem { [weak self] in self?.sendUDP() }
        retry = work
        queue.asyncAfter(deadline: .now() + 1, execute: work)
    }

    private func receiveUDP() {
        connection.receiveMessage { [weak self] data, _, _, error in
            guard let self, !self.finished else { return }
            if let data { self.completion(.success(data)) }
            if let error { self.fail(error) } else { self.receiveUDP() }
        }
    }

    private func sendTCP() {
        var frame = Data([UInt8(query.count >> 8), UInt8(query.count & 255)])
        frame.append(query)
        connection.send(content: frame, completion: .contentProcessed { [weak self] error in
            guard let self, !self.finished else { return }
            if let error { self.fail(error) } else { self.readTCPHeader() }
        })
    }

    private func readTCPHeader() {
        connection.receive(minimumIncompleteLength: 2, maximumLength: 2) { [weak self] data, _, _, error in
            guard let self, !self.finished else { return }
            guard error == nil, let data, data.count == 2 else {
                self.fail((error as Error?) ?? NativeDNSResolverError.closed); return
            }
            let bytes = Array(data)
            let size = Int(bytes[0]) * 256 + Int(bytes[1])
            guard size >= 12 else { self.fail(NativeDNSResolverError.invalidReply); return }
            self.connection.receive(minimumIncompleteLength: size, maximumLength: size) { [weak self] data, _, _, error in
                guard let self, !self.finished else { return }
                guard error == nil, let data, data.count == size else {
                    self.fail((error as Error?) ?? NativeDNSResolverError.closed); return
                }
                self.completion(.success(data))
                self.readTCPHeader()
            }
        }
    }

    private func cleanup() {
        finished = true
        timeout?.cancel(); timeout = nil
        retry?.cancel(); retry = nil
        connection.stateUpdateHandler = nil
        connection.cancel()
    }

    private func fail(_ error: Error) {
        guard !finished else { return }
        cleanup()
        completion(.failure(error))
    }

    func cancel() {
        if DispatchQueue.getSpecific(key: key) != nil {
            if !finished { cleanup() }
        } else {
            queue.sync { if !finished { cleanup() } }
        }
    }
}

// Only used below the availability of NEPacketTunnelProvider.virtualInterface.
// The deprecated API is the public, explicit through-tunnel API on those OSes.
@available(iOS, introduced: 9.0, deprecated: 18.0)
@available(macOS, introduced: 10.11, deprecated: 15.0)
private final class NativeDNSLegacyOperation: NativeDNSOperation {
    private let queue = DispatchQueue(label: "org.amnezia.native-dns-legacy")
    private let key = DispatchSpecificKey<Bool>()
    private let query: Data
    private let completion: (Result<Data, Error>) -> Void
    private var udp: NWUDPSession?
    private var tcp: NWTCPConnection?
    private var observation: NSKeyValueObservation?
    private var timeout: DispatchWorkItem?
    private var retry: DispatchWorkItem?
    private var finished = false
    private var started = false
    private var attempts = 0

    init(provider: NEPacketTunnelProvider, server: String, query: Data, transport: NativeDNSTransport,
         timeout: TimeInterval, completion: @escaping (Result<Data, Error>) -> Void) {
        self.query = query
        self.completion = completion
        queue.setSpecific(key: key, value: true)
        let deadline = DispatchTime.now() + timeout
        let timer = DispatchWorkItem { [weak self] in self?.fail(NativeDNSResolverError.timedOut) }
        self.timeout = timer
        queue.asyncAfter(deadline: deadline, execute: timer)
        queue.async { [weak self, weak provider] in
            guard let self, !self.finished else { return }
            guard let provider else { self.fail(NativeDNSResolverError.scopeUnavailable); return }
            guard DispatchTime.now() < deadline else { self.fail(NativeDNSResolverError.timedOut); return }
            let endpoint = NWHostEndpoint(hostname: server, port: "53")
            if transport == .udp {
                let session = provider.createUDPSessionThroughTunnel(to: endpoint, from: nil)
                self.udp = session
                session.setReadHandler({ [weak self] packets, error in
                    guard let self else { return }
                    self.queue.async {
                        guard !self.finished else { return }
                        for packet in packets ?? [] { self.completion(.success(packet)) }
                        if let error { self.fail(error) }
                    }
                }, maxDatagrams: 1)
                self.observation = session.observe(\.state, options: [.initial, .new]) { [weak self] session, _ in
                    guard let self else { return }
                    self.queue.async {
                        guard !self.finished else { return }
                        if session.state == .ready, !self.started { self.started = true; self.sendUDP() }
                        else if session.state == .failed || session.state == .cancelled {
                            self.fail(NativeDNSResolverError.closed)
                        }
                    }
                }
            } else {
                let connection = provider.createTCPConnectionThroughTunnel(to: endpoint, enableTLS: false,
                                                                           tlsParameters: nil, delegate: nil)
                self.tcp = connection
                self.observation = connection.observe(\.state, options: [.initial, .new]) { [weak self] connection, _ in
                    guard let self else { return }
                    self.queue.async {
                        guard !self.finished else { return }
                        if connection.state == .connected, !self.started {
                            self.started = true; self.sendTCP()
                        } else if connection.state == .disconnected || connection.state == .cancelled {
                            self.fail(NativeDNSResolverError.closed)
                        }
                    }
                }
            }
        }
    }

    private func sendUDP() {
        guard !finished, attempts < 3, let udp else { return }
        guard udp.state == .ready else { scheduleRetry(); return }
        attempts += 1
        udp.writeDatagram(query) { [weak self] error in
            guard let self else { return }
            self.queue.async {
                guard !self.finished else { return }
                if let error { self.fail(error) } else { self.scheduleRetry() }
            }
        }
    }

    private func scheduleRetry() {
        guard !finished, attempts < 3, query[query.startIndex + 2] & 0x78 == 0 else { return }
        let work = DispatchWorkItem { [weak self] in self?.sendUDP() }
        retry = work
        queue.asyncAfter(deadline: .now() + 1, execute: work)
    }

    private func sendTCP() {
        var frame = Data([UInt8(query.count >> 8), UInt8(query.count & 255)])
        frame.append(query)
        tcp?.write(frame) { [weak self] error in
            guard let self else { return }
            self.queue.async {
                guard !self.finished else { return }
                if let error { self.fail(error) } else { self.readTCPHeader() }
            }
        }
    }

    private func readTCPHeader() {
        tcp?.readMinimumLength(2, maximumLength: 2) { [weak self] data, error in
            guard let self else { return }
            self.queue.async {
                guard !self.finished else { return }
                guard error == nil, let data, data.count == 2 else {
                    self.fail(error ?? NativeDNSResolverError.closed); return
                }
                let bytes = Array(data)
                let size = Int(bytes[0]) * 256 + Int(bytes[1])
                guard size >= 12 else { self.fail(NativeDNSResolverError.invalidReply); return }
                self.tcp?.readMinimumLength(size, maximumLength: size) { [weak self] data, error in
                    guard let self else { return }
                    self.queue.async {
                        guard !self.finished else { return }
                        guard error == nil, let data, data.count == size else {
                            self.fail(error ?? NativeDNSResolverError.closed); return
                        }
                        self.completion(.success(data))
                        self.readTCPHeader()
                    }
                }
            }
        }
    }

    private func cleanup() {
        finished = true
        timeout?.cancel(); timeout = nil
        retry?.cancel(); retry = nil
        observation?.invalidate(); observation = nil
        udp?.cancel(); udp = nil
        tcp?.cancel(); tcp = nil
    }

    private func fail(_ error: Error) {
        guard !finished else { return }
        cleanup()
        completion(.failure(error))
    }

    func cancel() {
        if DispatchQueue.getSpecific(key: key) != nil {
            if !finished { cleanup() }
        } else {
            queue.sync { if !finished { cleanup() } }
        }
    }
}
