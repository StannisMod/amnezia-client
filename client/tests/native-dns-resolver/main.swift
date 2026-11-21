import Foundation
import Network

func require(_ value: @autoclosure () -> Bool, _ message: String) {
    if !value() { fatalError(message) }
}

final class Record {
    let lock = NSCondition()
    var connections = 0
    var queries = 0
    var replies: [Data] = []
    var errors = 0
    func update(_ body: (Record) -> Void) {
        lock.lock(); body(self); lock.broadcast(); lock.unlock()
    }
    func read<T>(_ body: (Record) -> T) -> T {
        lock.lock(); defer { lock.unlock() }; return body(self)
    }
    func wait(_ predicate: (Record) -> Bool) {
        let until = Date().addingTimeInterval(6)
        lock.lock(); defer { lock.unlock() }
        while !predicate(self) { require(lock.wait(until: until), "native DNS resolver event timeout") }
    }
}

final class Fixture {
    enum Mode { case dropFirst, dropAll, tcpCandidates }
    let listener: NWListener
    let state = Record()
    private let queue = DispatchQueue(label: "native-dns-resolver-fixture")
    private var connections: [NWConnection] = []
    private let mode: Mode
    private let ready = DispatchSemaphore(value: 0)
    init(_ transport: NativeDNSTransport, mode: Mode) throws {
        self.mode = mode
        let parameters = transport == .udp ? NWParameters.udp : NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        listener = try NWListener(using: parameters)
        listener.stateUpdateHandler = { [weak self] state in
            if case .ready = state { self?.ready.signal() }
            if case .failed(let error) = state { fatalError("loopback DNS listener failed: \(error)") }
        }
        listener.newConnectionHandler = { [weak self] connection in
            guard let self else { connection.cancel(); return }
            self.connections.append(connection)
            self.state.update { $0.connections += 1 }
            connection.start(queue: self.queue)
            if transport == .udp { self.receiveUDP(connection) }
            else { self.receiveTCP(connection) }
        }
        listener.start(queue: queue)
        require(ready.wait(timeout: .now() + 5) == .success, "loopback listener not ready")
    }

    var port: UInt16 { listener.port!.rawValue }

    private func answer(_ query: Data, wrong: Bool = false) -> Data {
        var wire = Data(query)
        if wrong { wire[0] ^= 1 }
        wire[2] |= 0x80
        wire[3] = 0x80
        return wire
    }

    private func receiveUDP(_ connection: NWConnection) {
        connection.receiveMessage { [weak self] data, _, _, error in
            guard let self, error == nil, let data else { return }
            self.state.update { $0.queries += 1 }
            if self.mode == .dropFirst && self.state.read({ $0.queries }) > 1 {
                connection.send(content: self.answer(data), completion: .contentProcessed { _ in })
            }
            self.receiveUDP(connection)
        }
    }

    private func receiveTCP(_ connection: NWConnection) {
        connection.receive(minimumIncompleteLength: 2, maximumLength: 2) { [weak self] data, _, _, error in
            guard let self, error == nil, let data, data.count == 2 else { return }
            let bytes = Array(data)
            let size = Int(bytes[0]) * 256 + Int(bytes[1])
            connection.receive(minimumIncompleteLength: size, maximumLength: size) { [weak self] data, _, _, error in
                guard let self, error == nil, let data, data.count == size else { return }
                self.state.update { $0.queries += 1 }
                guard self.mode == .tcpCandidates else { return }
                var reply = Data()
                for wrong in [true, false] {
                    let answer = self.answer(data, wrong: wrong)
                    reply.append(contentsOf: [UInt8(answer.count >> 8), UInt8(answer.count & 255)])
                    reply.append(answer)
                }
                // Split the first length prefix across writes; the receiver
                // must then handle two framed candidates on the same stream.
                let first = Data(reply.prefix(1)), rest = Data(reply.dropFirst(1))
                connection.send(content: first, completion: .contentProcessed { [weak self] error in
                    guard let self, error == nil else { return }
                    self.queue.asyncAfter(deadline: .now() + 0.01) {
                        connection.send(content: rest, completion: .contentProcessed { _ in })
                    }
                })
            }
        }
    }

    func close() {
        queue.sync {
            listener.cancel()
            for connection in connections { connection.cancel() }
            connections.removeAll()
        }
    }
}

let query = Data([0x12,0x34,0x01,0x00,0x00,0x01,0,0,0,0,0,0,7] +
    Array("managed".utf8) + [7] + Array("example".utf8) + [0,0,1,0,1])

for server in ["2001:db8::53", "fe80::53%en0", "::1", "::ffff:192.0.2.53"] {
    do {
        _ = try NativeDNSResolver.validateIPv4Server(server)
        fatalError("IPv6-OFF DNS admitted IPv6 upstream \(server)")
    } catch NativeDNSResolverError.scopeUnavailable {
        // Reject before constructing a socket; there is no resolver fallback.
    }
}
for server in ["", "dns.example", "0.0.0.0", "224.0.0.53", "255.255.255.255", "192.0.2.53\u{0}.invalid"] {
    do {
        _ = try NativeDNSResolver.validateIPv4Server(server)
        fatalError("invalid DNS upstream accepted \(server)")
    } catch NativeDNSResolverError.invalidServer {}
}
for server in ["192.0.2.53", "10.0.0.53", "127.0.0.1"] {
    _ = try NativeDNSResolver.validateIPv4Server(server)
}

do {
    let fixture = try Fixture(.udp, mode: .dropFirst)
    defer { fixture.close() }
    let result = Record()
    let operation = NativeDNSNetworkOperation(server: "127.0.0.1", interface: nil, port: fixture.port,
        query: query, transport: .udp, timeout: 4) { answer in
            result.update {
                switch answer {
                case .success(let wire): $0.replies.append(wire)
                case .failure: $0.errors += 1
                }
            }
        }
    result.wait { !$0.replies.isEmpty || $0.errors > 0 }
    operation.cancel()
    require(result.read { $0.errors == 0 && $0.replies[0][0] == query[0] }, "UDP recovery lost the response")
    require(fixture.state.read { $0.connections == 1 && $0.queries == 2 }, "UDP retry changed connection or exceeded the necessary retry")
}

do {
    let fixture = try Fixture(.tcp, mode: .tcpCandidates)
    defer { fixture.close() }
    let result = Record()
    let operation = NativeDNSNetworkOperation(server: "127.0.0.1", interface: nil, port: fixture.port,
        query: query, transport: .tcp, timeout: 4) { answer in
            result.update {
                switch answer {
                case .success(let wire): $0.replies.append(wire)
                case .failure: $0.errors += 1
                }
            }
        }
    result.wait { $0.replies.count == 2 || $0.errors > 0 }
    operation.cancel()
    require(result.read { $0.errors == 0 && $0.replies.count == 2 &&
        $0.replies[0][0] != query[0] && $0.replies[1][0] == query[0] }, "TCP framing/candidate replies failed")
    require(fixture.state.read { $0.connections == 1 && $0.queries == 1 }, "TCP scope was retried/reopened")
}

for ordinaryQuery in [false, true] {
    let fixture = try Fixture(.udp, mode: .dropAll)
    defer { fixture.close() }
    var request = query
    if !ordinaryQuery { request[2] = 0x28 } // UPDATE must never be retransmitted.
    let result = Record()
    let operation = NativeDNSNetworkOperation(server: "127.0.0.1", interface: nil, port: fixture.port,
        query: request, transport: .udp, timeout: ordinaryQuery ? 3.5 : 1.5) { answer in
            result.update {
                switch answer {
                case .success(let wire): $0.replies.append(wire)
                case .failure: $0.errors += 1
                }
            }
        }
    result.wait { $0.errors > 0 }
    operation.cancel()
    require(result.read { $0.replies.isEmpty && $0.errors == 1 }, "DNS timeout did not fail closed")
    require(fixture.state.read { $0.connections == 1 && $0.queries == (ordinaryQuery ? 3 : 1) },
            "UDP retry bound or non-query semantics changed")
}

for transport in [NativeDNSTransport.udp, .tcp] {
    let fixture = try Fixture(transport, mode: .dropAll)
    defer { fixture.close() }
    let callback = DispatchSemaphore(value: 0)
    let operation = NativeDNSNetworkOperation(server: "127.0.0.1", interface: nil, port: fixture.port,
        query: query, transport: transport, timeout: 1.5) { _ in callback.signal() }
    fixture.state.wait { $0.queries == 1 }
    operation.cancel()
    operation.cancel()
    // Span both the first retransmission and the original deadline. Neither
    // may outlive cancellation or report a late failure to the stopped host.
    require(callback.wait(timeout: .now() + 2) == .timedOut, "cancelled operation delivered a callback")
    require(fixture.state.read { $0.connections == 1 && $0.queries == 1 },
            "cancelled operation retried or reopened its resolver")
}

print("PASS: native DNS loopback UDP retry, TCP framing/candidates, deadline, cancellation and non-query policy")
