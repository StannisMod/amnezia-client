import Foundation
import NetworkExtension

// One native packet-flow reader remains owned by the original adapter. This
// controller only dispatches its reserved DNS endpoints, and serializes settings
// publication with preparation, rollback, generation retirement and Stop.
final class NativeDNSController {
    typealias Publish = (NEPacketTunnelNetworkSettings, @escaping (Error?) -> Void) -> Void
    enum ControllerError: Error { case stopped }
    private let queue = DispatchQueue(label: "org.amnezia.native-dns-settings")
    private let packets = NSLock()
    private var connections: [Connection] = []
    private var reserved: Set<String> = []
    private var stopped = true
    private var epoch: UInt64 = 0
    private var applying = false
    private var pending: [() -> Void] = []

    func start() {
        queue.async {
            self.epoch &+= 1
            self.stopped = false
        }
    }

    func apply(original: NEPacketTunnelNetworkSettings, blocked: Bool,
               writer: @escaping (Data) -> Bool,
               exchange: @escaping (NativeDNSSettings.Binding, [String]) -> NativeDNSExchange,
               failure: @escaping () -> Void, publish: @escaping Publish,
               completion: @escaping (Error?) -> Void) {
        queue.async {
            let epoch = self.epoch
            self.pending.append {
                guard !self.stopped, self.epoch == epoch else {
                    completion(ControllerError.stopped)
                    self.next()
                    return
                }
                do {
                    var connection: Connection?
                    var settings = original
                    if blocked {
                        let servers = original.dnsSettings?.servers ?? []
                        let paths = Dictionary(servers.map { ($0, NativeDNSSettings.Path.native) },
                                               uniquingKeysWith: { first, _ in first })
                        self.packets.lock()
                        let occupied = Set(self.connections.flatMap { $0.addresses })
                        self.packets.unlock()
                        let plan = try NativeDNSSettings(original: original, paths: paths, occupied: occupied)
                        connection = try Connection(plan: plan, writer: writer, exchange: exchange, failure: failure)
                        settings = plan.settings
                    }
                    self.packets.lock()
                    if let connection {
                        self.connections.append(connection)
                        self.reserved.formUnion(connection.addresses)
                    }
                    self.packets.unlock()
                    let prepared = connection
                    publish(settings) { error in
                        self.queue.async {
                            let current = !self.stopped && self.epoch == epoch
                            self.packets.lock()
                            let retired: [Connection]
                            if error == nil && current {
                                retired = self.connections.filter { $0 !== prepared }
                                self.connections = prepared.map { [$0] } ?? []
                                if !blocked { self.reserved.removeAll() }
                            } else {
                                retired = prepared.map { [$0] } ?? []
                                self.connections.removeAll { $0 === prepared }
                            }
                            self.packets.unlock()
                            self.retire(retired) {
                                completion(current ? error : ControllerError.stopped)
                                self.next()
                            }
                        }
                    }
                } catch {
                    completion(error)
                    self.next()
                }
            }
            self.run()
        }
    }

    private func run() {
        guard !applying, !pending.isEmpty else { return }
        applying = true
        pending.removeFirst()()
    }

    private func next() {
        applying = false
        run()
    }

    // True means native code must not receive the packet, including on failure.
    func intercept(_ packet: Data) -> Bool {
        guard let destination = Self.destination(packet) else { return false }
        packets.lock()
        let owner = connections.reversed().first { $0.addresses.contains(destination) }
        let captured = reserved.contains(destination)
        packets.unlock()
        if let owner { _ = owner.feed(packet, destination: destination); return true }
        return captured
    }

    func stop(completion: @escaping () -> Void) {
        queue.async {
            self.stopped = true
            self.epoch &+= 1
            self.packets.lock()
            let retired = self.connections
            self.connections.removeAll()
            self.packets.unlock()
            self.retire(retired, completion: completion)
        }
    }

    private func retire(_ connections: [Connection], completion: @escaping () -> Void) {
        let group = DispatchGroup()
        for connection in connections {
            group.enter()
            connection.stop { group.leave() }
        }
        group.notify(queue: queue) { completion() }
    }

    private static func destination(_ packet: Data) -> String? {
        guard packet.count >= 20, packet[packet.startIndex] >> 4 == 4 else { return nil }
        let base = packet.startIndex
        return (16..<20).map { String(packet[base + $0]) }.joined(separator: ".")
    }

    private final class Connection {
        let addresses: Set<String>
        private let guards: [String: NativeDNSGuard]
        init(plan: NativeDNSSettings, writer: @escaping (Data) -> Bool,
             exchange: (NativeDNSSettings.Binding, [String]) -> NativeDNSExchange,
             failure: @escaping () -> Void) throws {
            var prepared: [String: NativeDNSGuard] = [:]
            do {
                for binding in plan.bindings {
                    let forward: NativeDNSExchange
                    if binding.path == .unavailable {
                        forward = { _, _, _, _ in throw NativeDNSResolverError.scopeUnavailable }
                    } else {
                        forward = exchange(binding, plan.settings.ipv4Settings?.addresses ?? [])
                    }
                    prepared[binding.address] = try NativeDNSGuard(address: binding.address, writer: writer,
                                                                   exchange: forward, failure: failure)
                }
            } catch {
                for guardDNS in prepared.values { guardDNS.stop {} }
                throw error
            }
            guards = prepared
            addresses = Set(prepared.keys)
        }
        func feed(_ packet: Data, destination: String) -> NativeDNSGuard.Disposition {
            guards[destination]?.feed(packet) ?? .failed
        }
        func stop(completion: @escaping () -> Void) {
            let group = DispatchGroup()
            for guardDNS in guards.values {
                group.enter()
                guardDNS.stop { group.leave() }
            }
            group.notify(queue: .global()) { completion() }
        }
    }
}
