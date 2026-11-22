import Foundation
import NetworkExtension

// One native packet-flow reader remains owned by the original adapter. This
// controller only dispatches its reserved DNS endpoints, and serializes settings
// publication with preparation, rollback, generation retirement and Stop.
final class NativeDNSController {
    typealias Publish = (NEPacketTunnelNetworkSettings, @escaping (Error?) -> Void) -> Void
    enum ControllerError: Error { case stopped, publicationTimedOut }
    private let queue = DispatchQueue(label: "org.amnezia.native-dns-settings")
    private let packets = NSLock()
    private var connections: [Connection] = []
    private var reserved: Set<UInt32> = []
    private var stopped = true
    private var epoch: UInt64 = 0
    private var applying = false
    private var pending: [() -> Void] = []
    private let retirement = DispatchGroup()
    private let publicationTimeout: TimeInterval
    private final class Publication { var finished = false }

    init(publicationTimeout: TimeInterval = 4) {
        // The native WireGuard adapter waits five seconds before proceeding.
        // Return failure first; never let that timeout start an unconfigured
        // OFF tunnel or stall all future settings updates indefinitely.
        precondition(publicationTimeout > 0 && publicationTimeout <= 4)
        self.publicationTimeout = publicationTimeout
    }

    func start() {
        queue.async {
            self.epoch &+= 1
            self.stopped = false
        }
    }

    func apply(original: NEPacketTunnelNetworkSettings, blocked: Bool,
               paths: @escaping () throws -> [String: NativeDNSSettings.Path],
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
                    var newlyPrepared = false
                    var settings = original
                    if blocked {
                        let selected = try paths()
                        self.packets.lock()
                        let occupied = Set(self.connections.flatMap { $0.addresses })
                        let existing = self.connections.last
                        self.packets.unlock()
                        if let existing, existing.matches(original, paths: selected),
                           let plan = try? NativeDNSSettings(original: original, paths: selected,
                               occupied: occupied.subtracting(existing.addresses), captures: existing.orderedAddresses) {
                            // Endpoint/path refreshes with unchanged DNS must not
                            // reset established DNS TCP sessions needlessly.
                            connection = existing
                            settings = plan.settings
                        } else {
                            let plan = try NativeDNSSettings(original: original, paths: selected, occupied: occupied)
                            connection = try Connection(plan: plan, writer: writer, exchange: exchange, failure: failure)
                            newlyPrepared = true
                            settings = plan.settings
                        }
                    }
                    self.packets.lock()
                    if let connection, newlyPrepared {
                        self.connections.append(connection)
                        self.reserved.formUnion(connection.targets)
                    }
                    self.packets.unlock()
                    let prepared = connection
                    let staged = newlyPrepared
                    let publication = Publication()
                    let finish: (Error?, Bool) -> Void = { error, timedOut in
                        guard !publication.finished else { return }
                        publication.finished = true
                        let current = !self.stopped && self.epoch == epoch
                        self.packets.lock()
                        let retired: [Connection]
                        if timedOut && current {
                            self.stopped = true
                            self.epoch &+= 1
                            retired = self.connections
                            self.connections.removeAll()
                        } else if error == nil && current {
                            retired = self.connections.filter { $0 !== prepared }
                            self.connections = prepared.map { [$0] } ?? []
                            if !blocked { self.reserved.removeAll() }
                        } else {
                            retired = staged ? (prepared.map { [$0] } ?? []) : []
                            if staged { self.connections.removeAll { $0 === prepared } }
                        }
                        self.packets.unlock()
                        self.retire(retired) { self.next() }
                        if timedOut && current { failure() }
                        // Wake the adapter before its five-second fallback;
                        // Stop separately joins cleanup of all generations.
                        completion(current ? error : ControllerError.stopped)
                    }
                    let timer = DispatchWorkItem { finish(ControllerError.publicationTimedOut, true) }
                    if blocked {
                        self.queue.asyncAfter(deadline: .now() + self.publicationTimeout, execute: timer)
                    }
                    publish(settings) { error in
                        self.queue.async {
                            timer.cancel()
                            finish(error, false)
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
        let owner = connections.reversed().first { $0.targets.contains(destination) }
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
            self.retire(retired) {
                self.retirement.notify(queue: self.queue) { completion() }
            }
        }
    }

    private func retire(_ connections: [Connection], completion: @escaping () -> Void) {
        let group = DispatchGroup()
        for connection in connections {
            group.enter()
            retirement.enter()
            connection.stop {
                group.leave()
                self.retirement.leave()
            }
        }
        group.notify(queue: queue) { completion() }
    }

    private static func destination(_ packet: Data) -> UInt32? {
        guard packet.count >= 20, packet[packet.startIndex] >> 4 == 4 else { return nil }
        let base = packet.startIndex
        return UInt32(packet[base + 16]) << 24 | UInt32(packet[base + 17]) << 16 |
            UInt32(packet[base + 18]) << 8 | UInt32(packet[base + 19])
    }

    private final class Connection {
        let addresses: Set<String>
        let orderedAddresses: [String]
        private let upstreams: [String]
        private let sourceAddresses: [String]
        private let paths: [NativeDNSSettings.Path]
        let targets: Set<UInt32>
        private let guards: [UInt32: NativeDNSGuard]
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
            let mapped = Dictionary(uniqueKeysWithValues: prepared.map { address, guardDNS in
                let key = address.split(separator: ".").reduce(UInt32(0)) { ($0 << 8) | UInt32($1)! }
                return (key, guardDNS)
            })
            guards = mapped
            targets = Set(mapped.keys)
            addresses = Set(prepared.keys)
            orderedAddresses = plan.bindings.map(\.address)
            upstreams = plan.bindings.map(\.upstream)
            sourceAddresses = plan.settings.ipv4Settings?.addresses ?? []
            paths = plan.bindings.map(\.path)
        }
        func matches(_ original: NEPacketTunnelNetworkSettings, paths requested: [String: NativeDNSSettings.Path]) -> Bool {
            let selected = upstreams.map { server -> NativeDNSSettings.Path in
                if server.contains(":") { return .unavailable }
                if server.hasPrefix("127.") { return .loopback }
                return requested[server] ?? .unavailable
            }
            return original.dnsSettings?.servers == upstreams &&
                original.ipv4Settings?.addresses == sourceAddresses && selected == paths
        }
        func feed(_ packet: Data, destination: UInt32) -> NativeDNSGuard.Disposition {
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
