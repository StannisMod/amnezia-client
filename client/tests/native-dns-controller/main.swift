import Foundation
import NetworkExtension

func require(_ condition: @autoclosure () -> Bool, _ message: String) {
    if !condition() { fatalError(message) }
}

final class State {
    let lock = NSCondition()
    var packets: [Data] = []
    var prepared: [NEPacketTunnelNetworkSettings] = []
    var replies: [(Error?) -> Void] = []
    var errors: [Bool] = []
    var exchanges = 0
    var failures = 0
    func update(_ body: (State) -> Void) {
        lock.lock(); body(self); lock.broadcast(); lock.unlock()
    }
    func read<T>(_ body: (State) -> T) -> T {
        lock.lock(); defer { lock.unlock() }; return body(self)
    }
    func wait(_ predicate: (State) -> Bool) {
        let deadline = Date().addingTimeInterval(5)
        lock.lock(); defer { lock.unlock() }
        while !predicate(self) {
            require(lock.wait(until: deadline), "native DNS controller event timeout")
        }
    }
}

func packet(address: String, id: UInt16, type: UInt16 = 28) -> Data {
    let name: [UInt8] = [7] + Array("managed".utf8) + [7] + Array("example".utf8) + [0]
    var bytes = [UInt8](repeating: 0, count: 20 + 8 + 12 + name.count + 4)
    func put(_ at: Int, _ value: Int) {
        bytes[at] = UInt8((value >> 8) & 255); bytes[at + 1] = UInt8(value & 255)
    }
    bytes[0] = 0x45; bytes[8] = 64; bytes[9] = 17
    put(2, bytes.count)
    bytes[12] = 10; bytes[13] = 77; bytes[15] = 2
    bytes.replaceSubrange(16..<20, with: address.split(separator: ".").map { UInt8($0)! })
    put(20, 40000); put(22, 53); put(24, bytes.count - 20)
    put(28, Int(id)); bytes[30] = 1; put(32, 1)
    bytes.replaceSubrange(40..<(40 + name.count), with: name)
    put(40 + name.count, Int(type)); put(42 + name.count, 1)
    var sum = stride(from: 0, to: 20, by: 2).reduce(0) { $0 + Int(bytes[$1]) * 256 + Int(bytes[$1 + 1]) }
    while sum > 65535 { sum = (sum & 65535) + (sum >> 16) }
    put(10, (~sum) & 65535)
    return Data(bytes)
}

func settings(server: String = "10.77.0.53") -> NEPacketTunnelNetworkSettings {
    let value = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "203.0.113.1")
    value.ipv4Settings = NEIPv4Settings(addresses: ["10.77.0.2"], subnetMasks: ["255.255.255.0"])
    value.ipv4Settings?.includedRoutes = [NEIPv4Route.default()]
    value.dnsSettings = NEDNSSettings(servers: [server, "2001:db8::53"])
    return value
}

let state = State()
let controller = NativeDNSController()
let nativeFilter = try NativeDNSPacketFilter { wire in
    if wire.first.map({ $0 >> 4 == 6 }) == true { return true }
    return controller.intercept(wire)
}
func nativeIntercept(_ wire: Data) -> Bool {
    wire.withUnsafeBytes { raw in
        AmneziaNativePacketFilterFeed(
            UnsafeMutablePointer(mutating: raw.bindMemory(to: UInt8.self).baseAddress),
            Int32(wire.count)) != 0
    }
}
func apply(_ enabled: Bool = true, server: String = "10.77.0.53") {
    controller.apply(original: settings(server: server), blocked: enabled,
        paths: { [server: .tunnel, "2001:db8::53": .unavailable] }, writer: { wire in
        state.update { $0.packets.append(wire) }; return true
    }, exchange: { _, _ in
        return { _, _, _, _ in
            state.update { $0.exchanges += 1 }
            throw NativeDNSResolverError.scopeUnavailable
        }
    }, failure: { state.update { $0.failures += 1 } }, publish: { value, reply in
        state.update { $0.prepared.append(value); $0.replies.append(reply) }
    }, completion: { error in state.update { $0.errors.append(error != nil) } })
}

controller.start()
apply()
state.wait { $0.prepared.count == 1 }
let first = state.read { $0.prepared[0].dnsSettings!.servers }
require(nativeIntercept(packet(address: first[0], id: 1)), "native TUN guard not ready before publication")
state.wait { $0.packets.count == 1 }
require(state.read { $0.packets[0][31] & 15 == 0 && $0.packets[0][35] == 0 }, "AAAA was not NODATA")
require(controller.intercept(packet(address: first[1], id: 2)), "IPv6-only resolver has no local AAAA endpoint")
state.wait { $0.packets.count == 2 }
require(state.read { $0.exchanges == 0 }, "AAAA used native upstream")
require(nativeIntercept(packet(address: first[1], id: 3, type: 1)), "IPv6-only upstream A escaped native TUN policy")
state.wait { $0.packets.count == 3 }
require(state.read { $0.packets[2][31] & 15 == 2 && $0.exchanges == 0 }, "IPv6 upstream was contacted or failed open")
require(!controller.intercept(packet(address: "192.0.2.9", id: 4)), "ordinary native IPv4 was captured")
require(!nativeIntercept(packet(address: "192.0.2.9", id: 4)), "native TUN changed ordinary IPv4")
require(!controller.intercept(Data([0x60] + [UInt8](repeating: 0, count: 39))), "native IPv6 was moved to DNS proxy")
require(nativeIntercept(Data([0x60] + [UInt8](repeating: 0, count: 39))), "native TUN allowed IPv6 with OFF")
state.read { $0.replies[0] }(nil)
state.wait { $0.errors.count == 1 }

apply()
state.wait { $0.prepared.count == 2 }
require(state.read { $0.prepared[1].dnsSettings!.servers == first }, "unchanged DNS refresh republished new endpoints")
state.read { $0.replies[1] }(nil)
state.wait { $0.errors.count == 2 }
apply(server: "10.77.0.54")
state.wait { $0.prepared.count == 3 }
let rollback = state.read { $0.prepared[2].dnsSettings!.servers }
require(Set(first).isDisjoint(with: rollback), "staging repurposed an active resolver endpoint")
state.read { $0.replies[2] }(NativeDNSResolverError.scopeUnavailable)
state.wait { $0.errors.count == 3 }
require(state.read { $0.errors == [false, false, true] }, "publication failure was hidden")
require(controller.intercept(packet(address: first[0], id: 5)), "rollback lost previous DNS generation")
state.wait { $0.packets.count == 4 }
require(controller.intercept(packet(address: rollback[0], id: 6)), "failed staged endpoint fell through to native")

apply(server: "10.77.0.55")
state.wait { $0.prepared.count == 4 }
let stopped = DispatchSemaphore(value: 0)
controller.stop { stopped.signal() }
require(stopped.wait(timeout: .now() + 5) == .success, "DNS stop could not cancel staged generation")
state.read { $0.replies[3] }(nil)
state.wait { $0.errors.count == 4 }
require(state.read { $0.errors[3] }, "late settings publication reactivated a stopped generation")
require(controller.intercept(packet(address: first[0], id: 7)), "stopped endpoint fell through to native")
require(state.read { $0.failures == 0 && $0.packets.count == 4 }, "late reply or normal stop reported native failure")
nativeFilter.stop()
nativeFilter.stop()
require(!nativeIntercept(Data([0x60] + [UInt8](repeating: 0, count: 39))), "retired native filter still changes packets")

controller.start()
apply(false)
state.wait { $0.prepared.count == 5 }
require(state.read { $0.prepared[4].dnsSettings!.servers == settings().dnsSettings!.servers }, "ON DNS settings changed")
state.read { $0.replies[4] }(nil)
state.wait { $0.errors.count == 5 }
require(!controller.intercept(packet(address: first[0], id: 8)), "ON retained the previous DNS interception policy")
controller.stop { stopped.signal() }
require(stopped.wait(timeout: .now() + 5) == .success, "final DNS stop did not finish")
let timeoutState = State()
let timed = NativeDNSController(publicationTimeout: 0.1)
timed.start()
timed.apply(original: settings(), blocked: true,
    paths: { ["10.77.0.53": .tunnel, "2001:db8::53": .unavailable] }, writer: { _ in true },
    exchange: { _, _ in return { _, _, _, _ in throw NativeDNSResolverError.scopeUnavailable } },
    failure: { timeoutState.update { $0.failures += 1 } },
    publish: { value, reply in timeoutState.update { $0.prepared.append(value); $0.replies.append(reply) } },
    completion: { error in timeoutState.update { $0.errors.append(error != nil) } })
timeoutState.wait { $0.errors.count == 1 }
require(timeoutState.read { $0.errors == [true] && $0.failures == 1 }, "missing native publication callback did not fail closed")
timeoutState.read { $0.replies[0] }(nil)
timed.stop { stopped.signal() }
require(stopped.wait(timeout: .now() + 5) == .success, "publication timeout left retiring DNS generations alive")
require(timeoutState.read { $0.errors.count == 1 && $0.failures == 1 }, "late publication completed a failed generation twice")
let fast = NativeNetworkSettingsResult()
fast.complete(NativeDNSResolverError.scopeUnavailable)
let fastResult = fast.wait(until: Date().addingTimeInterval(0.1))
require(fastResult.completed && fastResult.error != nil, "native adapter lost a callback before waiting")
fast.complete(nil)
require(fast.wait(until: Date()).error != nil, "duplicate native callback replaced the first error")
let asynchronous = NativeNetworkSettingsResult()
DispatchQueue.global().async { asynchronous.complete(nil) }
let asynchronousResult = asynchronous.wait(until: Date().addingTimeInterval(5))
require(asynchronousResult.completed && asynchronousResult.error == nil, "native adapter lost an asynchronous callback")
let missing = NativeNetworkSettingsResult()
require(!missing.wait(until: Date().addingTimeInterval(0.01)).completed, "missing native callback was treated as success")
print("PASS: native DNS prepare/publish, IPv6 upstream rejection, rollback, stop race, native passthrough and ON")
