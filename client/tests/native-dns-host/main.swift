import Foundation

func require(_ value: @autoclosure () -> Bool, _ message: String) {
    if !value() { fatalError(message) }
}

final class State {
    let condition = NSCondition()
    var packets: [Data] = []
    var requests = 0
    var cancellations = 0
    var failures = 0
    var mode = 0
    var late: ((Result<Data, Error>) -> Void)?
    var owner: NativeDNSGuard?

    func update(_ body: (State) -> Void) {
        condition.lock()
        body(self)
        condition.broadcast()
        condition.unlock()
    }

    func read<T>(_ body: (State) -> T) -> T {
        condition.lock()
        defer { condition.unlock() }
        return body(self)
    }

    func wait(_ predicate: (State) -> Bool) {
        let end = Date().addingTimeInterval(5)
        condition.lock()
        defer { condition.unlock() }
        while !predicate(self) {
            require(condition.wait(until: end), "native DNS host event timed out")
        }
    }
}

final class Operation: NativeDNSOperation {
    let cancelled: () -> Void
    init(_ cancelled: @escaping () -> Void) { self.cancelled = cancelled }
    func cancel() { cancelled() }
}

enum ExpectedFailure: Error { case unavailable }

func packet(id: UInt16, type: UInt16) -> Data {
    let name: [UInt8] = [7] + Array("managed".utf8) + [7] + Array("example".utf8) + [0]
    var p = [UInt8](repeating: 0, count: 20 + 8 + 12 + name.count + 4)
    func put(_ offset: Int, _ value: Int) {
        p[offset] = UInt8((value >> 8) & 255)
        p[offset + 1] = UInt8(value & 255)
    }
    p[0] = 0x45
    put(2, p.count)
    p[8] = 64
    p[9] = 17
    p[12] = 10; p[13] = 77; p[15] = 2
    p[16] = 172; p[17] = 19; p[19] = 2
    put(20, 40000); put(22, 53); put(24, p.count - 20)
    put(28, Int(id)); p[30] = 1; put(32, 1)
    p.replaceSubrange(40..<(40 + name.count), with: name)
    put(40 + name.count, Int(type)); put(42 + name.count, 1)
    var sum = 0
    for index in stride(from: 0, to: 20, by: 2) {
        sum += Int(p[index]) * 256 + Int(p[index + 1])
    }
    while sum > 65535 { sum = (sum & 65535) + (sum >> 16) }
    put(10, (~sum) & 65535)
    return Data(p)
}

let state = State()
let guardDNS = try NativeDNSGuard(address: "172.19.0.2", writer: { packet in
    state.update { $0.packets.append(packet) }
    return true
}, exchange: { query, transport, timeout, completion in
    require(transport == .udp && timeout > 0 && timeout <= 5, "native transport/deadline changed")
    state.update { $0.requests += 1 }
    let mode = state.read { $0.mode }
    if mode == 1 { throw ExpectedFailure.unavailable }
    if mode == 2 {
        state.update { $0.late = completion }
    } else {
        var reply = query
        reply[2] |= 0x80
        reply[3] = 0x80
        var wrong = reply
        wrong[0] ^= 1
        // Synchronous callbacks exercise registration ordering on the serial
        // host queue. A spurious response must not close the valid operation.
        completion(.success(wrong))
        completion(.success(reply))
        completion(.success(reply))
    }
    return Operation { state.update { $0.cancellations += 1 } }
}, failure: {
    state.update { $0.failures += 1 }
})

require(guardDNS.feed(packet(id: 0x1234, type: 28)) == .dns, "AAAA was not intercepted")
state.wait { $0.packets.count == 1 }
require(state.read { $0.requests == 0 }, "AAAA reached native upstream")
require(state.read { $0.packets[0][31] & 15 == 0 && $0.packets[0][34] == 0 && $0.packets[0][35] == 0 },
        "AAAA response was not NODATA")

require(guardDNS.feed(packet(id: 0x1235, type: 1)) == .dns, "A was not intercepted")
state.wait { $0.packets.count == 2 && $0.cancellations == 1 }
require(state.read { $0.requests == 1 }, "A query retried/fell back")

state.update { $0.mode = 1 }
require(guardDNS.feed(packet(id: 0x1237, type: 1)) == .dns, "failed scope request not intercepted")
state.wait { $0.packets.count == 3 }
require(state.read { $0.packets[2][31] & 15 == 2 }, "scope failure did not return SERVFAIL")

var native = packet(id: 0x1238, type: 1)
native[16] = 198; native[17] = 51; native[18] = 100; native[19] = 2
require(guardDNS.feed(native) == .native, "non-DNS endpoint was captured")

state.update { $0.mode = 2 }
require(guardDNS.feed(packet(id: 0x1239, type: 1)) == .dns, "pending request not intercepted")
state.wait { $0.late != nil }
let stopped = DispatchSemaphore(value: 0)
guardDNS.stop { stopped.signal() }
require(stopped.wait(timeout: .now() + 5) == .success, "stop did not finish")
require(state.read { $0.cancellations == 2 && $0.failures == 0 }, "native operations were not cancelled exactly once")
let late = state.read { $0.late }
late?(.success(Data(repeating: 0, count: 12)))
let drained = DispatchSemaphore(value: 0)
guardDNS.stop { drained.signal() }
require(drained.wait(timeout: .now() + 5) == .success, "duplicate stop did not finish")
require(state.read { $0.packets.count == 3 && $0.cancellations == 2 }, "late callback changed stopped DNS")
require(guardDNS.feed(packet(id: 0x123a, type: 28)) == .failed, "stopped guard allowed packet fallback")

let failedState = State()
let failedStopped = DispatchSemaphore(value: 0)
let failingGuard = try NativeDNSGuard(address: "172.19.0.3", writer: { _ in false },
    exchange: { _, _, _, _ in
        fatalError("local AAAA policy reached upstream during writer failure")
    }, failure: {
        failedState.update { $0.failures += 1 }
        let owner = failedState.read { $0.owner }
        owner?.stop { failedStopped.signal() }
    })
failedState.update { $0.owner = failingGuard }
var failedPacket = packet(id: 0x1240, type: 28)
failedPacket[19] = 3
// Recompute the IPv4 header checksum after selecting the second DNS endpoint.
failedPacket[10] = 0; failedPacket[11] = 0
var failedSum = 0
for index in stride(from: 0, to: 20, by: 2) {
    failedSum += Int(failedPacket[index]) * 256 + Int(failedPacket[index + 1])
}
while failedSum > 65535 { failedSum = (failedSum & 65535) + (failedSum >> 16) }
failedPacket[10] = UInt8(((~failedSum) >> 8) & 255)
failedPacket[11] = UInt8((~failedSum) & 255)
require(failingGuard.feed(failedPacket) == .dns, "writer failure packet was not intercepted")
require(failedStopped.wait(timeout: .now() + 5) == .success, "failure callback could not stop native guard")
require(failedState.read { $0.failures == 1 }, "native writer failure was not exactly once")
failedState.update { $0.owner = nil }
require(failingGuard.feed(failedPacket) == .failed, "failed endpoint allowed fallback")
print("PASS: Swift/native DNS host NODATA, response matching, scoped failure, cancellation and stop")
