import Foundation

// Used only on the owning serial queue. Tokens invalidate DNS results and
// scheduled retries after stop or a newer physical-network change.
struct EndpointRefreshPolicy {
    private var generation: UInt64 = 0
    private var attempts = 0
    mutating func begin() -> UInt64 {
        generation &+= 1
        attempts = 0
        return generation
    }
    mutating func cancel() { generation &+= 1 }
    func accepts(_ token: UInt64) -> Bool { token == generation }
    mutating func nextDelay(for token: UInt64) -> TimeInterval? {
        guard accepts(token), attempts < 6 else { return nil }
        let delay: TimeInterval = attempts == 0 ? 0 : Double(1 << (attempts - 1))
        attempts += 1
        return delay
    }
}
