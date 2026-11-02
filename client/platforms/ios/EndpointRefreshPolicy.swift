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

// Same observations as the desktop watchdog: no packets are generated merely
// to probe the server. All times are monotonic milliseconds, never wall time.
struct EndpointHealthPolicy {
    enum Action: Equatable { case none, refresh, exhausted }
    var staleMs: Int64 = 240000
    private var epoch: UInt64?
    private var handshake: Int64 = 0
    private var tx: UInt64 = 0
    private var rx: UInt64 = 0
    private var lastSample: Int64?
    private var pendingSince: Int64?
    private var deadline: Int64?
    private var attempts = 0
    private var exhausted = false

    init(staleMs: Int64 = 240000) { self.staleMs = staleMs }

    mutating func sample(backend: UInt64, handshake: Int64, tx: UInt64, rx: UInt64, now: Int64) -> Action {
        guard !exhausted else { return .none }
        let changed = epoch != backend
        let gap = lastSample.map { now < $0 || now - $0 > 30000 } ?? false
        if changed { epoch = backend; pendingSince = nil; deadline = now + 45000 }
        let evidence = handshake > 0 && (changed || handshake != self.handshake || rx > self.rx)
        if evidence { attempts = 0; deadline = nil; pendingSince = nil }
        else if gap {
            pendingSince = nil
            if deadline != nil { deadline = now + 45000 }
        }
        let sending = !changed && !gap && tx > self.tx
        if !evidence && deadline == nil && sending && pendingSince == nil { pendingSince = now }
        let due = deadline.map { now >= $0 } ?? (sending && pendingSince.map { now - $0 >= staleMs } == true)
        self.handshake = handshake; self.tx = tx; self.rx = rx; lastSample = now
        guard due else { return .none }
        guard attempts < 6 else { exhausted = true; return .exhausted }
        attempts += 1
        pendingSince = nil
        deadline = now + 180000
        return .refresh
    }

    static func staleBudget(rekey: String?, reject: String?) -> Int64 {
        [rekey, reject].compactMap { value -> Int64? in
            guard let value, let seconds = Int64(String(value.split(separator: "-").last ?? "").trimmingCharacters(in: .whitespaces)),
                  seconds > 0, seconds <= 86400 else { return nil }
            return (seconds * 2 + 30) * 1000
        }.reduce(240000, max)
    }
}
