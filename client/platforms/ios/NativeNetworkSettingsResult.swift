import Foundation

protocol NativeNetworkSettingsFailurePolicy: AnyObject {
    var requiresConfirmedNativeSettings: Bool { get }
}

// Native WireGuard's settings callback can arrive before the adapter starts
// waiting. Store completion under the same condition as the wait; a signal
// alone is not durable state and can otherwise lose a fast error/success.
final class NativeNetworkSettingsResult: @unchecked Sendable {
    private let condition = NSCondition()
    private var completed = false
    private var error: Error?

    func complete(_ error: Error?) {
        condition.lock()
        defer { condition.unlock() }
        guard !completed else { return }
        self.error = error
        completed = true
        condition.broadcast()
    }

    func wait(until deadline: Date) -> (completed: Bool, error: Error?) {
        condition.lock()
        defer { condition.unlock() }
        while !completed {
            if !condition.wait(until: deadline) { return (false, nil) }
        }
        return (true, error)
    }
}
