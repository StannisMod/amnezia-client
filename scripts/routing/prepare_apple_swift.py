"""Fix native settings completion ownership without modifying the submodule."""
import argparse
from pathlib import Path

ORIGINAL = '''    private func setNetworkSettings(_ networkSettings: NEPacketTunnelNetworkSettings) throws {
        self.logHandler(.verbose, "setNetworkSettings: applying")
        var systemError: Error?
        let condition = NSCondition()

        // Activate the condition
        condition.lock()
        defer { condition.unlock() }

        self.packetTunnelProvider?.setTunnelNetworkSettings(networkSettings) { error in
            systemError = error
            condition.signal()
        }

        // Packet tunnel's `setTunnelNetworkSettings` times out in certain
        // scenarios & never calls the given callback.
        let setTunnelNetworkSettingsTimeout: TimeInterval = 5 // seconds

        if condition.wait(until: Date().addingTimeInterval(setTunnelNetworkSettingsTimeout)) {
            if let systemError = systemError {
                throw WireGuardAdapterError.setNetworkSettings(systemError)
            }
        } else {
            self.logHandler(.error, "setTunnelNetworkSettings timed out after 5 seconds; proceeding anyway")
        }

        self.lastNetworkSettingsUpdateAt = Date()
    }'''

REPLACEMENT = '''    private func setNetworkSettings(_ networkSettings: NEPacketTunnelNetworkSettings) throws {
        self.logHandler(.verbose, "setNetworkSettings: applying")
        let policy = self.packetTunnelProvider as? NativeNetworkSettingsFailurePolicy
        let requiresConfirmation = policy?.requiresConfirmedNativeSettings == true
        let result = NativeNetworkSettingsResult()
        self.packetTunnelProvider?.setTunnelNetworkSettings(networkSettings) { error in
            result.complete(error)
        }
        let outcome = result.wait(until: Date().addingTimeInterval(5))
        if outcome.completed {
            if let error = outcome.error {
                throw WireGuardAdapterError.setNetworkSettings(error)
            }
        } else if requiresConfirmation {
            throw WireGuardAdapterError.setNetworkSettings(
                NSError(domain: "NativeNetworkSettingsConfirmation", code: 1))
        } else {
            self.logHandler(.error, "setTunnelNetworkSettings timed out after 5 seconds; proceeding anyway")
        }
        self.lastNetworkSettingsUpdateAt = Date()
    }'''


def prepare(source, destination):
    text = Path(source).read_text()
    if text.count(ORIGINAL) != 1:
        raise RuntimeError("Unexpected native WireGuard Swift settings completion entry point")
    Path(destination).write_text(text.replace(ORIGINAL, REPLACEMENT))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    prepare(args.source, args.output)
