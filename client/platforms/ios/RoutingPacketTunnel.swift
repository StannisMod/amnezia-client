import Foundation
import NetworkExtension
import Darwin

// Serializes native lifetime and the sole public packetFlow reader. Native
// output may arrive on any Go thread; it copies Data before returning to Go.
final class RoutingPacketTunnel {
    private weak var provider: NEPacketTunnelProvider?
    private let queue = DispatchQueue(label: "org.amnezia.routing-session")
    private var handle: Int64 = -1
    private var generation: UInt64 = 0
    private var stopped = false
    private var sessionData: Data?
    private var originalConfig: WGConfig?
    private var refreshPolicy = EndpointRefreshPolicy()
    private var refreshWork: DispatchWorkItem?
    private var lookupDeadline: DispatchWorkItem?
    private var lookupGeneration: UInt64 = 0
    private var endpointHealthTimer: DispatchSourceTimer?
    private var endpointHealth = EndpointHealthPolicy()
    private let endpointCandidates = EndpointAddressCandidates()
    private var backendEpoch: UInt64 = 0

    init(provider: NEPacketTunnelProvider) { self.provider = provider }

    private static let writePacket: AmneziaPacketWriter = { context, bytes, size in
        guard let context, let bytes, size > 0 else { return 0 }
        let host = Unmanaged<RoutingPacketTunnel>.fromOpaque(context).takeUnretainedValue()
        guard let provider = host.provider else { return 0 }
        let data = Data(bytes: bytes, count: Int(size))
        let family = (bytes.pointee >> 4) == 6 ? AF_INET6 : AF_INET
        return provider.packetFlow.writePackets([data], withProtocols: [NSNumber(value: family)]) ? 1 : 0
    }
    private static let releaseHost: AmneziaHostRelease = { context in
        if let context { Unmanaged<RoutingPacketTunnel>.fromOpaque(context).release() }
    }

    func start(config: WGConfig, completion: @escaping (Error?) -> Void) {
        queue.async {
            do {
                guard !self.stopped, self.handle < 0, let provider = self.provider,
                      let protocolConfig = provider.protocolConfiguration as? NETunnelProviderProtocol,
                      !protocolConfig.includeAllNetworks else { throw RoutingError.invalidConfiguration }
                let raw = try Self.sessionConfiguration(config, endpoint: Self.numericHost(
                    try EndpointAddressResolver.addresses(config.hostName), port: config.port, candidates: self.endpointCandidates))
                self.originalConfig = config // Keep the domain, not its bootstrap IP.
                self.sessionData = raw
                let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
                settings.mtu = 1280
                let v4 = NEIPv4Settings(addresses: ["172.19.0.1"], subnetMasks: ["255.255.255.252"])
                v4.includedRoutes = [NEIPv4Route.default()]
                settings.ipv4Settings = v4
                let v6 = NEIPv6Settings(addresses: ["fdfe:dcba:9876::1"], networkPrefixLengths: [126])
                v6.includedRoutes = [NEIPv6Route.default()]
                settings.ipv6Settings = v6
                let dns = NEDNSSettings(servers: ["172.19.0.2"])
                dns.matchDomains = [""]
                settings.dnsSettings = dns
                provider.setTunnelNetworkSettings(settings) { error in
                    self.queue.async {
                        guard !self.stopped else { completion(RoutingError.stopped); return }
                        if let error { completion(error); return }
                        let context = Unmanaged.passRetained(self).toOpaque()
                        self.handle = raw.withUnsafeBytes { buffer in
                            AmneziaRoutingStart(UnsafeMutablePointer(mutating: buffer.bindMemory(to: CChar.self).baseAddress),
                                                Int32(raw.count), context, Self.writePacket, Self.releaseHost)
                        }
                        guard self.handle > 0 else {
                            provider.setTunnelNetworkSettings(nil) { _ in completion(RoutingError.backendFailed) }
                            return
                        }
                        self.backendEpoch &+= 1
                        self.startEndpointWatchdog(config: config)
                        self.generation &+= 1
                        self.readPackets(generation: self.generation)
                        completion(nil)
                    }
                }
            } catch { completion(error) }
        }
    }

    private func readPackets(generation: UInt64) {
        guard !stopped, handle > 0, generation == self.generation, let provider else { return }
        provider.packetFlow.readPackets { [weak self] packets, _ in
            guard let self else { return }
            self.queue.async {
                guard !self.stopped, self.handle > 0, generation == self.generation else { return }
                for data in packets {
                    data.withUnsafeBytes { buffer in
                        _ = AmneziaRoutingFeed(self.handle, UnsafeMutablePointer(mutating: buffer.bindMemory(to: UInt8.self).baseAddress), Int32(data.count))
                    }
                }
                self.readPackets(generation: generation)
            }
        }
    }

    func stop(completion: @escaping () -> Void) {
        queue.async {
            self.stopped = true
            self.provider?.reasserting = false
            self.refreshPolicy.cancel()
            self.endpointHealthTimer?.cancel()
            self.endpointHealthTimer = nil
            self.refreshWork?.cancel()
            self.lookupDeadline?.cancel()
            self.lookupGeneration &+= 1
            self.generation &+= 1
            if self.handle > 0 { AmneziaRoutingStop(self.handle); self.handle = -1 }
            self.provider?.setTunnelNetworkSettings(nil) { _ in completion() }
            if self.provider == nil { completion() }
        }
    }

    func networkChanged() {
        queue.async {
            guard !self.stopped, self.handle > 0, let config = self.originalConfig else { return }
            self.refreshWork?.cancel()
            self.lookupDeadline?.cancel()
            self.lookupGeneration &+= 1
            let token = self.refreshPolicy.begin()
            self.provider?.reasserting = true
            self.refreshTransport(config: config, token: token)
        }
    }

    private func refreshTransport(config: WGConfig, token: UInt64) {
        guard !stopped, refreshPolicy.accepts(token), handle > 0 else { return }
        guard let delay = refreshPolicy.nextDelay(for: token) else {
            provider?.reasserting = false
            provider?.cancelTunnelWithError(RoutingError.endpointResolution)
            return
        }
        let work = DispatchWorkItem { [weak self] in
            guard let self, !self.stopped, self.refreshPolicy.accepts(token), self.handle > 0 else { return }
            self.lookupGeneration &+= 1
            let lookup = self.lookupGeneration
            let deadline = DispatchWorkItem { [weak self] in
                guard let self, !self.stopped, self.refreshPolicy.accepts(token), lookup == self.lookupGeneration else { return }
                self.lookupGeneration &+= 1 // A late DNS result cannot install a tunnel.
                self.refreshTransport(config: config, token: token)
            }
            self.lookupDeadline = deadline
            self.queue.asyncAfter(deadline: .now() + 15, execute: deadline)
            // getaddrinfo must not block the lifetime/packet-flow queue. Keep
            // the current capture/backend while the new uplink acquires DNS.
            DispatchQueue.global(qos: .utility).async { [weak self] in
                guard let self else { return }
                let result = Result { try EndpointAddressResolver.addresses(config.hostName) }
                self.queue.async { [weak self] in
                    guard let self, !self.stopped, self.refreshPolicy.accepts(token),
                          lookup == self.lookupGeneration, self.handle > 0 else { return }
                    self.lookupDeadline?.cancel()
                    self.lookupGeneration &+= 1 // Consume the result exactly once, including deadline races.
                    switch result {
                    case .failure:
                        self.refreshTransport(config: config, token: token)
                    case .success(let addresses):
                        // Only an accepted lookup may consume a candidate. A
                        // timed-out/superseded worker must not skip a usable IP.
                        let raw: Data
                        do {
                            let endpoint = try Self.numericHost(addresses, port: config.port, candidates: self.endpointCandidates)
                            raw = try Self.sessionConfiguration(config, endpoint: endpoint)
                        } catch {
                            self.refreshTransport(config: config, token: token)
                            return
                        }
                        // Reuse the same public packetFlow reader and capture.
                        // Transport workers finish before the replacement starts.
                        AmneziaRoutingStop(self.handle)
                        let context = Unmanaged.passRetained(self).toOpaque()
                        self.handle = raw.withUnsafeBytes { buffer in
                            AmneziaRoutingStart(UnsafeMutablePointer(mutating: buffer.bindMemory(to: CChar.self).baseAddress),
                                                Int32(raw.count), context, Self.writePacket, Self.releaseHost)
                        }
                        self.backendEpoch &+= 1
                        self.sessionData = raw
                        self.provider?.reasserting = false
                        if self.handle <= 0 { self.provider?.cancelTunnelWithError(RoutingError.backendFailed) }
                    }
                }
            }
        }
        refreshWork = work
        queue.asyncAfter(deadline: .now() + delay, execute: work)
    }

    private func startEndpointWatchdog(config: WGConfig) {
        endpointHealthTimer?.cancel()
        let host = config.hostName
        guard !host.contains(":"), host.rangeOfCharacter(from: CharacterSet(charactersIn: "0123456789.").inverted) != nil else { return }
        endpointHealth = EndpointHealthPolicy(staleMs: EndpointHealthPolicy.staleBudget(
            rekey: config.rekeyAfterTime, reject: config.rejectAfterTime))
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 5, repeating: 5, leeway: .milliseconds(500))
        timer.setEventHandler { [weak self] in
            guard let self, !self.stopped, self.handle > 0 else { return }
            var rx: UInt64 = 0, tx: UInt64 = 0, handshake: UInt64 = 0
            let available = AmneziaRoutingStats(self.handle, &rx, &tx, &handshake) == 0
            let action = self.endpointHealth.sample(backend: available ? self.backendEpoch : self.backendEpoch | (1 << 63),
                handshake: available ? Int64(clamping: handshake) : 0, tx: tx, rx: rx,
                now: Int64(ProcessInfo.processInfo.systemUptime * 1000))
            switch action {
            case .none: break
            case .refresh: self.networkChanged()
            case .exhausted:
                self.endpointHealthTimer?.cancel()
                self.endpointHealthTimer = nil
                self.provider?.reasserting = false
                self.provider?.cancelTunnelWithError(RoutingError.endpointResolution)
            }
        }
        endpointHealthTimer = timer
        timer.resume()
    }

    func status(completion: @escaping (Data?) -> Void) {
        queue.async {
            var rx: UInt64 = 0, tx: UInt64 = 0, handshake: UInt64 = 0
            guard self.handle > 0, AmneziaRoutingStats(self.handle, &rx, &tx, &handshake) == 0 else { completion(nil); return }
            var status: [String: Any] = ["rx_bytes": String(rx), "tx_bytes": String(tx), "last_handshake_time_sec": handshake]
            if let raw = AmneziaRoutingDiagnostics(self.handle) {
                defer { free(raw) }
                status["routing"] = try? JSONSerialization.jsonObject(with: Data(String(cString: raw).utf8))
            }
            completion(try? JSONSerialization.data(withJSONObject: status))
        }
    }

    private static func sessionConfiguration(_ config: WGConfig, endpoint: String) throws -> Data {
        guard let rulesText = config.routingConfig, let rulesData = rulesText.data(using: .utf8),
              let rules = try JSONSerialization.jsonObject(with: rulesData) as? [String: Any],
              config.allowedIPs.contains("0.0.0.0/0") else { throw RoutingError.invalidConfiguration }
        let dns = config.dns1.isEmpty ? config.dns2 : config.dns1
        // The real resolver is explicit. Never bootstrap it with managed DNS.
        var v4 = in_addr(), v6 = in6_addr()
        guard inet_pton(AF_INET, dns, &v4) == 1 || inet_pton(AF_INET6, dns, &v6) == 1 else { throw RoutingError.invalidConfiguration }
        let parameterNames = ["HeaderProtectionKey": "header_protection_key", "ContentPaddingAddition": "content_padding_addition",
                              "RekeyAfterTime": "rekey_after_time", "RekeyTimeout": "rekey_timeout", "RejectAfterTime": "reject_after_time",
                              "KeepaliveTimeout": "keepalive_timeout", "MaxHandshakeAttempts": "max_handshake_attempts",
                              "RandomTrailers": "random_trailers", "DisableCookies": "disable_cookies"]
        var parameters = [String: String]()
        for line in config.settings.components(separatedBy: "\n") {
            let pair = line.components(separatedBy: " = ")
            if pair.count == 2 {
                let name = parameterNames[pair[0]] ?? pair[0].lowercased()
                var value = pair[1]
                if name == "header_protection_key" {
                    guard let key = Data(base64Encoded: value), key.count == 32 else { throw RoutingError.invalidConfiguration }
                    value = key.map { String(format: "%02x", $0) }.joined()
                }
                if name == "random_trailers" || name == "disable_cookies" {
                    switch value.lowercased() {
                    case "on", "true", "1": value = "true"
                    case "off", "false", "0": value = "false"
                    default: throw RoutingError.invalidConfiguration
                    }
                }
                parameters[name] = value
            }
        }
        let addresses = config.clientIP.split(separator: ",").map { String($0).trimmingCharacters(in: .whitespaces).components(separatedBy: "/")[0] }
        var awg: [String: Any] = ["address": addresses, "private_key": config.clientPrivateKey, "public_key": config.serverPublicKey,
                                  "endpoint": endpoint, "allowed_ips": config.allowedIPs, "parameters": parameters, "mtu": 1280]
        if let key = config.presharedKey, !key.isEmpty { awg["pre_shared_key"] = key }
        if let keepalive = config.persistentKeepAlive {
            // Preserve AWG 3.1 ranges for validation by the shared native core.
            awg["keepalive"] = keepalive
        }
        let support = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        try FileManager.default.createDirectory(at: support, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let transport = config.routingTransport ?? "awg" // saved pre-adapter sessions
        guard transport == "awg" || transport == "wireguard" else { throw RoutingError.invalidConfiguration }
        if transport == "wireguard" {
            guard parameters.isEmpty,
                  let keepalive = UInt16(config.persistentKeepAlive ?? "0") else { throw RoutingError.invalidConfiguration }
            awg.removeValue(forKey: "parameters")
            awg["keepalive"] = keepalive
        }
        return try JSONSerialization.data(withJSONObject: ["rules": rules, "vpn": ["type": transport, transport: awg],
                    "cache_path": support.appendingPathComponent("routing-fakeip-v1.db").path,
                    "resolver": dns.contains(":") ? "[\(dns)]:53" : "\(dns):53", "resolver_action": config.routingDNSPath ?? "vpn"])
    }

    // Called before capture is installed. Resolve only the peer endpoint using
    // the native resolver; destination domains are never pre-resolved into rules.
    private static func numericHost(_ addresses: [String], port: Int, candidates: EndpointAddressCandidates) throws -> String {
        guard port > 0 && port <= 65535 else { throw RoutingError.invalidConfiguration }
        guard let value = candidates.select(addresses) else { throw RoutingError.endpointResolution }
        return value.contains(":") ? "[\(value)]:\(port)" : "\(value):\(port)"
    }

    enum RoutingError: Error { case invalidConfiguration, endpointResolution, backendFailed, stopped }
}
