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
                let raw = try Self.sessionConfiguration(config)
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
            self.generation &+= 1
            if self.handle > 0 { AmneziaRoutingStop(self.handle); self.handle = -1 }
            self.provider?.setTunnelNetworkSettings(nil) { _ in completion() }
            if self.provider == nil { completion() }
        }
    }

    func networkChanged() {
        queue.async {
            guard !self.stopped, self.handle > 0, let raw = self.sessionData else { return }
            // Keep the same public packetFlow reader and OS capture settings.
            // Recreate transport sockets after the old workers are joined.
            AmneziaRoutingStop(self.handle)
            let context = Unmanaged.passRetained(self).toOpaque()
            self.handle = raw.withUnsafeBytes { buffer in
                AmneziaRoutingStart(UnsafeMutablePointer(mutating: buffer.bindMemory(to: CChar.self).baseAddress),
                                    Int32(raw.count), context, Self.writePacket, Self.releaseHost)
            }
            if self.handle <= 0 { self.provider?.cancelTunnelWithError(RoutingError.backendFailed) }
        }
    }

    func status(completion: @escaping (Data?) -> Void) {
        queue.async {
            var rx: UInt64 = 0, tx: UInt64 = 0, handshake: UInt64 = 0
            guard self.handle > 0, AmneziaRoutingStats(self.handle, &rx, &tx, &handshake) == 0 else { completion(nil); return }
            completion(try? JSONSerialization.data(withJSONObject: ["rx_bytes": String(rx), "tx_bytes": String(tx), "last_handshake_time_sec": handshake]))
        }
    }

    private static func sessionConfiguration(_ config: WGConfig) throws -> Data {
        guard let rulesText = config.routingConfig, let rulesData = rulesText.data(using: .utf8),
              let rules = try JSONSerialization.jsonObject(with: rulesData) as? [String: Any],
              config.allowedIPs.contains("0.0.0.0/0") else { throw RoutingError.invalidConfiguration }
        let endpoint = try numericHost(config.hostName, port: config.port)
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
            guard let seconds = UInt16(keepalive) else { throw RoutingError.invalidConfiguration }
            awg["keepalive"] = seconds
        }
        let support = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        try FileManager.default.createDirectory(at: support, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        return try JSONSerialization.data(withJSONObject: ["rules": rules, "awg": awg,
                    "cache_path": support.appendingPathComponent("routing-fakeip-v1.db").path,
                    "resolver": dns.contains(":") ? "[\(dns)]:53" : "\(dns):53", "resolver_action": config.routingDNSPath ?? "vpn"])
    }

    // Called before capture is installed. Resolve only the peer endpoint using
    // the native resolver; destination domains are never pre-resolved into rules.
    private static func numericHost(_ hostname: String, port: Int) throws -> String {
        guard port > 0 && port <= 65535 else { throw RoutingError.invalidConfiguration }
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_DGRAM
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(hostname, String(port), &hints, &result) == 0, let first = result else { throw RoutingError.endpointResolution }
        defer { freeaddrinfo(first) }
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        guard getnameinfo(first.pointee.ai_addr, first.pointee.ai_addrlen, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else { throw RoutingError.endpointResolution }
        let value = String(cString: host)
        return value.contains(":") ? "[\(value)]:\(port)" : "\(value):\(port)"
    }

    enum RoutingError: Error { case invalidConfiguration, endpointResolution, backendFailed, stopped }
}
