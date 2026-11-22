import Foundation
import NetworkExtension
import Darwin

// Connection-local OFF settings. Keep one endpoint per original resolver so
// the OS retains server ordering/selection, rather than hiding a fallback
// policy behind a single synthetic address.
struct NativeDNSSettings {
    enum Path: Equatable { case tunnel, underlay, loopback, interface(UInt32), unavailable }
    struct Binding {
        let address: String
        let upstream: String
        let path: Path
    }
    enum PlanError: Error { case invalidSettings, encryptedDNS, noCaptureAddress }
    let settings: NEPacketTunnelNetworkSettings
    let bindings: [Binding]

    // Scope must come from the native connection's actual resolver policy.
    // Reconstructing it from included/excluded routes alone is insufficient:
    // system routes and interface-scoped DNS can supersede those routes.
    init(original: NEPacketTunnelNetworkSettings, paths: [String: Path], occupied: Set<String> = [],
         captures: [String]? = nil) throws {
        guard let dns = original.dnsSettings, !dns.servers.isEmpty, dns.servers.count <= 32,
              let copy = original.copy() as? NEPacketTunnelNetworkSettings else {
            throw PlanError.invalidSettings
        }
        // Do not silently turn authenticated DNS into plaintext forwarding.
        guard type(of: dns) == NEDNSSettings.self else { throw PlanError.encryptedDNS }
        guard captures == nil || captures?.count == dns.servers.count else { throw PlanError.invalidSettings }
        let ipv4 = original.ipv4Settings
        let included = try (ipv4?.includedRoutes ?? []).map(Route.init)
        let excluded = try (ipv4?.excludedRoutes ?? []).map(Route.init)
        let addresses = ipv4?.addresses ?? []
        let masks = ipv4?.subnetMasks ?? []
        guard !addresses.isEmpty, addresses.count == masks.count else { throw PlanError.invalidSettings }
        let connected = try zip(addresses, masks).map { try Route(address: $0.0, mask: $0.1) }
        var occupied = occupied.union(addresses + dns.servers + [original.tunnelRemoteAddress])
        var result: [Binding] = []
        for (index, upstream) in dns.servers.enumerated() {
            let path: Path
            if let ip = Self.ipv4(upstream) {
                _ = try NativeDNSResolver.validateIPv4Server(upstream)
                if ip >> 24 == 127 {
                    path = .loopback
                } else {
                    guard let selected = paths[upstream], selected != .loopback else {
                        throw PlanError.invalidSettings
                    }
                    path = selected
                }
            } else {
                // A valid IPv6 resolver still gets a local endpoint for AAAA
                // NODATA, but no IPv6 upstream operation may be constructed.
                var ip = in6_addr()
                let pieces = upstream.split(separator: "%", omittingEmptySubsequences: false)
                guard !upstream.utf8.contains(0), !pieces.isEmpty, pieces.count <= 2,
                      String(pieces[0]).withCString({ inet_pton(AF_INET6, $0, &ip) }) == 1,
                      pieces.count == 1 || !pieces[1].isEmpty else { throw PlanError.invalidSettings }
                path = .unavailable
            }
            // Reserve only individual /32s. Do not hijack an explicit split
            // route or a real interface/resolver/remote address.
            let pool = (1...253).map { "198.19.255.\($0)" }
            let candidates = captures.map { [$0[index]] } ?? pool
            guard let capture = candidates.first(where: { candidate in
                guard pool.contains(candidate) else { return false }
                guard !occupied.contains(candidate), let ip = Self.ipv4(candidate) else { return false }
                return !(included + excluded + connected).contains { $0.prefix > 1 && $0.contains(ip) }
            }) else { throw PlanError.noCaptureAddress }
            occupied.insert(capture)
            result.append(Binding(address: capture, upstream: upstream, path: path))
        }
        let replacement = NEDNSSettings(servers: result.map(\.address))
        replacement.domainName = dns.domainName
        replacement.searchDomains = dns.searchDomains
        replacement.matchDomains = dns.matchDomains
        replacement.matchDomainsNoSearch = dns.matchDomainsNoSearch
#if compiler(>=6.2)
        if #available(iOS 26.0, macOS 26.0, *) {
            replacement.allowFailover = false
        }
#endif
        copy.dnsSettings = replacement
        guard let copiedIPv4 = ipv4?.copy() as? NEIPv4Settings else {
            throw PlanError.invalidSettings
        }
        copiedIPv4.includedRoutes = (copiedIPv4.includedRoutes ?? []) + result.map {
            NEIPv4Route(destinationAddress: $0.address, subnetMask: "255.255.255.255")
        }
        copy.ipv4Settings = copiedIPv4
        settings = copy
        bindings = result
    }

    private static func ipv4(_ string: String) -> UInt32? {
        guard !string.utf8.contains(0) else { return nil }
        var address = in_addr()
        guard string.withCString({ inet_pton(AF_INET, $0, &address) }) == 1 else { return nil }
        return UInt32(bigEndian: address.s_addr)
    }

    private struct Route {
        let address: UInt32
        let mask: UInt32
        let prefix: Int
        init(_ route: NEIPv4Route) throws {
            try self.init(address: route.destinationAddress, mask: route.destinationSubnetMask)
        }
        init(address: String, mask: String) throws {
            guard let ip = NativeDNSSettings.ipv4(address), let bits = NativeDNSSettings.ipv4(mask) else {
                throw PlanError.invalidSettings
            }
            let inverse = ~bits
            guard inverse & (inverse &+ 1) == 0 else { throw PlanError.invalidSettings }
            self.address = ip & bits
            self.mask = bits
            self.prefix = bits.nonzeroBitCount
        }
        func contains(_ ip: UInt32) -> Bool { ip & mask == address }
    }
}
