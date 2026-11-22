import Foundation
import NetworkExtension
import Darwin

// Public native policy inputs only. Routing sockets / net/route.h are not
// available in iPhoneOS SDKs. Do not copy private kernel structure definitions.
enum NativeDNSRoute {
    struct ConnectedRoute {
        let address: String
        let mask: String
        let index: UInt32
    }
    enum PolicyError: Error { case invalidRoute, unavailable }

    static func path(server: String, settings: NEPacketTunnelNetworkSettings,
                     connected: [ConnectedRoute], includeAll: Bool, enforce: Bool,
                     excludeLocal: Bool) throws -> NativeDNSSettings.Path {
        if server.contains(":") { return .unavailable }
        let address = try NativeDNSResolver.validateIPv4Server(server)
        let ip = UInt32(bigEndian: address.s_addr)
        if ip >> 24 == 127 { return .loopback }
        let addresses = settings.ipv4Settings?.addresses ?? []
        let masks = settings.ipv4Settings?.subnetMasks ?? []
        guard addresses.count == masks.count else { throw PolicyError.invalidRoute }
        let sourceRoutes = try zip(addresses, masks).map { try prefix(address: $0.0, mask: $0.1, matching: ip) }
        let included = try ((settings.ipv4Settings?.includedRoutes ?? []).map {
            try prefix(address: $0.destinationAddress, mask: $0.destinationSubnetMask, matching: ip)
        } + sourceRoutes).max() ?? -1
        let excluded = try (settings.ipv4Settings?.excludedRoutes ?? []).map {
            try prefix(address: $0.destinationAddress, mask: $0.destinationSubnetMask, matching: ip)
        }.max() ?? -1
        let local = try connected.map {
            (try prefix(address: $0.address, mask: $0.mask, matching: ip), $0.index)
        }.filter { $0.0 > 0 }
        let localPrefix = local.map { $0.0 }.max() ?? -1
        let localInterfaces = Set(local.filter { $0.0 == localPrefix }.map { $0.1 })
        func localPath() -> NativeDNSSettings.Path {
            guard localInterfaces.count == 1, let index = localInterfaces.first else { return .unavailable }
            return .interface(index)
        }
        if includeAll {
            // Native builders explicitly exclude the remote VPN endpoint.
            if excluded == 32 { return .underlay }
            if excludeLocal && localPrefix >= 0 { return localPath() }
            return .tunnel
        }
        if enforce {
            if excludeLocal && localPrefix >= 0 { return localPath() }
            return included > excluded ? .tunnel : .underlay
        }
        if localPrefix >= 0 && localPrefix > max(included, excluded) { return localPath() }
        return included > excluded ? .tunnel : .underlay
    }

    // Snapshot connected underlay subnets from public getifaddrs. The caller
    // supplies only currently available underlying-interface indexes, excluding
    // its own virtual interface. A stale/unavailable selected index cannot
    // silently become another interface during forwarding.
    static func connectedRoutes(indexes: Set<UInt32>) throws -> [ConnectedRoute] {
        var first: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&first) == 0 else { throw PolicyError.unavailable }
        defer { freeifaddrs(first) }
        var result: [ConnectedRoute] = []
        var current = first
        while let entry = current {
            defer { current = entry.pointee.ifa_next }
            let index = if_nametoindex(entry.pointee.ifa_name)
            guard indexes.contains(index), let address = entry.pointee.ifa_addr,
                  let mask = entry.pointee.ifa_netmask,
                  address.pointee.sa_family == sa_family_t(AF_INET),
                  mask.pointee.sa_family == 0 || mask.pointee.sa_family == sa_family_t(AF_INET) else { continue }
            if let address = text(address), let mask = text(mask) {
                result.append(ConnectedRoute(address: address, mask: mask, index: index))
            }
        }
        return result
    }

    static func interfaceOwnsIPv4(index: UInt32, addresses: [String]) throws -> Bool {
        try connectedRoutes(indexes: [index]).contains { addresses.contains($0.address) }
    }

    private static func text(_ pointer: UnsafePointer<sockaddr>) -> String? {
        guard let offset = MemoryLayout<sockaddr_in>.offset(of: \.sin_addr),
              Int(pointer.pointee.sa_len) >= offset else { return nil }
        // BSD netmasks may omit trailing zero bytes. Read only the public
        // sockaddr's declared length, padding the remaining address with zero.
        let count = min(MemoryLayout<in_addr>.size, Int(pointer.pointee.sa_len) - offset)
        let source = UnsafeRawPointer(pointer).advanced(by: offset).assumingMemoryBound(to: UInt8.self)
        var address = in_addr()
        withUnsafeMutableBytes(of: &address) { target in
            for index in 0..<count { target[index] = source[index] }
        }
        var bytes = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        let capacity = socklen_t(bytes.count)
        guard inet_ntop(AF_INET, &address, &bytes, capacity) != nil else { return nil }
        return String(cString: bytes)
    }

    private static func prefix(address: String, mask: String, matching ip: UInt32) throws -> Int {
        func numeric(_ value: String) throws -> UInt32 {
            guard !value.utf8.contains(0) else { throw PolicyError.invalidRoute }
            var parsed = in_addr()
            guard value.withCString({ inet_pton(AF_INET, $0, &parsed) }) == 1 else { throw PolicyError.invalidRoute }
            return UInt32(bigEndian: parsed.s_addr)
        }
        let source = try numeric(address), bits = try numeric(mask)
        let inverse = ~bits
        guard inverse & (inverse &+ 1) == 0 else { throw PolicyError.invalidRoute }
        return (source & bits) == (ip & bits) ? bits.nonzeroBitCount : -1
    }
}
