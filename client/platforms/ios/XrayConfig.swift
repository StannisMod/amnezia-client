import Foundation
import NetworkExtension

struct XrayConfig: Decodable {
    let dns1: String?
    let dns2: String?
    let splitTunnelType: Int?
    let splitTunnelSites: [String]?
    let config: String
}

struct XrayRoute {
    let address: String
    let prefixLength: Int
}

enum XrayNetworkSettings {
    static func make() -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "254.1.1.1")
        settings.mtu = 9000
        settings.ipv4Settings = NEIPv4Settings(addresses: ["198.18.0.1"], subnetMasks: ["255.255.0.0"])
        settings.ipv4Settings?.includedRoutes = [NEIPv4Route.default()]
        settings.ipv6Settings = NEIPv6Settings(addresses: ["fd6e:a81b:704f:1211::1"], networkPrefixLengths: [64])
        settings.ipv6Settings?.includedRoutes = [NEIPv6Route.default()]
        return settings
    }

    // Addresses and prefixes come from the app's existing IPAddressRange parser.
    // Validate the whole list before changing either family's routes.
    @discardableResult
    static func applySplit(type: Int, routes: [XrayRoute], to settings: NEPacketTunnelNetworkSettings) -> Bool {
        guard routes.allSatisfy({ (0...($0.address.contains(":") ? 128 : 32)).contains($0.prefixLength) }) else {
            return false
        }
        var ipv4 = [NEIPv4Route]()
        var ipv6 = [NEIPv6Route]()
        for route in routes {
            if route.address.contains(":") {
                ipv6.append(NEIPv6Route(destinationAddress: route.address, networkPrefixLength: NSNumber(value: route.prefixLength)))
            } else {
                let mask = route.prefixLength == 0 ? UInt32(0) : UInt32.max << UInt32(32 - route.prefixLength)
                let dotted = (0..<4).map { String((mask >> UInt32((3 - $0) * 8)) & 255) }.joined(separator: ".")
                ipv4.append(NEIPv4Route(destinationAddress: route.address, subnetMask: dotted))
            }
        }
        if type == 1 {
            settings.ipv4Settings?.includedRoutes = ipv4
            settings.ipv6Settings?.includedRoutes = ipv6
        } else if type == 2 {
            settings.ipv4Settings?.excludedRoutes = ipv4
            settings.ipv6Settings?.excludedRoutes = ipv6
        }
        return true
    }
}
