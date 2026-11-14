import Foundation
#if canImport(NetworkExtension)
import NetworkExtension
#endif

// Addresses are parsed by IPAddressRange before constructing these routes.
struct OpenVPNRoute: Equatable {
    let address: String
    let prefixLength: Int
    var isIPv6: Bool { address.contains(":") }
}

#if canImport(NetworkExtension)
enum OpenVPNNetworkSettings {
    static func apply(_ policy: OpenVPNIPv6Policy, remoteIPv6: String?, providerExcluded: [NEIPv6Route],
                      to settings: NEPacketTunnelNetworkSettings) {
        guard !policy.included.isEmpty else { settings.ipv6Settings = nil; return }
        let ipv6 = settings.ipv6Settings
            ?? NEIPv6Settings(addresses: [OpenVPNIPv6Policy.captureAddress], networkPrefixLengths: [128])
        ipv6.includedRoutes = policy.included.map {
            NEIPv6Route(destinationAddress: $0.address, networkPrefixLength: NSNumber(value: $0.prefixLength))
        }
        var excluded = providerExcluded
        func exclude(_ subnet: OpenVPNRoute) {
            if !excluded.contains(where: { $0.destinationAddress == subnet.address &&
                $0.destinationNetworkPrefixLength.intValue == subnet.prefixLength }) {
                excluded.append(NEIPv6Route(destinationAddress: subnet.address,
                                            networkPrefixLength: NSNumber(value: subnet.prefixLength)))
            }
        }
        policy.excluded.forEach(exclude)
        if let remote = remoteIPv6 {
            exclude(OpenVPNRoute(address: remote, prefixLength: 128))
        }
        ipv6.excludedRoutes = excluded
        settings.ipv6Settings = ipv6
    }
}
#endif

struct OpenVPNIPv6Policy {
    static let captureAddress = "fd15:53b6:dead::2"
    let included: [OpenVPNRoute]
    let excluded: [OpenVPNRoute]

    static func permittedPackets(_ packets: [Data], protocols: [NSNumber], blockIPv6: Bool,
                                 ipv6Family: Int) -> ([Data], [NSNumber]) {
        guard packets.count == protocols.count else { return ([], []) }
        guard blockIPv6 else { return (packets, protocols) }
        var accepted: [Data] = []
        var families: [NSNumber] = []
        for (packet, family) in zip(packets, protocols) {
            if family.intValue == ipv6Family || packet.first.map({ $0 >> 4 == 6 }) == true { continue }
            accepted.append(packet)
            families.append(family)
        }
        return (accepted, families)
    }

    static func blocksIPv6(in config: String) -> Bool {
        var inlineTag: String?
        for raw in config.components(separatedBy: "\n") {
            let line = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if let tag = inlineTag {
                if line == "</\(tag)>" { inlineTag = nil }
                continue
            }
            if line.hasPrefix("<"), line.hasSuffix(">"), !line.hasPrefix("</") {
                inlineTag = String(line.dropFirst().dropLast())
                continue
            }
            let token = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).first
            if token == "block-ipv6" || token == "--block-ipv6" { return true }
        }
        return false
    }

    static func make(splitType: Int, routes: [OpenVPNRoute], dnsServers: [String]) -> OpenVPNIPv6Policy? {
        guard (0...2).contains(splitType), routes.allSatisfy({
            (0...($0.isIPv6 ? 128 : 32)).contains($0.prefixLength)
        }) else { return nil }
        let ipv6 = routes.filter(\.isIPv6)
        var included = splitType == 1 ? ipv6 : [OpenVPNRoute(address: "::", prefixLength: 0)]
        if splitType == 1 {
            for dns in dnsServers where dns.contains(":") {
                let route = OpenVPNRoute(address: dns, prefixLength: 128)
                if !included.contains(route) { included.append(route) }
            }
        }
        return OpenVPNIPv6Policy(included: included, excluded: splitType == 2 ? ipv6 : [])
    }

    // OpenVPN3 gets interface addresses from authenticated PUSH. Remove only
    // our OpenVPN2 fallback; never edit an administrator's address or credentials.
    static func adapterConfig(_ config: String) -> String {
        let inlineTags: Set<String> = ["ca", "cert", "key", "pkcs12", "tls-auth", "tls-crypt",
            "tls-crypt-v2", "secret", "crl-verify", "extra-certs"]
        var activeInlineTag: String?
        var managed = false
        let lines = config.components(separatedBy: "\n")
        var candidates = Set<Int>()
        var removals = Set<Int>()
        for (index, line) in lines.enumerated() {
            let token = line.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if let tag = activeInlineTag {
                if token == "</\(tag)>" { activeInlineTag = nil }
                continue
            }
            if token.hasPrefix("<"), token.hasSuffix(">"), !token.hasPrefix("</") {
                let tag = String(token.dropFirst().dropLast())
                if inlineTags.contains(tag) { activeInlineTag = tag }
            }
            if line == "# amnezia-ipv6-block-begin" { managed = true; candidates.removeAll() }
            if line == "# amnezia-ipv6-block-end" {
                if managed { removals.formUnion(candidates) }
                managed = false
            }
            if managed && (line == "ifconfig-ipv6 fd15:53b6:dead::2/64 fd15:53b6:dead::1"
                || line == "setenv opt disable-dco") { candidates.insert(index) }
        }
        return lines.enumerated().filter { !removals.contains($0.offset) }.map(\.element).joined(separator: "\n")
    }
}
