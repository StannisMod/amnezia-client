import Foundation
#if canImport(NetworkExtension)
import NetworkExtension
#endif

func require(_ value: Bool, _ message: String) { precondition(value, message) }
let defaults = [OpenVPNRoute(address: "::", prefixLength: 0)]
let v4 = OpenVPNRoute(address: "192.0.2.0", prefixLength: 24)
let v6 = [OpenVPNRoute(address: "2001:db8::", prefixLength: 32),
          OpenVPNRoute(address: "fd99::", prefixLength: 16),
          OpenVPNRoute(address: "64:ff9b::", prefixLength: 96)]
let full = OpenVPNIPv6Policy.make(splitType: 0, routes: [], dnsServers: [])!
for splitType in 0...2 {
    let blocked = OpenVPNIPv6Policy.make(splitType: splitType,
        routes: [OpenVPNRoute(address: "192.0.2.0", prefixLength: 24),
                 OpenVPNRoute(address: "2001:db8::", prefixLength: 32)],
        dnsServers: [], blockIPv6: true)!
    require(blocked.included == [OpenVPNRoute(address: "::", prefixLength: 0)],
            "IPv6 OFF must capture all IPv6 in every split mode")
    require(blocked.excluded.isEmpty, "IPv6 OFF must not restore site exclusions")
}
require(full.included == defaults && full.excluded.isEmpty, "Full capture includes GUA, ULA and NAT64")
let include4 = OpenVPNIPv6Policy.make(splitType: 1, routes: [v4], dnsServers: [])!
require(include4.included.isEmpty && include4.excluded.isEmpty, "IPv4-only inclusion leaves IPv6 direct")
let include6 = OpenVPNIPv6Policy.make(splitType: 1, routes: [v4] + v6, dnsServers: [])!
require(include6.included == v6 && include6.excluded.isEmpty, "IPv6 inclusions use the right address family")
let dns = OpenVPNIPv6Policy.make(splitType: 1, routes: [v4], dnsServers: ["1.1.1.1", "fd42::53", "fd42::53"])!
require(dns.included == [OpenVPNRoute(address: "fd42::53", prefixLength: 128)], "Selected DNS stays in the VPN without capturing unrelated IPv6")
let exclude = OpenVPNIPv6Policy.make(splitType: 2, routes: [v4] + v6, dnsServers: [])!
require(exclude.included == defaults && exclude.excluded == v6, "Mixed exclusions retain IPv6 default and direct exceptions")
require(OpenVPNIPv6Policy.make(splitType: 3, routes: [], dnsServers: []) == nil, "Reject unknown mode")
require(OpenVPNIPv6Policy.make(splitType: 1, routes: [OpenVPNRoute(address: "::", prefixLength: 129)], dnsServers: []) == nil, "Reject invalid prefix")
let address = "ifconfig-ipv6 fd15:53b6:dead::2/64 fd15:53b6:dead::1"
let managed = "# amnezia-ipv6-block-begin\n\(address)\nsetenv opt disable-dco\nblock-ipv6\nroute-ipv6 fd99::/16\n# amnezia-ipv6-block-end\n"
let adapted = OpenVPNIPv6Policy.adapterConfig(managed)
require(!adapted.contains(address) && adapted.contains("block-ipv6\nroute-ipv6 fd99::/16"), "Remove only the owned address, retain blocking and routes")
require(!adapted.contains("disable-dco"), "The userspace Apple adapter does not receive the managed OpenVPN2 DCO toggle")
require(OpenVPNIPv6Policy.adapterConfig(adapted) == adapted, "Adaptation is idempotent")
require(OpenVPNIPv6Policy.adapterConfig(address) == address, "Preserve explicit administrator address")
let inline = "<key>\n\(managed)</key>\n"
require(OpenVPNIPv6Policy.adapterConfig(inline) == inline, "Do not edit credentials")
let incomplete = "# amnezia-ipv6-block-begin\n\(address)\n"
require(OpenVPNIPv6Policy.adapterConfig(incomplete) == incomplete, "Do not reinterpret an incomplete managed block")
let credentialInside = "# amnezia-ipv6-block-begin\n<key>\n\(address)\n</key>\n# amnezia-ipv6-block-end\n"
require(OpenVPNIPv6Policy.adapterConfig(credentialInside) == credentialInside, "Do not edit inline data inside a managed block")
require(OpenVPNIPv6Policy.blocksIPv6(in: managed), "Managed legacy profile blocks IPv6")
require(!OpenVPNIPv6Policy.blocksIPv6(in: "<key>\nblock-ipv6\n</key>\n# block-ipv6\n"), "Credential and comment contents are not options")
let packets = [Data([0x45, 1]), Data([0x60, 2]), Data([0x45, 3])]
let families: [NSNumber] = [2, 30, 2]
let blocked = OpenVPNIPv6Policy.permittedPackets(packets, protocols: families, blockIPv6: true, ipv6Family: 30)
require(blocked.0 == [packets[0], packets[2]] && blocked.1 == [2, 2], "IPv6 blocking retains exact IPv4 bytes and order")
let allowed = OpenVPNIPv6Policy.permittedPackets(packets, protocols: families, blockIPv6: false, ipv6Family: 30)
require(allowed.0 == packets && allowed.1 == families, "Authenticated dual-stack sessions retain all packet bytes")
require(OpenVPNIPv6Policy.permittedPackets([Data([0x60])], protocols: [2], blockIPv6: true, ipv6Family: 30).0.isEmpty, "IPv6 header cannot bypass blocking with the wrong family tag")
require(OpenVPNIPv6Policy.permittedPackets([Data([0x45])], protocols: [30], blockIPv6: true, ipv6Family: 30).0.isEmpty, "IPv6 family cannot bypass blocking with the wrong header")
require(OpenVPNIPv6Policy.permittedPackets(packets, protocols: [], blockIPv6: false, ipv6Family: 30).0.isEmpty, "Mismatched packet metadata is rejected")
require(CommandLine.arguments.count == 2, "Pass the Qt-checked OpenVPN policy fixture")
let fixture = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))) as! [String: String]
require(fixture.count == 9, "Every canonical Qt policy must be checked")
for (name, config) in fixture {
    let output = OpenVPNIPv6Policy.adapterConfig(config)
    let originalRoutes = config.components(separatedBy: "\n").filter { $0.hasPrefix("route-ipv6 ") }
    let adaptedRoutes = output.components(separatedBy: "\n").filter { $0.hasPrefix("route-ipv6 ") }
    require(originalRoutes == adaptedRoutes, "Preserve Qt IPv6 scope: \(name)")
    require(OpenVPNIPv6Policy.blocksIPv6(in: config) == OpenVPNIPv6Policy.blocksIPv6(in: output), "Preserve Qt family blocking: \(name)")
    require(OpenVPNIPv6Policy.adapterConfig(output) == output, "Canonical adaptation is idempotent: \(name)")
}
#if canImport(NetworkExtension)
let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "192.0.2.1")
settings.ipv4Settings = NEIPv4Settings(addresses: ["10.8.0.2"], subnetMasks: ["255.255.255.0"])
OpenVPNNetworkSettings.apply(full, remoteIPv6: "2001:db8::1", providerExcluded: [], to: settings)
require(settings.ipv6Settings?.addresses == [OpenVPNIPv6Policy.captureAddress], "Legacy server gets a local IPv6 capture address")
require(settings.ipv6Settings?.includedRoutes?.first?.destinationNetworkPrefixLength.intValue == 0, "Legacy IPv6 is captured")
require(settings.ipv6Settings?.excludedRoutes?.last?.destinationAddress == "2001:db8::1", "IPv6 transport endpoint remains outside its own tunnel")
require(settings.ipv4Settings?.addresses == ["10.8.0.2"], "IPv6 application preserves IPv4 settings")
settings.ipv6Settings = NEIPv6Settings(addresses: ["fd42::2"], networkPrefixLengths: [64])
let providerException = NEIPv6Route(destinationAddress: "2001:db8:beef::", networkPrefixLength: 48)
OpenVPNNetworkSettings.apply(full, remoteIPv6: nil, providerExcluded: [providerException], to: settings)
require(settings.ipv6Settings?.excludedRoutes?.first === providerException, "Explicit provider exceptions are preserved")
for splitType in 0...2 {
    let blocked = OpenVPNIPv6Policy.make(splitType: splitType, routes: [v4], dnsServers: [], blockIPv6: true)!
    OpenVPNNetworkSettings.apply(blocked, remoteIPv6: "2001:db8::1",
                                providerExcluded: [providerException], to: settings, blockIPv6: true)
    require(settings.ipv6Settings?.includedRoutes?.first?.destinationNetworkPrefixLength.intValue == 0,
            "IPv6 OFF captures the entire family")
    require(settings.ipv6Settings?.excludedRoutes?.count == 1 &&
            settings.ipv6Settings?.excludedRoutes?.first?.destinationAddress == "2001:db8::1",
            "IPv6 OFF preserves only the transport endpoint exception")
}
OpenVPNNetworkSettings.apply(include6, remoteIPv6: nil, providerExcluded: [], to: settings)
require(settings.ipv6Settings?.addresses == ["fd42::2"], "Authenticated server address is preserved")
require(settings.ipv6Settings?.includedRoutes?.count == 3, "Actual NE settings receive every selected IPv6 range")
require(settings.ipv6Settings?.excludedRoutes?.isEmpty == true, "Previous owned exceptions do not survive a new policy")
OpenVPNNetworkSettings.apply(exclude, remoteIPv6: nil, providerExcluded: [], to: settings)
require(settings.ipv6Settings?.excludedRoutes?.count == 3, "Actual NE exclusions keep both families separate")
OpenVPNNetworkSettings.apply(include4, remoteIPv6: nil, providerExcluded: [], to: settings)
require(settings.ipv6Settings == nil, "Unselected IPv6 remains direct")
#endif
print("Apple OpenVPN IPv6 policy tests passed")
