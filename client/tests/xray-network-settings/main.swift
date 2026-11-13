import Foundation
import NetworkExtension

func require(_ value: Bool, _ message: String) {
    precondition(value, message)
}

let full = XrayNetworkSettings.make()
require(full.ipv4Settings?.includedRoutes?.count == 1, "IPv4 full capture")
require(full.ipv6Settings?.includedRoutes?.first?.destinationNetworkPrefixLength.intValue == 0, "IPv6 full capture")
require(full.ipv6Settings?.addresses == ["fd6e:a81b:704f:1211::1"], "IPv6 TUN address")

let selected = XrayNetworkSettings.make()
require(XrayNetworkSettings.applySplit(type: 1, routes: [XrayRoute(address: "192.0.2.0", prefixLength: 24)], to: selected), "IPv4 include policy")
require(selected.ipv4Settings?.includedRoutes?.first?.destinationSubnetMask == "255.255.255.0", "IPv4 netmask")
require(selected.ipv6Settings?.includedRoutes?.isEmpty == true, "IPv4 selection does not capture unrelated IPv6")

let mixed = XrayNetworkSettings.make()
require(XrayNetworkSettings.applySplit(type: 1, routes: [
    XrayRoute(address: "2001:db8::", prefixLength: 32),
    XrayRoute(address: "fd42::", prefixLength: 64),
    XrayRoute(address: "64:ff9b::", prefixLength: 96)
], to: mixed), "IPv6 include policy")
require(mixed.ipv4Settings?.includedRoutes?.isEmpty == true, "IPv6 selection does not capture unrelated IPv4")
require(mixed.ipv6Settings?.includedRoutes?.map { $0.destinationNetworkPrefixLength.intValue } == [32, 64, 96], "GUA, ULA and NAT64 prefixes")

let excluded = XrayNetworkSettings.make()
require(XrayNetworkSettings.applySplit(type: 2, routes: [
    XrayRoute(address: "192.0.2.1", prefixLength: 32),
    XrayRoute(address: "2001:db8::1", prefixLength: 128)
], to: excluded), "Mixed exclusions")
require(excluded.ipv4Settings?.excludedRoutes?.count == 1 && excluded.ipv6Settings?.excludedRoutes?.count == 1, "Family-specific exclusions")
require(excluded.ipv6Settings?.includedRoutes?.first?.destinationNetworkPrefixLength.intValue == 0, "Exclusions preserve full IPv6 default")
require(!XrayNetworkSettings.applySplit(type: 1, routes: [XrayRoute(address: "::", prefixLength: 129)], to: excluded), "Reject invalid prefix before mutation")
require(excluded.ipv6Settings?.includedRoutes?.first?.destinationNetworkPrefixLength.intValue == 0, "Invalid policy leaves previous capture intact")
print("Apple Xray IPv4/IPv6 network settings tests passed")
