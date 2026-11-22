import Foundation
import NetworkExtension

func require(_ value: @autoclosure () -> Bool, _ message: String) {
    if !value() { fatalError(message) }
}

func original() -> NEPacketTunnelNetworkSettings {
    let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "203.0.113.10")
    settings.mtu = 1400
    settings.ipv4Settings = NEIPv4Settings(addresses: ["10.77.0.2"], subnetMasks: ["255.255.255.0"])
    settings.ipv4Settings?.includedRoutes = [NEIPv4Route.default()]
    settings.ipv4Settings?.excludedRoutes = [
        NEIPv4Route(destinationAddress: "192.168.0.0", subnetMask: "255.255.0.0")]
    settings.ipv6Settings = NEIPv6Settings(addresses: ["fd77::2"], networkPrefixLengths: [64])
    settings.ipv6Settings?.includedRoutes = [NEIPv6Route.default()]
    let dns = NEDNSSettings(servers: ["10.77.0.53", "192.168.1.53", "2001:db8::53"])
    dns.domainName = "corp.example"
    dns.searchDomains = ["corp.example", "lab.example"]
    dns.matchDomains = ["corp.example"]
    dns.matchDomainsNoSearch = true
    settings.dnsSettings = dns
    return settings
}

let source = original()
let plan = try NativeDNSSettings(original: source, paths: ["10.77.0.53": .tunnel, "192.168.1.53": .underlay])
require(plan.bindings.map(\.upstream) == source.dnsSettings!.servers, "resolver list/order changed")
require(plan.bindings.map(\.path) == [.tunnel, .underlay, .unavailable], "scope or IPv6 OFF policy changed")
require(Set(plan.bindings.map(\.address)).count == 3, "original resolvers share a capture endpoint")
require(plan.settings.dnsSettings!.servers == plan.bindings.map(\.address), "published DNS differs from prepared endpoints")
require(source.dnsSettings!.servers == ["10.77.0.53", "192.168.1.53", "2001:db8::53"], "original settings mutated")
require(source.ipv4Settings!.includedRoutes!.count == 1, "source routes mutated")
require(plan.settings.ipv4Settings!.includedRoutes!.count == 4, "capture /32 routes absent")
require(plan.settings.ipv4Settings!.excludedRoutes!.count == 1, "native split exclusions changed")
require(plan.settings.dnsSettings!.matchDomains == source.dnsSettings!.matchDomains &&
        plan.settings.dnsSettings!.domainName == source.dnsSettings!.domainName &&
        plan.settings.dnsSettings!.searchDomains == source.dnsSettings!.searchDomains &&
        plan.settings.dnsSettings!.matchDomainsNoSearch, "DNS domain scope/search metadata changed")
require(plan.settings.mtu == source.mtu &&
        plan.settings.ipv6Settings!.addresses == source.ipv6Settings!.addresses, "native link settings changed")

do {
    _ = try NativeDNSSettings(original: original(), paths: [:])
    fatalError("missing resolver scope selected an implicit path")
} catch NativeDNSSettings.PlanError.invalidSettings {}

let ipv6Only = original()
ipv6Only.dnsSettings = NEDNSSettings(servers: ["2001:db8::53", "fe80::53%en0"])
let denied = try NativeDNSSettings(original: ipv6Only, paths: [:])
require(denied.bindings.count == 2 && denied.bindings.allSatisfy { $0.path == .unavailable },
        "IPv6-only DNS got a transport exception")

let encrypted = original()
encrypted.dnsSettings = NEDNSOverHTTPSSettings(servers: ["192.0.2.53"])
do {
    _ = try NativeDNSSettings(original: encrypted, paths: [:])
    fatalError("encrypted DNS was downgraded to plaintext")
} catch NativeDNSSettings.PlanError.encryptedDNS {}

let collision = original()
collision.ipv4Settings?.excludedRoutes?.append(
    NEIPv4Route(destinationAddress: "198.19.255.0", subnetMask: "255.255.255.0"))
do {
    _ = try NativeDNSSettings(original: collision, paths: ["10.77.0.53": .tunnel, "192.168.1.53": .underlay])
    fatalError("capture overrode a specific user route")
} catch NativeDNSSettings.PlanError.noCaptureAddress {}

let exactCollision = original()
exactCollision.dnsSettings = NEDNSSettings(servers: ["198.19.255.1", "198.19.255.2"])
let avoiding = try NativeDNSSettings(original: exactCollision,
    paths: ["198.19.255.1": .tunnel, "198.19.255.2": .tunnel])
require(avoiding.bindings.allSatisfy { !exactCollision.dnsSettings!.servers.contains($0.address) },
        "managed DNS recursively forwards to itself or another endpoint")

let duplicate = original()
duplicate.dnsSettings = NEDNSSettings(servers: ["10.77.0.53", "10.77.0.53"])
let duplicates = try NativeDNSSettings(original: duplicate, paths: ["10.77.0.53": .tunnel])
require(duplicates.bindings.count == 2 && duplicates.bindings[0].address != duplicates.bindings[1].address,
        "server list was silently deduplicated")

print("PASS: native DNS per-server settings, explicit scope, strict IPv6 OFF, metadata, collision and no downgrade")

let routeSettings = original()
let lan = [NativeDNSRoute.ConnectedRoute(address: "192.168.1.10", mask: "255.255.255.0", index: 7)]
func selected(_ server: String, all: Bool = false, enforce: Bool = false, local: Bool = false,
              routes: [NativeDNSRoute.ConnectedRoute] = lan) throws -> NativeDNSSettings.Path {
    try NativeDNSRoute.path(server: server, settings: routeSettings, connected: routes,
                           includeAll: all, enforce: enforce, excludeLocal: local)
}
let tunnelDNS = try selected("10.77.0.53")
require(tunnelDNS == .tunnel, "native connected-subnet DNS lost tunnel scope")
let publicDNS = try selected("192.0.2.53")
require(publicDNS == .tunnel, "native full route was not retained")
let lanDNS = try selected("192.168.1.53")
require(lanDNS == .interface(7), "more specific connected underlay DNS scope changed")
let fullPolicy = try selected("192.168.1.53", all: true)
require(fullPolicy == .tunnel, "includeAllNetworks policy was ignored")
let excludedLocal = try selected("192.168.1.53", all: true, local: true)
require(excludedLocal == .interface(7), "explicit local-network exclusion was ignored")
routeSettings.ipv4Settings?.includedRoutes = [
    NEIPv4Route(destinationAddress: "10.77.0.0", subnetMask: "255.255.255.0")]
let splitDirect = try selected("192.0.2.53")
require(splitDirect == .underlay, "include-only native DNS was forced through tunnel")
routeSettings.ipv4Settings?.includedRoutes = [NEIPv4Route.default()]
let enforced = try selected("192.168.1.53", enforce: true)
require(enforced == .underlay, "enforced explicit exclusion lost primary underlay scope")
routeSettings.ipv4Settings?.excludedRoutes = []
let enforcedTunnel = try selected("192.168.1.53", enforce: true)
require(enforcedTunnel == .tunnel, "enforced native route was overridden by local subnet")
let ambiguous = try selected("192.168.1.53", routes: lan + [
    NativeDNSRoute.ConnectedRoute(address: "192.168.1.20", mask: "255.255.255.0", index: 8)])
require(ambiguous == .unavailable, "ambiguous local DNS scope silently chose another interface")
let deniedV6 = try selected("2001:db8::53", all: true)
require(deniedV6 == .unavailable, "includeAllNetworks enabled IPv6 DNS transport")
routeSettings.ipv4Settings?.includedRoutes = [
    NEIPv4Route(destinationAddress: "192.0.2.0", subnetMask: "255.0.255.0")]
do {
    _ = try selected("192.0.2.53")
    fatalError("invalid native route selected an upstream path")
} catch NativeDNSRoute.PolicyError.invalidRoute {}
print("PASS: public native DNS policy full/include/exclude, connected interfaces, enforcement and strict OFF")
