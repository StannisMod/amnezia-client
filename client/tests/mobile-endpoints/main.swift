import Foundation

func require(_ value: @autoclosure () -> Bool, _ message: String) {
    if !value() { fatalError(message) }
}
var policy = EndpointRefreshPolicy()
let first = policy.begin()
require((0..<6).compactMap { _ in policy.nextDelay(for: first) } == [0, 1, 2, 4, 8, 16], "bounded backoff")
require(policy.nextDelay(for: first) == nil, "six attempts exhaust the budget")
let replacement = policy.begin()
require(!policy.accepts(first), "new path invalidates old DNS result")
require(policy.nextDelay(for: first) == nil, "old callback cannot consume new path's budget")
require(policy.nextDelay(for: replacement) == 0, "new path starts immediately")
policy.cancel()
require(!policy.accepts(replacement), "stop invalidates pending DNS")

func config(_ host: String) throws -> WGConfig {
    let raw: [String: Any] = ["dns1": "1.1.1.1", "dns2": "", "mtu": "1280", "hostName": host,
        "port": 51820, "client_ip": "10.8.0.2/32", "client_priv_key": "PRIVATE", "server_pub_key": "PUBLIC",
        "allowed_ips": ["0.0.0.0/0", "::/0"], "splitTunnelType": 0, "splitTunnelSites": []]
    return try JSONDecoder().decode(WGConfig.self, from: JSONSerialization.data(withJSONObject: raw))
}
let domain = try config("vpn.example.org")
require(domain.hostName == "vpn.example.org", "profile retains the domain")
require(domain.str.contains("Endpoint = vpn.example.org:51820"), "domain survives native export")
require(domain.str.contains("PrivateKey = PRIVATE"), "endpoint handling preserves the client key")
let ipv6 = try config("2001:db8::1")
require(ipv6.str.contains("Endpoint = [2001:db8::1]:51820"), "IPv6 endpoints need brackets")
let bracketed = try config("[2001:db8::1]")
require(bracketed.str.contains("Endpoint = [2001:db8::1]:51820"), "IPv6 must not be bracketed twice")
print("Apple endpoint policy and config tests passed")
