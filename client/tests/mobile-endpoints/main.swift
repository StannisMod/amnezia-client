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

var idleHealth = EndpointHealthPolicy(staleMs: 10000)
require(idleHealth.sample(backend: 1, handshake: 100, tx: 10, rx: 10, now: 0) == .none, "initial healthy peer")
for now in stride(from: Int64(5000), through: 100000, by: 5000) {
    require(idleHealth.sample(backend: 1, handshake: 100, tx: 10, rx: 10, now: now) == .none, "idle is not an outage")
}
require(idleHealth.sample(backend: 1, handshake: 100, tx: 20, rx: 10, now: 105000) == .none, "first send gets grace")
require(idleHealth.sample(backend: 1, handshake: 101, tx: 30, rx: 10, now: 110000) == .none, "handshake is progress")
require(idleHealth.sample(backend: 1, handshake: 101, tx: 40, rx: 20, now: 115000) == .none, "incoming traffic is progress")

var outage = EndpointHealthPolicy(staleMs: 10000)
_ = outage.sample(backend: 1, handshake: 100, tx: 10, rx: 10, now: 0)
require(outage.sample(backend: 1, handshake: 100, tx: 20, rx: 10, now: 5000) == .none, "start stale interval")
require(outage.sample(backend: 1, handshake: 100, tx: 30, rx: 10, now: 10000) == .none, "wait full stale interval")
require(outage.sample(backend: 1, handshake: 100, tx: 40, rx: 10, now: 15000) == .refresh, "same-network outage requests DNS refresh")
for now in stride(from: Int64(20000), through: 190000, by: 5000) {
    require(outage.sample(backend: 1, handshake: 100, tx: UInt64(now), rx: 10, now: now) == .none, "old legacy handshake cannot reset budget")
}
require(outage.sample(backend: 1, handshake: 100, tx: 195000, rx: 10, now: 195000) == .refresh, "retry without a new handshake")
require(outage.sample(backend: 2, handshake: 0, tx: 0, rx: 0, now: 200000) == .none, "new backend is not proof of reachability")
require(outage.sample(backend: 2, handshake: 101, tx: 10, rx: 10, now: 205000) == .none, "real handshake completes recovery")

var sleeping = EndpointHealthPolicy(staleMs: 10000)
_ = sleeping.sample(backend: 1, handshake: 100, tx: 10, rx: 10, now: 0)
_ = sleeping.sample(backend: 1, handshake: 100, tx: 20, rx: 10, now: 5000)
require(sleeping.sample(backend: 1, handshake: 100, tx: 30, rx: 10, now: 60000) == .none, "wake-up gets a grace period")
_ = sleeping.sample(backend: 1, handshake: 100, tx: 40, rx: 10, now: 65000)
_ = sleeping.sample(backend: 1, handshake: 100, tx: 50, rx: 10, now: 70000)
require(sleeping.sample(backend: 1, handshake: 100, tx: 60, rx: 10, now: 75000) == .refresh, "real outage after wake-up still recovers")

var failures = EndpointHealthPolicy()
var epoch: UInt64 = 1
var refreshes = 0, exhausted = 0
for now in stride(from: Int64(0), through: 1000000, by: 5000) {
    switch failures.sample(backend: epoch, handshake: 0, tx: 0, rx: 0, now: now) {
    case .none: break
    case .refresh: refreshes += 1; epoch += 1
    case .exhausted: exhausted += 1
    }
}
require(refreshes == 6 && exhausted == 1, "finite mobile handshake recovery budget")
require(EndpointHealthPolicy.staleBudget(rekey: "120-600", reject: "180") == 1230000, "long AWG timer ranges")
print("Apple same-network endpoint health tests passed")
