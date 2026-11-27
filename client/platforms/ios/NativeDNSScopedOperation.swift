import Foundation
import Network
import NetworkExtension

// The native connection supplies an explicit scope from its public routing
// policy. No kernel routing-message ABI or implicit default-network dialer is
// used. The returned per-query operation owns cancellation and its deadline.
enum NativeDNSScopedOperation {
    static func start(provider: NEPacketTunnelProvider, binding: NativeDNSSettings.Binding,
                      interface: (UInt32?) -> Network.NWInterface?,
                      query: Data, transport: NativeDNSTransport, timeout: TimeInterval,
                      completion: @escaping (Result<Data, Error>) -> Void) throws -> NativeDNSOperation {
        let scope: NativeDNSResolver.Scope
        switch binding.path {
        case .tunnel: scope = .tunnel
        case .loopback: scope = .loopback
        case .underlay:
            guard let selected = interface(nil) else { throw NativeDNSResolverError.scopeUnavailable }
            scope = .interface(selected)
        case .interface(let index):
            guard let selected = interface(index) else { throw NativeDNSResolverError.scopeUnavailable }
            scope = .interface(selected)
        case .unavailable: throw NativeDNSResolverError.scopeUnavailable
        }
        let resolver = try NativeDNSResolver(provider: provider, server: binding.upstream, scope: scope)
        return try resolver.exchange(query, transport: transport, timeout: timeout, completion: completion)
    }
}
