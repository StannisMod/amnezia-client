#ifndef AMNEZIA_OPENVPN_NATIVE_DNS_OPTIONS_HPP
#define AMNEZIA_OPENVPN_NATIVE_DNS_OPTIONS_HPP
#include <openvpn/client/dns.hpp>

namespace amnezia {
// Until the policy-aware Android adapter represents the complete negotiated
// metadata, never let OpenVPN3's legacy flat callback bridge erase it.
inline bool nativeDNSOptionsRepresentable(const openvpn::DnsOptions &options)
{
    if (options.servers.size() > 1) return false;
    for (const auto &entry : options.servers)
    {
        const auto &server = entry.second;
        if (server.port4 > 65535 || server.port6 > 65535
            || server.domain_type != openvpn::DnsServer::DomainType::Unset
            || !server.domains.empty()
            || server.dnssec != openvpn::DnsServer::Security::Unset
            || (server.transport != openvpn::DnsServer::Transport::Unset
                && server.transport != openvpn::DnsServer::Transport::Plain
                && server.transport != openvpn::DnsServer::Transport::TLS)
            || (!server.sni.empty() && server.transport != openvpn::DnsServer::Transport::TLS))
            return false;
    }
    return true;
}
} // namespace amnezia
#endif
