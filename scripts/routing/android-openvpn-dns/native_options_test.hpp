#ifndef AMNEZIA_OPENVPN_NATIVE_OPTIONS_TEST_HPP
#define AMNEZIA_OPENVPN_NATIVE_OPTIONS_TEST_HPP
#include <openvpn/io/io.hpp>
#include <openvpn/log/lognull.hpp>
#include "native_dns_options.hpp"
namespace {
void testNativeDNSMetadataNeverFlattens()
{
    openvpn::OptionList empty;
    openvpn::DnsOptions options(empty);
    assert(amnezia::nativeDNSOptionsRepresentable(options));
    options.search_domains = {"first.example", "second.example", "first.example"};
    options.servers.emplace(-3, openvpn::DnsServer{});
    auto &server = options.servers.at(-3);
    assert(amnezia::nativeDNSOptionsRepresentable(options));
    server.port4=53; server.port6=53;
    server.transport=openvpn::DnsServer::Transport::Plain;
    assert(amnezia::nativeDNSOptionsRepresentable(options));
    server.port4=5353;
    assert(amnezia::nativeDNSOptionsRepresentable(options)); server.port4=65536;
    assert(!amnezia::nativeDNSOptionsRepresentable(options)); server.port4=53;
    server.port6=853;
    assert(amnezia::nativeDNSOptionsRepresentable(options)); server.port6=65536;
    assert(!amnezia::nativeDNSOptionsRepresentable(options)); server.port6=53;
    server.transport=openvpn::DnsServer::Transport::TLS;
    assert(amnezia::nativeDNSOptionsRepresentable(options));
    server.sni="selected.example";
    assert(amnezia::nativeDNSOptionsRepresentable(options));
    server.sni.clear();
    server.transport=openvpn::DnsServer::Transport::HTTPS;
    assert(!amnezia::nativeDNSOptionsRepresentable(options)); // No guessed DoH URI.
    server.transport=openvpn::DnsServer::Transport::Plain;
    for (auto value : {openvpn::DnsServer::Security::No, openvpn::DnsServer::Security::Yes,
                       openvpn::DnsServer::Security::Optional}) {
        server.dnssec=value;
        assert(!amnezia::nativeDNSOptionsRepresentable(options));
    }
    server.dnssec=openvpn::DnsServer::Security::Unset;
    server.sni="selected.example"; assert(!amnezia::nativeDNSOptionsRepresentable(options));
    server.sni.clear();
    server.domain_type=openvpn::DnsServer::DomainType::Resolve;
    assert(!amnezia::nativeDNSOptionsRepresentable(options));
    server.domain_type=openvpn::DnsServer::DomainType::Exclude;
    assert(!amnezia::nativeDNSOptionsRepresentable(options));
    server.domain_type=openvpn::DnsServer::DomainType::Unset;
    server.domains={"selected.example"}; assert(!amnezia::nativeDNSOptionsRepresentable(options));
    server.domains.clear();
    options.servers.emplace(4,openvpn::DnsServer{});
    assert(!amnezia::nativeDNSOptionsRepresentable(options));
    assert(options.search_domains.size()==3 && options.search_domains.front()==options.search_domains.back());
}
}
#endif
