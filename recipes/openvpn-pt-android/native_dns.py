"""Checked Android OpenVPN3 sole-reader DNS ingress/egress overlay."""
import hashlib
from pathlib import Path

EXPECTED = {
    "openvpn/tun/builder/base.hpp": "4cc88fbe5d2aeb203227ff920d8c8185befa26244fb4e20018c923eca14718ac",
    "openvpn/tun/builder/client.hpp": "1e00993e03cd6247d8a588aba4f99fba7fa674dea6301a0eeeba32148d31a0e5",
    "client/ovpncli.i": "08b9d4dac15eaee63c832e1d74306741ae9541363917dd7c3352d3f33962f7cb",
    "openvpn/client/async_resolve/asio.hpp": "d0140d999afd64d857ba3b027a90c3dc604317907c60f709e0da5d5c9a225382",
    "openvpn/tun/client/tunprop.hpp": "42269f293ec75a2446baed4896cd1431f5ae00cc9f55bed1678fc5170ab17f5e",
}


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise ValueError("Pinned OpenVPN3 hook changed: " + before[:100])
    return text.replace(before, after, 1)


def prepare(source, support):
    """Return a tiny include/SWIG overlay, without copying an OpenVPN build tree."""
    source, support = Path(source), Path(support)
    original = {name: (source / name).read_bytes() for name in EXPECTED}
    for name, data in original.items():
        if hashlib.sha256(data).hexdigest() != EXPECTED[name]:
            raise ValueError("Unexpected native OpenVPN3 source: " + name)
    base = original["openvpn/tun/builder/base.hpp"].decode()
    base = replace_once(base, "#include <string>", '''#include <string>
#include <openvpn/common/platform.hpp>
#ifdef OPENVPN_PLATFORM_ANDROID
#include "native_dns_owner.hpp"
#endif''')
    base = replace_once(base, "  public:\n", "  public:\n" + (support / "native_dns_base.inc").read_text() + "\n")
    client = original["openvpn/tun/builder/client.hpp"].decode()
    client = replace_once(client, '''        if (disconnected)
            tun_persist.reset();''', '''        if (disconnected)
        {
#ifdef OPENVPN_PLATFORM_ANDROID
            if (builder) builder->amnezia_dns_stop();
#endif
            tun_persist.reset();
        }''')
    client = replace_once(client, '''                    // reset target tun builder object
                    if (!tb->tun_builder_new())''', '''                    // Prepare the next DNS generation before Android publication.
#ifdef OPENVPN_PLATFORM_ANDROID
                    tb->amnezia_dns_begin();
#endif
                    // reset target tun builder object
                    if (!tb->tun_builder_new())''')
    client = replace_once(client, '''                impl->start(config->n_parallel);''', '''#ifdef OPENVPN_PLATFORM_ANDROID
                dns_engine = amnezia::NativeDNSEngine::create(
                    [this](std::function<void()> operation) {
                        openvpn_io::post(io_context, std::move(operation));
                    },
                    [this](const uint8_t *bytes, int size) {
                        Ptr retained(this);
                        if (halt || !impl) return;
                        if (!config->builder->tun_builder_dns_tunnel_allowed()) {
                            parent.tun_error(Error::TUN_READ_ERROR, "native DNS tunnel scope no longer admitted");
                            return;
                        }
                        try {
                            BufferAllocated packet;
                            (*config->frame)[Frame::READ_TUN].prepare(packet);
                            packet.write(bytes, size);
                            if (config->stats) {
                                config->stats->inc_stat(SessionStats::TUN_BYTES_IN, size);
                                config->stats->inc_stat(SessionStats::TUN_PACKETS_IN, 1);
                            }
                            parent.tun_recv(packet);
                        } catch (const std::exception &e) {
                            parent.tun_error(Error::TUN_READ_ERROR, e.what());
                        }
                    });
                if (!config->builder->amnezia_dns_attach(sd, config->tun_prefix, dns_engine))
                    throw tun_builder_error("native DNS capture attachment failed");
#endif
                impl->start(config->n_parallel);''')
    client = replace_once(client, '''        parent.tun_recv(pfp->buf);''', '''#ifdef OPENVPN_PLATFORM_ANDROID
        const auto handled = config->builder->amnezia_dns_feed(
            pfp->buf.data(), static_cast<int>(pfp->buf.size()));
        if (handled != 0)
        {
            if (handled < 0)
                parent.tun_error(Error::TUN_READ_ERROR, "native DNS frontend failed");
            return;
        }
#endif
        parent.tun_recv(pfp->buf);''')
    client = replace_once(client, '''    bool send(Buffer &buf)
    {
        if (impl)''', '''    bool send(Buffer &buf)
    {
#ifdef OPENVPN_PLATFORM_ANDROID
        // OFF has no inbound IPv6 data/control-plane exception either.
        if (config->builder->amnezia_dns_active() && buf.size() && (buf[0] >> 4) == 6)
            return true;
        const auto dns_handled = config->builder->amnezia_dns_feed_tunnel(
            buf.data(), static_cast<int>(buf.size()));
        if (dns_handled != 0)
        {
            if (dns_handled < 0)
                parent.tun_error(Error::TUN_READ_ERROR, "native DNS tunnel frontend failed");
            return true;
        }
#endif
        if (impl)''')
    client = replace_once(client, '''            halt = true;

            // stop tun''', '''            halt = true;
#ifdef OPENVPN_PLATFORM_ANDROID
            if (dns_engine) dns_engine->quiesce();
            config->builder->amnezia_dns_quiesce();
#endif

            // stop tun''')
    client = replace_once(client, '''            tun_persist.reset();
        }
    }


    openvpn_io::io_context''', '''            tun_persist.reset();
#ifdef OPENVPN_PLATFORM_ANDROID
            if (dns_engine) dns_engine->close();
#endif
        }
    }


    openvpn_io::io_context''')
    client = replace_once(client, "    openvpn_io::io_context &io_context;", '''#ifdef OPENVPN_PLATFORM_ANDROID
    amnezia::NativeDNSEngine::Ptr dns_engine;
#endif
    openvpn_io::io_context &io_context;''')
    interface = original["client/ovpncli.i"].decode()
    # ovpncli.cpp owns OpenVPN's process globals. The director now also sees
    # Base64 through the DNS owner header, and must only DECLARE those globals.
    interface = replace_once(interface, '#include "ovpncli.hpp"',
                             '#define OPENVPN_EXTERN extern\n#include "ovpncli.hpp"')
    interface = replace_once(interface, '%include "openvpn/tun/builder/base.hpp"', '''
%ignore openvpn::TunBuilderBase::amnezia_dns_begin;
%ignore openvpn::TunBuilderBase::amnezia_dns_attach;
%ignore openvpn::TunBuilderBase::amnezia_dns_feed;
%ignore openvpn::TunBuilderBase::amnezia_dns_feed_tunnel;
%ignore openvpn::TunBuilderBase::amnezia_dns_active;
%ignore openvpn::TunBuilderBase::amnezia_dns_quiesce;
%include "openvpn/tun/builder/base.hpp"'''.strip())
    resolver = original["openvpn/client/async_resolve/asio.hpp"].decode()
    resolver = replace_once(resolver, "#include <openvpn/common/hostport.hpp>", '''#include <openvpn/common/hostport.hpp>
#include <mutex>
#ifdef OPENVPN_PLATFORM_ANDROID
#include "native_dns.h"
#include "native_dns_bootstrap.hpp"
#endif''')
    resolver = replace_once(resolver, "        std::atomic<bool> detached{false};",
        "        std::atomic<bool> detached{false};\n        std::recursive_mutex callback_gate;")
    resolver = replace_once(resolver, '''        void detach()
        {
            detached.store''', '''        void detach()
        {
            std::lock_guard<std::recursive_mutex> lock(callback_gate);
            detached.store''')
    resolver = replace_once(resolver, '''            openvpn_io::post(io_context, [self = Ptr(this), results, error]()''',
        '''            std::lock_guard<std::recursive_mutex> lock(callback_gate);
            if (is_detached()) return;
            openvpn_io::post(io_context, [self = Ptr(this), results, error]()''')
    resolver = replace_once(resolver, '''\t  auto parent = self->parent;''',
        '''          std::lock_guard<std::recursive_mutex> lock(self->callback_gate);
\t  auto parent = self->parent;''')
    resolver = replace_once(resolver, '''            std::thread t([self = Ptr(this), host, port]()''', '''#ifdef OPENVPN_PLATFORM_ANDROID
            auto bootstrap_owner = amnezia::NativeDNSBootstrap::acquire();
            std::thread t([self = Ptr(this), host, port, bootstrap_owner]()
#else
            std::thread t([self = Ptr(this), host, port]()
#endif''')
    resolver = replace_once(resolver, '''\t  results = resolver.resolve(host, port, error);''', '''#ifdef OPENVPN_PLATFORM_ANDROID
          if (AmneziaOpenVPNDNSIPv6Off())
          {
              const auto address = openvpn_io::ip::make_address_v4(host, error);
              if (!error && !address.is_unspecified() && !address.is_multicast())
                  results = resolver.resolve(host, port,
                      RESOLVER_TYPE::numeric_host | RESOLVER_TYPE::numeric_service, error);
              else if (!error)
                  error = openvpn_io::error::host_not_found;
          }
          else
#endif
\t  results = resolver.resolve(host, port, error);''')
    tunprop = original["openvpn/tun/client/tunprop.hpp"].decode()
    tunprop = replace_once(tunprop, "#include <openvpn/client/dns.hpp>", '''#include <openvpn/client/dns.hpp>
#ifdef OPENVPN_PLATFORM_ANDROID
#include "native_dns_options.hpp"
#endif''')
    tunprop = replace_once(tunprop, "        DnsOptions dns_options(opt);", '''        DnsOptions dns_options(opt);
#ifdef OPENVPN_PLATFORM_ANDROID
        if (tb->amnezia_ipv6_off())
        {
            if (!amnezia::nativeDNSOptionsRepresentable(dns_options))
                throw tun_prop_dhcp_option_error("selected native DNS metadata requires a policy-aware adapter");
            for (const auto &domain : dns_options.search_domains)
                if (!tb->tun_builder_add_search_domain(domain))
                    throw tun_prop_dhcp_option_error("native DNS search domain publication failed");
        }
#endif''')
    tunprop = replace_once(tunprop, '''        for (const auto &domain : dns_options.search_domains)
        {
            if (!tb->tun_builder_set_adapter_domain_suffix''', '''        for (const auto &domain : dns_options.search_domains)
        {
#ifdef OPENVPN_PLATFORM_ANDROID
            if (tb->amnezia_ipv6_off()) break; // Complete ordered search list was published above.
#endif
            if (!tb->tun_builder_set_adapter_domain_suffix''')
    for family, ipv6 in ((4, "false"), (6, "true")):
        original_call = f"tb->tun_builder_add_dns_server(server.address{family}.to_string(), {ipv6})"
        tunprop = replace_once(tunprop, original_call, f'''(
#ifdef OPENVPN_PLATFORM_ANDROID
                    tb->amnezia_ipv6_off()
                        ? (server.transport == DnsServer::Transport::TLS
                            ? tb->tun_builder_dns_transport(server.address{family}.to_string(),
                                server.port{family} ? server.port{family} : 853, {ipv6}, "tls", server.sni)
                            : tb->tun_builder_dns_server(server.address{family}.to_string(),
                                server.port{family} ? server.port{family} : 53, {ipv6}))
                        :
#endif
                    {original_call})''')
    return {
        "openvpn/tun/builder/base.hpp": base.encode(),
        "openvpn/tun/builder/client.hpp": client.encode(),
        "client/ovpncli.i": interface.encode(),
        "native_dns_owner.hpp": (support / "native_dns_owner.hpp").read_bytes(),
        "native_dns_engine.hpp": (support / "native_dns_engine.hpp").read_bytes(),
        "native_dns_bootstrap.hpp": (support / "native_dns_bootstrap.hpp").read_bytes(),
        "native_dns.h": (support / "native_dns.h").read_bytes(),
        "native_dns_options.hpp": (support / "native_dns_options.hpp").read_bytes(),
        "openvpn/tun/client/tunprop.hpp": tunprop.encode(),
        "openvpn/client/async_resolve/asio.hpp": resolver.encode(),
    }
