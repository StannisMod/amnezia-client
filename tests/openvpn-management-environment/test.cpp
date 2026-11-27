#include "../../client/core/protocols/openVpnManagementEnvironment.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <iostream>

int main()
{
    using Result = OpenVpnManagementEnvironment::Result;
    OpenVpnManagementEnvironment env;
    assert(!env.nativeRoutesSucceeded());
    assert(env.consume(">UPDOWN:ENV,END") == Result::Invalid);
    assert(env.consume(">UPDOWN:UP") == Result::Pending);
    assert(env.consume(">UPDOWN:ENV,foreign_option_2=dhcp-option DNS 2001:db8::53") == Result::Pending);
    assert(env.consume(">LOG:unrelated") == Result::Ignored);
    assert(env.consume(">UPDOWN:ENV,dns_server_1_resolve_domain_1=private  domain=x") == Result::Pending);
    assert(env.consume(">UPDOWN:ENV,END") == Result::Complete);
    assert(env.isUp());
    assert(!env.nativeRoutesSucceeded()); // Historical runtimes provide no route proof.
    assert(env.values().at("foreign_option_2") == "dhcp-option DNS 2001:db8::53");
    assert(env.values().at("dns_server_1_resolve_domain_1") == "private  domain=x");
    assert(env.consume(">UPDOWN:DOWN") == Result::Pending);
    assert(env.values().empty());
    assert(env.consume(">UPDOWN:ENV,dev=tun0") == Result::Pending);
    assert(env.consume(">UPDOWN:ENV,dev=tun1") == Result::Invalid);
    assert(env.values().empty());
    assert(env.consume(">UPDOWN:ENV,END") == Result::Invalid);
    assert(env.consume(">UPDOWN:UP") == Result::Pending);
    assert(env.consume(">UPDOWN:ENV,amnezia_native_routes=success") == Result::Pending);
    assert(!env.nativeRoutesSucceeded()); // An incomplete frame is never sufficient.
    assert(env.consume(">UPDOWN:ENV,END") == Result::Complete);
    assert(env.nativeRoutesSucceeded());
    assert(env.consume(">UPDOWN:ENV,END") == Result::Invalid);
    assert(!env.nativeRoutesSucceeded());
    assert(env.values().empty());
    assert(env.consume(">UPDOWN:INVALID") == Result::Invalid);
    for (const auto *status : {"failed", "unmanaged", "SUCCESS", ""}) {
        assert(env.consume(">UPDOWN:UP") == Result::Pending);
        assert(env.consume(std::string(">UPDOWN:ENV,amnezia_native_routes=") + status) == Result::Pending);
        assert(env.consume(">UPDOWN:ENV,END") == Result::Complete);
        assert(!env.nativeRoutesSucceeded());
    }
    assert(env.consume(">UPDOWN:DOWN") == Result::Pending);
    assert(env.consume(">UPDOWN:ENV,amnezia_native_routes=success") == Result::Pending);
    assert(env.consume(">UPDOWN:ENV,END") == Result::Complete);
    assert(!env.nativeRoutesSucceeded());
    assert(env.consume(">UPDOWN:UP") == Result::Pending);
    assert(env.consume(">UPDOWN:ENV,=bad") == Result::Invalid);
    assert(env.consume(">UPDOWN:UP") == Result::Pending);
    assert(env.consume(">UPDOWN:ENV,key=" + std::string(65536, 'x')) == Result::Invalid);
    assert(env.consume(">UPDOWN:UP") == Result::Pending);
    env.reset();
    assert(env.consume(">UPDOWN:ENV,END") == Result::Invalid);
    std::cout << "PASS: native environment framing, IPv6 DNS, metadata, interleaving, duplicate/malformed/oversize rejection, reset\n";
}
