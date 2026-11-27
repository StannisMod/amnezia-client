#include "../../ipc/ipc.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <iostream>

int main()
{
    const QStringList baseline {
        "--config", "/owned/profile.ovpn", "--management", "127.0.0.1",
        "25001", "--management-client"
    };
    assert(amnezia::sanitizeArguments(amnezia::OpenVPN, baseline) == baseline);
    const auto off = baseline + QStringList {"--management-up-down"};
    assert(amnezia::sanitizeArguments(amnezia::OpenVPN, off) == off);
    const auto untrusted = off + QStringList {"--up", "/untrusted/script", "--unknown"};
    assert(amnezia::sanitizeArguments(amnezia::OpenVPN, untrusted) == off);
    assert(!amnezia::sanitizeArguments(amnezia::Tun2Socks, {"--management-up-down"})
                .contains("--management-up-down"));
    std::cout << "PASS: real service argument sanitizer preserves OFF environment flag, unchanged ON arguments, rejects unapproved options\n";
}
