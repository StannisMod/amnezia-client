#include "../../platforms/macos/daemon/macopenvpnipv6routes.h"
#if !defined(Q_OS_MACOS) || defined(MACOS_NE)
#error This target requires the actual desktop macOS SDK and Qt build.
#endif

int main()
{
    // Compilation boundary, not a packet test. No route mutation is requested.
    amnezia::macOpenVpnIpv6::Native native;
    const auto api = native.api();
    MacOpenVpnIpv6Routes routes;
    return api.select && api.sources && api.read && api.create && api.changeOwned && api.removeOwned ? 0 : 1;
}
