// Build-only native Win32 API boundary check. Does not modify routes.
#include "../../platforms/windows/daemon/windowsopenvpnipv6api.h"
int main(int argc, char **)
{
    const auto api = amnezia::windowsOpenVpnIpv6::nativeApi();
    if (argc == 0) return api.interfaceLuid(0).has_value() ? 1 : 0;
    return 0;
}
