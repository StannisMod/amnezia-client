#ifndef NATIVEDNSFIREWALL_H
#define NATIVEDNSFIREWALL_H
#include <winsock2.h>
#include <windows.h>
#include <QHostAddress>

namespace NativeDnsFirewall {
inline constexpr GUID baselineSublayer{0xc78056ff, 0x2bc1, 0x4211,
    {0xaa, 0xdd, 0x7f, 0x35, 0x8d, 0xef, 0x20, 0x2d}};
// Same baseline sublayer and priority as WindowsFirewall's selected-DNS rules.
// Only local IPv4 alias UDP/TCP port 53 is permitted. Close with FwpmEngineClose0
// after confirmed OS DNS restoration and before removing assigned aliases.
HANDLE openLease(const QList<QHostAddress> &endpoints);
// Pre-dial IPv4 DNS fence. IPv6 is independently denied by the native policy.
// No resolver, process or privileged transport exception is installed.
HANDLE openSetupFence();
}
#endif
