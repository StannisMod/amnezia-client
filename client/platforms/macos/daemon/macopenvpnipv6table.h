#pragma once
#include "macopenvpnipv6policy.h"

namespace amnezia::macOpenVpnIpv6 {
// Semantic route data, populated from actual Darwin SDK messages by Native.
// This is deliberately not a copy of any kernel structure or ABI constants.
struct Entry {
    QHostAddress destination;
    int prefix = 0;
    Path path;
    QString scope;
    bool up = false;
    bool blocked = false;
    bool managed = false;
    bool usable() const { return prefix >= 0 && prefix <= 128
        && destination.protocol() == QAbstractSocket::IPv6Protocol && up && !blocked && validPath(path); }
    Route row() const { return {destination.toString(), scope, path, managed && usable()}; }
};
struct PathChoice { std::optional<Path> path; bool ambiguous = false; };
inline PathChoice sourcePath(const QList<Entry> &entries, QHostAddress host, const QString &device)
{
    host.setScopeId({});
    PathChoice result;
    int prefix = -1, scoped = -1;
    for (const auto &entry : entries) {
        if (!entry.usable() || entry.path.device != device
            || (!entry.scope.isEmpty() && entry.scope != device)
            || !host.isInSubnet(entry.destination, entry.prefix)) continue;
        const int scope = !entry.scope.isEmpty();
        if (entry.prefix < prefix || (entry.prefix == prefix && scope < scoped)) continue;
        if (entry.prefix > prefix || scope > scoped) {
            result = {entry.path, false}; prefix = entry.prefix; scoped = scope;
        } else if (result.path && *result.path != entry.path) result.ambiguous = true;
    }
    return result;
}
inline std::optional<QString> nativeDevice(const QList<Entry> &entries, const QString &tunnel,
                                           const QString &originalDefault,
                                           const std::function<bool(const QString &)> &hasSource)
{
    QString device;
    for (const auto &entry : entries) {
        if (entry.prefix || !entry.scope.isEmpty() || !entry.usable() || entry.path.device == tunnel) continue;
        if (!device.isEmpty() && device != entry.path.device) return {};
        device = entry.path.device;
    }
    if (device.isEmpty() && !originalDefault.isEmpty() && originalDefault != tunnel && hasSource(originalDefault))
        device = originalDefault;
    if (device.isEmpty()) {
        // Handover may remove the original NIC. Only a unique remaining native
        // default is safe without knowing the OS's otherwise preferred path.
        for (const auto &entry : entries) {
            if (entry.prefix || !entry.usable() || entry.path.device == tunnel || !hasSource(entry.path.device)) continue;
            if (!device.isEmpty() && device != entry.path.device) return {};
            device = entry.path.device;
        }
    }
    if (device.isEmpty() || device == tunnel || !hasSource(device)) return {};
    return device;
}
} // namespace amnezia::macOpenVpnIpv6
