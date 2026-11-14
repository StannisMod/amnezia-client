#pragma once

#include <QHostAddress>
#include <QList>
#include <QMap>
#include <QSet>
#include <QStringList>
#include <algorithm>
#include <functional>
#include <optional>
#include <utility>
#include <vector>

// Transaction policy for Darwin's unscoped destination route and per-interface
// source paths. The native adapter must query actual routes, check ownership
// before mutations, and report success only after reconciling the kernel result.
namespace amnezia::macOpenVpnIpv6 {
struct Path {
    QString device;
    QHostAddress gateway; // Null means an interface route; only the native adapter can validate its link semantics.
    bool operator==(const Path &other) const { return device == other.device && gateway == other.gateway; }
    bool operator!=(const Path &other) const { return !(*this == other); }
};
struct Route {
    QString host;
    QString scope; // Empty for the route used by new, unbound sockets.
    Path path;
    bool managed = true;
    bool transient = false; // Kernel-generated clone, not a durable source pin.
    bool operator==(const Route &other) const {
        return host == other.host && scope == other.scope && path == other.path && managed == other.managed && transient == other.transient;
    }
};
struct Observed { std::optional<Route> exact; };
struct Api {
    std::function<std::optional<Path>(const QString &, const QString &, bool)> select;
    // Effective usable paths for existing source interfaces, never guessed gateways.
    std::function<std::optional<QList<Path>>(const QString &)> sources;
    // A successful query with no exact host/scope row is distinct from failure.
    std::function<std::optional<Observed>(const QString &, const QString &)> read;
    std::function<bool(const Route &)> create;
    // Idempotent: an already matching after-row is success. A failed command
    // may have reached the kernel, so the policy also rolls back its intent.
    std::function<bool(const Route &, const Route &)> changeOwned;
    // Missing or externally replaced rows are released without deleting the replacement.
    std::function<bool(const Route &)> removeOwned;
};

inline bool validHost(const QHostAddress &address)
{
    bool mapped = false;
    address.toIPv4Address(&mapped);
    return address.protocol() == QAbstractSocket::IPv6Protocol && !mapped
        && address.scopeId().isEmpty() && !address.isNull() && !address.isLoopback()
        && !address.isMulticast() && !address.isLinkLocal();
}
inline bool validPath(const Path &path)
{
    if (path.device.isEmpty() || path.device.size() > 64) return false;
    for (const auto ch : path.device)
        if (!ch.isLetterOrNumber() || ch.unicode() > 127) return false;
    if (path.gateway.isNull()) return path.gateway.protocol() == QAbstractSocket::UnknownNetworkLayerProtocol
        || path.gateway.protocol() == QAbstractSocket::IPv6Protocol;
    bool mapped = false;
    path.gateway.toIPv4Address(&mapped);
    return path.gateway.protocol() == QAbstractSocket::IPv6Protocol && !mapped
        && !path.gateway.isLoopback() && !path.gateway.isMulticast()
        && (path.gateway.scopeId().isEmpty() || path.gateway.scopeId() == path.device);
}

class Policy {
public:
    explicit Policy(Api api) : m_api(std::move(api)) {}
    Policy(const Policy &) = delete;
    Policy &operator=(const Policy &) = delete;
    ~Policy() { clear(); }

    bool add(const QString &tunnel, const QStringList &hosts, bool throughVpn)
    {
        if (!validPath({tunnel, {}}) || (!m_tunnel.isEmpty() && tunnel != m_tunnel)
            || hosts.size() > 128 || !m_pending.isEmpty() || !m_api.select || !m_api.sources
            || !m_api.read || !m_api.create || !m_api.changeOwned || !m_api.removeOwned) return false;
        QMap<QString, Route> planned;
        QMap<QString, QList<Path>> guards;
        QList<Route> borrowed;
        QSet<QString> destinations;
        for (const auto &route : m_owned) destinations.insert(route.host);
        for (const auto &input : hosts) {
            const QHostAddress address(input);
            if (!validHost(address)) return false;
            const auto host = address.toString();
            if (guards.contains(host)) continue;
            destinations.insert(host);
            if (destinations.size() > 4096) return false;
            const auto selected = m_api.select(tunnel, host, throughVpn);
            const auto paths = m_api.sources(host);
            if (!selected || !validPath(*selected) || !paths || paths->size() > 64
                || (selected->device == tunnel) != throughVpn) return false;
            QMap<QString, Path> pins;
            for (const auto &path : *paths) {
                if (!validPath(path) || (pins.contains(path.device) && pins[path.device] != path)) return false;
                pins.insert(path.device, path);
            }
            if (pins.contains(selected->device) && pins[selected->device] != *selected) return false;
            pins.insert(selected->device, *selected);
            guards.insert(host, *paths);
            // Validate all existing ownership and the whole batch before the
            // first mutation, including retained paths from previous updates.
            for (const auto &owned : m_owned) {
                if (owned.host != host) continue;
                const auto found = m_api.read(host, owned.scope);
                if (!found || !found->exact || !(*found->exact == owned)) return false;
            }
            QList<Route> desired{{host, {}, *selected, true}};
            for (const auto &pin : pins) desired.append({host, pin.device, pin, true});
            for (const auto &route : desired) {
                const auto key = routeKey(route);
                const auto found = m_api.read(host, route.scope);
                if (!found) return false;
                if (m_owned.contains(key)) {
                    if (m_owned[key] == route) continue;
                    // Scoped paths belong to existing source-bound sockets.
                    if (!route.scope.isEmpty()) return false;
                } else if (found->exact) {
                    // An existing matching scoped path can be used, never
                    // adopted as ours. A foreign unscoped row cannot be changed.
                    if (route.scope.isEmpty() || found->exact->path != route.path) return false;
                    if (!found->exact->transient) {
                        borrowed.append(*found->exact);
                        continue;
                    }
                    // Let the kernel replace its matching cloned cache row
                    // with our durable pin; never delete a foreign row first.
                }
                planned.insert(key, route);
            }
        }
        if (m_owned.size() + planned.size() > 16384) return false;
        QList<Route> added;
        std::vector<std::pair<Route, Route>> changed;
        const auto rollback = [&] {
            for (auto it = changed.rbegin(); it != changed.rend(); ++it)
                if (!m_api.changeOwned(it->second, it->first)) m_pending.append(it->second);
            for (auto it = added.crbegin(); it != added.crend(); ++it)
                if (!m_api.removeOwned(*it)) m_pending.append(*it);
        };
        // Install every source pin before changing any unscoped route. Old
        // scoped paths stay owned until process exit; switching never deletes them.
        for (const bool scoped : {true, false}) {
            for (auto it = planned.cbegin(); it != planned.cend(); ++it) {
                const auto &route = it.value();
                if ((!route.scope.isEmpty()) != scoped) continue;
                if (m_owned.contains(it.key())) {
                    const auto old = m_owned[it.key()];
                    changed.emplace_back(old, route);
                    if (!m_api.changeOwned(old, route)) { rollback(); return false; }
                } else {
                    added.append(route);
                    if (!m_api.create(route)) { rollback(); return false; }
                }
            }
        }
        for (auto it = guards.cbegin(); it != guards.cend(); ++it) {
            const auto after = m_api.sources(it.key());
            if (!after) { rollback(); return false; }
            for (const auto &path : it.value())
                if (!after->contains(path)) { rollback(); return false; }
        }
        for (const auto &route : borrowed) {
            const auto after = m_api.read(route.host, route.scope);
            if (!after || !after->exact || !(*after->exact == route)) { rollback(); return false; }
        }
        for (auto it = planned.cbegin(); it != planned.cend(); ++it) m_owned.insert(it.key(), it.value());
        m_tunnel = tunnel;
        return true;
    }

    bool clear()
    {
        if (!m_api.removeOwned) return m_owned.isEmpty() && m_pending.isEmpty();
        const auto primaryRemains = [&](const QString &host) {
            return m_owned.contains(host + '|') || std::any_of(m_pending.cbegin(), m_pending.cend(),
                [&](const Route &route) { return route.host == host && route.scope.isEmpty(); });
        };
        for (const bool scoped : {false, true}) {
            for (auto it = m_owned.begin(); it != m_owned.end();) {
                if ((!it->scope.isEmpty()) != scoped || (scoped && primaryRemains(it->host))) { ++it; continue; }
                if (m_api.removeOwned(it.value())) it = m_owned.erase(it);
                else ++it;
            }
            for (qsizetype i = m_pending.size(); i-- > 0;) {
                if ((!m_pending[i].scope.isEmpty()) != scoped
                    || (scoped && primaryRemains(m_pending[i].host))) continue;
                if (m_api.removeOwned(m_pending[i])) m_pending.removeAt(i);
            }
        }
        if (m_owned.isEmpty() && m_pending.isEmpty()) m_tunnel.clear();
        return m_owned.isEmpty() && m_pending.isEmpty();
    }
private:
    static QString routeKey(const Route &route) { return route.host + '|' + route.scope; }
    Api m_api;
    QMap<QString, Route> m_owned;
    QList<Route> m_pending;
    QString m_tunnel;
};
} // namespace amnezia::macOpenVpnIpv6
