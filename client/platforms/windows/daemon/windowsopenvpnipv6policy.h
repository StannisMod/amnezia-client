#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <map>
#include <limits>
#include <optional>
#include <vector>
#include <utility>

// Windows strong-host routing keeps an established socket on the interface
// owning its source address. Verify that invariant around each owned update.
// The native API adapter is separate so transaction failures can be exercised
// without changing the test runner's routes.
namespace amnezia::windowsOpenVpnIpv6 {
using Address = std::array<unsigned char, 16>;
struct Path {
    std::uint64_t luid = 0;
    Address gateway{};
    std::uint32_t scope = 0;
    bool operator==(const Path &other) const
    { return luid == other.luid && gateway == other.gateway && scope == other.scope; }
    bool operator!=(const Path &other) const { return !(*this == other); }
};
struct Source { Address address{}; std::uint64_t luid = 0; };
struct Route { Address destination{}; Path path; std::uint32_t metric = 0; };
struct Api {
    std::function<std::optional<std::uint64_t>(std::uint32_t)> interfaceLuid;
    std::function<bool(std::uint64_t)> strongHost;
    std::function<std::optional<std::vector<Source>>()> sources;
    std::function<std::optional<Path>(std::uint64_t, const Address &, bool)> path;
    std::function<std::optional<Path>(const Address &, const Address &)> fromSource;
    std::function<std::optional<bool>(const Address &, const std::vector<Route> &)> foreignHostRouteExists;
    std::function<bool(const Route &)> owns;
    std::function<bool(const Route &)> create;
    std::function<std::optional<std::uint32_t>(std::uint64_t)> interfaceMetric;
    std::function<bool(const Route &, const Route &)> updateOwned;
    // An absent or externally replaced row is already released. Never delete
    // a replacement whose ownership marker differs.
    std::function<bool(const Route &)> removeOwned;
};

inline bool validAddress(const Address &address)
{
    if (address == Address{} || address[0] == 0xff
        || (address[0] == 0xfe && (address[1] & 0xc0) == 0x80)) return false;
    Address loopback{}; loopback.back() = 1;
    if (address == loopback) return false;
    return !(std::all_of(address.begin(), address.begin() + 10, [](auto b) { return b == 0; })
             && address[10] == 0xff && address[11] == 0xff);
}

class Policy {
public:
    Policy(Api api, std::uint32_t marker) : m_api(std::move(api)), m_marker(marker) {}
    Policy(const Policy &) = delete;
    Policy &operator=(const Policy &) = delete;
    ~Policy() { clear(); }

    bool add(std::uint32_t interfaceIndex, const std::vector<Address> &hosts, bool throughVpn)
    {
        if (!interfaceIndex || !m_marker || m_marker == (std::numeric_limits<std::uint32_t>::max)()
            || !m_pending.empty() || hosts.size() > 128
            || m_owned.size() + hosts.size() > 4096) return false;
        if (!m_api.interfaceLuid || !m_api.strongHost || !m_api.sources || !m_api.path
            || !m_api.fromSource || !m_api.foreignHostRouteExists || !m_api.owns
            || !m_api.create || !m_api.removeOwned || !m_api.interfaceMetric
            || !m_api.updateOwned) return false;
        const auto tunnel = m_api.interfaceLuid(interfaceIndex);
        if (!tunnel || !*tunnel || (m_tunnel && m_tunnel != *tunnel) || !m_api.strongHost(*tunnel)) return false;
        const auto sources = m_api.sources();
        if (!sources || sources->size() > 256) return false;
        if (std::none_of(sources->begin(), sources->end(), [&](const Source &source) {
                return source.luid == *tunnel && validAddress(source.address);
            })) return false;
        std::map<Address, std::vector<Route>> planned;
        struct Guard { Address source; Address destination; Path path; };
        std::vector<Guard> guards;
        for (const auto &host : hosts) {
            if (!validAddress(host)) return false;
            if (planned.count(host)) continue;
            const auto path = m_api.path(*tunnel, host, throughVpn);
            if (!path || !path->luid || !m_api.strongHost(path->luid)) return false;
            const auto old = m_owned.find(host);
            const std::vector<Route> previous = old == m_owned.end() ? std::vector<Route>{} : old->second;
            const auto foreign = m_api.foreignHostRouteExists(host, previous);
            if (!foreign || *foreign) return false;
            for (const auto &route : previous) {
                if (!m_api.owns(route)) return false;
                // A changed gateway on the same interface would also change
                // the path of established sockets. Do not silently replace it.
                if (route.path.luid == path->luid && route.path != *path) return false;
            }
            std::vector<Route> next{{host, *path, 0}};
            for (const auto &route : previous)
                if (route.path != *path) next.push_back(route);
            if (next.size() > 256) return false;
            for (std::size_t i = 0; i < next.size(); ++i) {
                const auto metric = m_api.interfaceMetric(next[i].path.luid);
                // Windows compares route + interface metrics. Normalize their
                // sum so only new, unbound sockets prefer the selected path.
                // Old paths stay installed for strong-host source routing.
                if (!metric || *metric > m_marker) return false;
                next[i].metric = m_marker - *metric + (i ? 1u : 0u);
            }
            planned.emplace(host, std::move(next));
            for (const auto &source : *sources) {
                if (!validAddress(source.address)) continue;
                if (!m_api.strongHost(source.luid)) return false;
                const auto before = m_api.fromSource(source.address, host);
                if (!before) continue;
                if (before->luid != source.luid) return false;
                if (source.luid == path->luid && *before != *path) return false;
                guards.push_back({source.address, host, *before});
            }
        }
        std::vector<Route> added;
        std::vector<std::pair<Route, Route>> changed;
        const auto rollback = [&] {
            bool success = true;
            for (auto it = changed.rbegin(); it != changed.rend(); ++it)
                if (!m_api.updateOwned(it->second, it->first)) success = false;
            for (const auto &route : added) if (!m_api.removeOwned(route)) success = false;
            // Retain every possible owned version after a partial rollback.
            // Exact ownership checks prevent deleting external replacements.
            if (!success) {
                for (const auto &route : added) m_pending.push_back(route);
                for (const auto &entry : changed) m_pending.push_back(entry.second);
            }
        };
        for (const auto &entry : planned) {
            const auto old = m_owned.find(entry.first);
            for (const auto &route : entry.second) {
                const Route *previous = nullptr;
                if (old != m_owned.end())
                    for (const auto &candidate : old->second)
                        if (candidate.path == route.path) { previous = &candidate; break; }
                if (!previous) {
                    if (!m_api.create(route)) { rollback(); return false; }
                    added.push_back(route);
                } else if (previous->metric != route.metric) {
                    if (!m_api.updateOwned(*previous, route)) { rollback(); return false; }
                    changed.emplace_back(*previous, route);
                }
            }
        }
        for (const auto &guard : guards) {
            const auto after = m_api.fromSource(guard.source, guard.destination);
            if (!after || *after != guard.path || !m_api.strongHost(guard.path.luid)) {
                rollback(); return false;
            }
        }
        for (const auto &entry : planned) m_owned.insert_or_assign(entry.first, entry.second);
        m_tunnel = *tunnel;
        return true;
    }

    bool clear()
    {
        if (!m_api.removeOwned) return m_owned.empty() && m_pending.empty();
        for (auto it = m_owned.begin(); it != m_owned.end();) {
            auto &routes = it->second;
            routes.erase(std::remove_if(routes.begin(), routes.end(),
                [&](const Route &route) { return m_api.removeOwned(route); }), routes.end());
            if (routes.empty()) it = m_owned.erase(it); else ++it;
        }
        m_pending.erase(std::remove_if(m_pending.begin(), m_pending.end(),
            [&](const Route &route) { return m_api.removeOwned(route); }), m_pending.end());
        if (m_owned.empty() && m_pending.empty()) { m_tunnel = 0; return true; }
        return false;
    }
private:
    Api m_api;
    std::uint32_t m_marker;
    std::uint64_t m_tunnel = 0;
    std::map<Address, std::vector<Route>> m_owned;
    std::vector<Route> m_pending;
};
} // namespace amnezia::windowsOpenVpnIpv6
