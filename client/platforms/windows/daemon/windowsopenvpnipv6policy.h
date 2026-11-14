#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <map>
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
    std::function<std::optional<bool>(const Address &, const std::optional<Route> &)> foreignHostRouteExists;
    std::function<bool(const Route &)> owns;
    std::function<bool(const Route &)> create;
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
        if (!interfaceIndex || !m_marker || !m_pending.empty() || hosts.size() > 128
            || m_owned.size() + hosts.size() > 4096) return false;
        if (!m_api.interfaceLuid || !m_api.strongHost || !m_api.sources || !m_api.path
            || !m_api.fromSource || !m_api.foreignHostRouteExists || !m_api.owns
            || !m_api.create || !m_api.removeOwned) return false;
        const auto tunnel = m_api.interfaceLuid(interfaceIndex);
        if (!tunnel || !*tunnel || (m_tunnel && m_tunnel != *tunnel) || !m_api.strongHost(*tunnel)) return false;
        const auto sources = m_api.sources();
        if (!sources || sources->size() > 256) return false;
        if (std::none_of(sources->begin(), sources->end(), [&](const Source &source) {
                return source.luid == *tunnel && validAddress(source.address);
            })) return false;
        std::map<Address, Route> planned;
        std::vector<Route> replaced;
        struct Guard { Address source; Address destination; Path path; };
        std::vector<Guard> guards;
        for (const auto &host : hosts) {
            if (!validAddress(host)) return false;
            if (planned.count(host)) continue;
            const auto path = m_api.path(*tunnel, host, throughVpn);
            if (!path || !path->luid || !m_api.strongHost(path->luid)) return false;
            const auto old = m_owned.find(host);
            const auto foreign = m_api.foreignHostRouteExists(host,
                old == m_owned.end() ? std::optional<Route>{} : old->second);
            if (!foreign || *foreign) return false;
            if (old != m_owned.end()) {
                if (!m_api.owns(old->second)) return false;
                if (old->second.path == *path) continue;
                // The same interface/prefix is a single Windows route key.
                // Do not delete first and expose a temporary routing gap.
                if (old->second.path.luid == path->luid) return false;
                replaced.push_back(old->second);
            }
            planned.emplace(host, Route{host, *path, m_marker});
            for (const auto &source : *sources) {
                if (!validAddress(source.address)) continue;
                if (!m_api.strongHost(source.luid)) return false;
                const auto before = m_api.fromSource(source.address, host);
                if (!before) continue; // No previously usable path from this source.
                if (before->luid != source.luid) return false;
                if (source.luid == path->luid && *before != *path) return false;
                guards.push_back({source.address, host, *before});
            }
        }
        std::vector<Route> added, removed;
        const auto rollback = [&] {
            bool success = true;
            for (const auto &route : added) if (!m_api.removeOwned(route)) success = false;
            for (const auto &route : removed) if (!m_api.create(route)) success = false;
            // Retain failed cleanup entries for a later clear()/destructor.
            if (!success) for (const auto &route : added) m_pending.push_back(route);
        };
        for (const auto &entry : planned) {
            if (!m_api.create(entry.second)) { rollback(); return false; }
            added.push_back(entry.second);
        }
        for (const auto &old : replaced) {
            if (!m_api.removeOwned(old)) { rollback(); return false; }
            removed.push_back(old);
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
            if (m_api.removeOwned(it->second)) it = m_owned.erase(it); else ++it;
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
    std::map<Address, Route> m_owned;
    std::vector<Route> m_pending;
};
} // namespace amnezia::windowsOpenVpnIpv6
