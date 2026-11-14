#pragma once

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#include "windowsopenvpnipv6policy.h"
#ifdef _WIN32
#include <iphlpapi.h>
#include <netioapi.h>
#include <memory>
#include <limits>

namespace amnezia::windowsOpenVpnIpv6 {
inline SOCKADDR_INET socketAddress(const Address &address, std::uint32_t scope = 0)
{
    SOCKADDR_INET result{};
    result.Ipv6.sin6_family = AF_INET6;
    std::copy(address.begin(), address.end(), reinterpret_cast<unsigned char *>(&result.Ipv6.sin6_addr));
    result.Ipv6.sin6_scope_id = scope;
    return result;
}
inline Path routePath(const MIB_IPFORWARD_ROW2 &row)
{
    Path result;
    result.luid = row.InterfaceLuid.Value;
    std::copy_n(reinterpret_cast<const unsigned char *>(&row.NextHop.Ipv6.sin6_addr),
                16, result.gateway.begin());
    // NetIO can return an implicit or explicit link-local zone for the same
    // next hop. Normalize it before comparing ownership and source paths.
    if (IN6_IS_ADDR_LINKLOCAL(&row.NextHop.Ipv6.sin6_addr)) {
        NET_IFINDEX index = row.InterfaceIndex;
        if (!index) ConvertInterfaceLuidToIndex(&row.InterfaceLuid, &index);
        result.scope = index;
    }
    return result;
}
inline bool strongHost(std::uint64_t value)
{
    MIB_IPINTERFACE_ROW row{};
    InitializeIpInterfaceEntry(&row);
    row.Family = AF_INET6;
    row.InterfaceLuid.Value = value;
    return GetIpInterfaceEntry(&row) == NO_ERROR && row.Connected
        && !row.WeakHostSend && !row.ForwardingEnabled;
}
inline MIB_IPFORWARD_ROW2 nativeRow(const Route &route)
{
    MIB_IPFORWARD_ROW2 row{};
    InitializeIpForwardEntry(&row);
    row.InterfaceLuid.Value = route.path.luid;
    row.DestinationPrefix.Prefix = socketAddress(route.destination);
    row.DestinationPrefix.PrefixLength = 128;
    row.NextHop = socketAddress(route.path.gateway, route.path.scope);
    row.SitePrefixLength = 0;
    row.Metric = route.metric;
    row.Protocol = static_cast<NL_ROUTE_PROTOCOL>(MIB_IPPROTO_NETMGMT);
    row.ValidLifetime = row.PreferredLifetime = 0xffffffff;
    row.Publish = row.Loopback = row.AutoconfigureAddress = row.Immortal = FALSE;
    return row;
}
inline bool matches(const MIB_IPFORWARD_ROW2 &row, const Route &route)
{
    return row.DestinationPrefix.PrefixLength == 128 && routePath(row) == route.path
        && row.Metric == route.metric && row.Protocol == MIB_IPPROTO_NETMGMT
        && !row.Publish && !row.Loopback && !row.AutoconfigureAddress;
}
inline Api nativeApi()
{
    Api api;
    api.interfaceLuid = [](std::uint32_t index) -> std::optional<std::uint64_t> {
        NET_LUID luid{};
        if (ConvertInterfaceIndexToLuid(index, &luid) != NO_ERROR) return {};
        return luid.Value;
    };
    api.strongHost = strongHost;
    api.sources = []() -> std::optional<std::vector<Source>> {
        PMIB_UNICASTIPADDRESS_TABLE table = nullptr;
        if (GetUnicastIpAddressTable(AF_INET6, &table) != NO_ERROR) return {};
        const std::unique_ptr<MIB_UNICASTIPADDRESS_TABLE, decltype(&FreeMibTable)> owned(table, FreeMibTable);
        std::vector<Source> sources;
        for (ULONG i = 0; i < table->NumEntries; ++i) {
            const auto &row = table->Table[i];
            if (row.DadState != IpDadStatePreferred && row.DadState != IpDadStateDeprecated) continue;
            MIB_IF_ROW2 iface{};
            iface.InterfaceLuid = row.InterfaceLuid;
            if (GetIfEntry2(&iface) != NO_ERROR || iface.OperStatus != IfOperStatusUp) continue;
            Source source;
            source.luid = row.InterfaceLuid.Value;
            std::copy_n(reinterpret_cast<const unsigned char *>(&row.Address.Ipv6.sin6_addr),
                        16, source.address.begin());
            if (validAddress(source.address)) sources.push_back(source);
        }
        return sources;
    };
    api.fromSource = [](const Address &source, const Address &destination) -> std::optional<Path> {
        const auto from = socketAddress(source), to = socketAddress(destination);
        SOCKADDR_INET selected{};
        MIB_IPFORWARD_ROW2 row{};
        if (GetBestRoute2(nullptr, 0, &from, &to, 0, &row, &selected) != NO_ERROR) return {};
        return routePath(row);
    };
    api.path = [](std::uint64_t tunnel, const Address &destination, bool throughVpn) -> std::optional<Path> {
        if (throughVpn) {
            NET_LUID luid{}; luid.Value = tunnel;
            const auto to = socketAddress(destination);
            SOCKADDR_INET selected{};
            MIB_IPFORWARD_ROW2 row{};
            if (GetBestRoute2(&luid, 0, nullptr, &to, 0, &row, &selected) == NO_ERROR
                && row.InterfaceLuid.Value == tunnel) return routePath(row);
            // TAP also reports IF_TYPE_PROP_VIRTUAL, but still resolves
            // Ethernet neighbors. Only a MAC-less L3 adapter can omit a hop.
            MIB_IF_ROW2 iface{}; iface.InterfaceLuid = luid;
            if (GetIfEntry2(&iface) == NO_ERROR && iface.Type == IF_TYPE_PROP_VIRTUAL
                && iface.PhysicalAddressLength == 0)
                return Path{tunnel, {}, 0};
            // A new DNS destination need not match an existing include
            // prefix. Reuse the unambiguous on-link peer from the tunnel's
            // observed routes instead of treating the destination as a peer.
            PMIB_IPFORWARD_TABLE2 table = nullptr;
            if (GetIpForwardTable2(AF_INET6, &table) != NO_ERROR) return {};
            const std::unique_ptr<MIB_IPFORWARD_TABLE2, decltype(&FreeMibTable)> owned(table, FreeMibTable);
            std::optional<Path> gateway;
            for (ULONG i = 0; i < table->NumEntries; ++i) {
                const auto &observed = table->Table[i];
                if (observed.InterfaceLuid.Value != tunnel || observed.Loopback
                    || observed.NextHop.Ipv6.sin6_family != AF_INET6
                    || IN6_IS_ADDR_UNSPECIFIED(&observed.NextHop.Ipv6.sin6_addr)) continue;
                MIB_IPFORWARD_ROW2 peer{};
                SOCKADDR_INET source{};
                if (GetBestRoute2(&luid, 0, nullptr, &observed.NextHop, 0, &peer, &source) != NO_ERROR
                    || peer.InterfaceLuid.Value != tunnel || peer.Loopback
                    || !IN6_IS_ADDR_UNSPECIFIED(&peer.NextHop.Ipv6.sin6_addr)) continue;
                const auto path = routePath(observed);
                if (gateway && *gateway != path) return {}; // Do not guess between peers.
                gateway = path;
            }
            return gateway;
        }
        PMIB_IPFORWARD_TABLE2 table = nullptr;
        if (GetIpForwardTable2(AF_INET6, &table) != NO_ERROR) return {};
        const std::unique_ptr<MIB_IPFORWARD_TABLE2, decltype(&FreeMibTable)> owned(table, FreeMibTable);
        std::optional<Path> best;
        std::uint64_t metric = (std::numeric_limits<std::uint64_t>::max)();
        for (ULONG i = 0; i < table->NumEntries; ++i) {
            const auto &row = table->Table[i];
            if (row.DestinationPrefix.PrefixLength != 0 || row.InterfaceLuid.Value == tunnel
                || row.Loopback || !strongHost(row.InterfaceLuid.Value)) continue;
            MIB_IPINTERFACE_ROW iface{};
            InitializeIpInterfaceEntry(&iface);
            iface.Family = AF_INET6; iface.InterfaceLuid = row.InterfaceLuid;
            if (GetIpInterfaceEntry(&iface) != NO_ERROR) continue;
            const auto cost = std::uint64_t(row.Metric) + iface.Metric;
            if (cost < metric) { metric = cost; best = routePath(row); }
        }
        return best;
    };
    api.foreignHostRouteExists = [](const Address &destination, const std::vector<Route> &ours) -> std::optional<bool> {
        PMIB_IPFORWARD_TABLE2 table = nullptr;
        if (GetIpForwardTable2(AF_INET6, &table) != NO_ERROR) return {};
        const std::unique_ptr<MIB_IPFORWARD_TABLE2, decltype(&FreeMibTable)> owned(table, FreeMibTable);
        for (ULONG i = 0; i < table->NumEntries; ++i) {
            const auto &row = table->Table[i];
            if (row.DestinationPrefix.PrefixLength == 128
                && std::equal(destination.begin(), destination.end(),
                              reinterpret_cast<const unsigned char *>(&row.DestinationPrefix.Prefix.Ipv6.sin6_addr))) {
                if (std::none_of(ours.begin(), ours.end(), [&](const Route &route) { return matches(row, route); })) return true;
            }
        }
        return false;
    };
    api.owns = [](const Route &route) {
        auto row = nativeRow(route);
        return GetIpForwardEntry2(&row) == NO_ERROR && matches(row, route);
    };
    api.create = [](const Route &route) {
        const auto row = nativeRow(route);
        return CreateIpForwardEntry2(&row) == NO_ERROR;
    };
    api.interfaceMetric = [](std::uint64_t luid) -> std::optional<std::uint32_t> {
        MIB_IPINTERFACE_ROW row{};
        InitializeIpInterfaceEntry(&row);
        row.Family = AF_INET6;
        row.InterfaceLuid.Value = luid;
        if (GetIpInterfaceEntry(&row) != NO_ERROR) return {};
        return row.Metric;
    };
    api.updateOwned = [](const Route &before, const Route &after) {
        if (before.destination != after.destination || before.path != after.path) return false;
        auto row = nativeRow(before);
        if (GetIpForwardEntry2(&row) != NO_ERROR || !matches(row, before)) return false;
        row.Metric = after.metric;
        return SetIpForwardEntry2(&row) == NO_ERROR;
    };
    api.removeOwned = [](const Route &route) {
        auto row = nativeRow(route);
        const auto status = GetIpForwardEntry2(&row);
        if (status == ERROR_NOT_FOUND) return true;
        if (status != NO_ERROR) return false;
        if (!matches(row, route)) return true; // An external replacement is not ours.
        const auto result = DeleteIpForwardEntry2(&row);
        return result == NO_ERROR || result == ERROR_NOT_FOUND;
    };
    return api;
}
} // namespace amnezia::windowsOpenVpnIpv6
#endif
