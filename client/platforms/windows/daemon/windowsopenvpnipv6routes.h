#pragma once

#include "windowsopenvpnipv6policy.h"
#include <QHostAddress>
#include <QNetworkInterface>
#include <QRandomGenerator>
#include <QStringList>
#include <QDebug>
#include <iterator>

class WindowsOpenVpnIpv6Routes {
public:
    using Lookup = std::function<std::uint32_t(const QHostAddress &)>;
    explicit WindowsOpenVpnIpv6Routes(amnezia::windowsOpenVpnIpv6::Api api, Lookup lookup = interfaceForAddress,
                                     std::uint32_t marker = 0)
        : m_lookup(std::move(lookup)), m_policy(std::move(api),
              marker ? marker : (0x10000000u | (QRandomGenerator::system()->generate() & 0x0fffffffu))) {}
    ~WindowsOpenVpnIpv6Routes() {
        if (!m_policy.clear()) qWarning() << "OpenVPN IPv6 route cleanup remains incomplete";
    }
    bool add(const QString &localIpv4, const QStringList &hosts, bool throughVpn)
    {
        const QHostAddress local(localIpv4);
        if (local.protocol() != QAbstractSocket::IPv4Protocol || local.isNull() || local.isLoopback()
            || local.isMulticast() || hosts.size() > 128) return false;
        std::vector<amnezia::windowsOpenVpnIpv6::Address> addresses;
        for (const auto &host : hosts) {
            const QHostAddress address(host);
            if (address.protocol() != QAbstractSocket::IPv6Protocol || !address.scopeId().isEmpty()) return false;
            amnezia::windowsOpenVpnIpv6::Address value{};
            const auto bytes = address.toIPv6Address();
            std::copy(std::begin(bytes.c), std::end(bytes.c), value.begin());
            if (!amnezia::windowsOpenVpnIpv6::validAddress(value)) return false;
            addresses.push_back(value);
        }
        return m_policy.add(m_lookup(local), addresses, throughVpn);
    }
private:
    static std::uint32_t interfaceForAddress(const QHostAddress &address)
    {
        int selected = 0;
        for (const auto &iface : QNetworkInterface::allInterfaces()) {
            if (!iface.flags().testFlag(QNetworkInterface::IsUp)
                || iface.flags().testFlag(QNetworkInterface::IsLoopBack)) continue;
            for (const auto &entry : iface.addressEntries()) {
                if (entry.ip() != address) continue;
                if (selected && selected != iface.index()) return 0;
                selected = iface.index();
            }
        }
        return selected > 0 ? std::uint32_t(selected) : 0;
    }
    Lookup m_lookup;
    amnezia::windowsOpenVpnIpv6::Policy m_policy;
};
