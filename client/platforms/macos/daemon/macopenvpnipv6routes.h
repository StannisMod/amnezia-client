#pragma once
#include "macopenvpnipv6native.h"

#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
#include <QDebug>

class MacOpenVpnIpv6Routes {
public:
    // Construct before OpenVPN starts so native default-interface selection
    // is not inferred from the VPN's subsequently installed routes.
    MacOpenVpnIpv6Routes() : m_policy(m_native.api()) {}
    ~MacOpenVpnIpv6Routes() {
        if (!m_policy.clear()) qWarning() << "OpenVPN macOS IPv6 route cleanup remains incomplete";
    }
    bool add(const QString &localIpv4, const QStringList &hosts, bool throughVpn) {
        const QHostAddress local(localIpv4);
        if (local.protocol() != QAbstractSocket::IPv4Protocol || local.isNull()
            || local.isLoopback() || local.isMulticast()) return false;
        QString tunnel;
        for (const auto &iface : QNetworkInterface::allInterfaces()) {
            if (!iface.flags().testFlag(QNetworkInterface::IsUp)
                || !iface.flags().testFlag(QNetworkInterface::IsPointToPoint)) continue;
            for (const auto &entry : iface.addressEntries()) {
                if (entry.ip() != local) continue;
                if (!tunnel.isEmpty() && tunnel != iface.name()) return false;
                tunnel = iface.name();
            }
        }
        return !tunnel.isEmpty() && m_policy.add(tunnel, hosts, throughVpn);
    }
private:
    amnezia::macOpenVpnIpv6::Native m_native;
    amnezia::macOpenVpnIpv6::Policy m_policy;
};
#endif
