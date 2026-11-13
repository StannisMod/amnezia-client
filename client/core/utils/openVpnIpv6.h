#pragma once

#include "proxyIpv6Routes.h"
#include "routeModes.h"
#include <QRegularExpression>

namespace amnezia::openVpnIpv6 {
inline QRegularExpression captureBlock()
{
    return QRegularExpression("^# amnezia-ipv6-capture-begin\\n.*?^# amnezia-ipv6-capture-end[ \\t]*(?:\\n|$)",
        QRegularExpression::MultilineOption | QRegularExpression::DotMatchesEverythingOption);
}
inline bool activeServerTunnel(const QString &config, const QString &kernelAddresses)
{
    const QRegularExpression directive("^[ \\t]*server-ipv6[ \\t]+([^\\s#]+)[ \\t]*(?:#.*)?$",
                                       QRegularExpression::MultilineOption);
    const auto match = directive.match(config);
    if (!match.hasMatch()) return false;
    const auto subnet = QHostAddress::parseSubnet(match.captured(1));
    if (subnet.first.protocol() != QAbstractSocket::IPv6Protocol || subnet.second < 64 || subnet.second > 112) return false;
    for (const auto &line : kernelAddresses.split('\n')) {
        const auto fields = line.simplified().split(' ');
        if (fields.size() != 6 || fields[5] != "tun0"
            || !QRegularExpression("^[0-9a-fA-F]{32}$").match(fields[0]).hasMatch()) continue;
        bool validFlags;
        const auto flags = fields[4].toUInt(&validFlags, 16);
        if (!validFlags || (flags & (0x40 | 0x08))) continue; // tentative / DAD failed
        QStringList groups;
        for (int i = 0; i < 32; i += 4) groups.append(fields[0].mid(i, 4));
        if (QHostAddress(groups.join(':')).isInSubnet(subnet)) return true;
    }
    return false;
}

inline QString captureDirectives(RouteMode mode, const QStringList &sites, const QStringList &dns)
{
    QStringList included, excluded;
    if (mode != RouteMode::VpnOnlyForwardSites) included << "::/0";
    for (const auto &site : sites) {
        const auto subnet = QHostAddress::parseSubnet(site);
        if (subnet.first.protocol() != QAbstractSocket::IPv6Protocol) continue;
        if (mode == RouteMode::VpnOnlyForwardSites) included << site;
        else if (mode == RouteMode::VpnAllExceptSites) excluded << site;
    }
    if (mode == RouteMode::VpnOnlyForwardSites)
        for (const auto &server : dns)
            if (QHostAddress(server).protocol() == QAbstractSocket::IPv6Protocol) included << server + "/128";
    QStringList routes;
    if (!routing::proxyIpv6Routes(included, excluded, routes)) return "\nblock-ipv6\n";
    QString output = "\n# amnezia-ipv6-capture-begin\n";
    for (const auto &route : routes) output += "\nroute-ipv6 " + route;
    return output + "\n# amnezia-ipv6-capture-end\n";
}
}
