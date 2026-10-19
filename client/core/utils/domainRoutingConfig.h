#pragma once

#include <QHostAddress>
#include <QJsonArray>
#include <QJsonObject>
#include <QVariantMap>
#include <QUrl>
#include <QRegularExpression>

#include "routeModes.h"

namespace amnezia::routing {

inline QJsonObject destinationRule(QString input, const QString &action, bool enabled)
{
    if (action != "direct" && action != "vpn") return {};
    input = input.trimmed();
    QString kind;
    QHostAddress address(input);
    auto subnet = QHostAddress::parseSubnet(input);
    if (!address.scopeId().isEmpty() || !subnet.first.scopeId().isEmpty()) return {};
    if (!address.isNull() || subnet.second >= 0) {
        kind = "cidr";
        if (subnet.second < 0) subnet = {address, address.protocol() == QAbstractSocket::IPv4Protocol ? 32 : 128};
        if (subnet.first.protocol() == QAbstractSocket::IPv4Protocol) {
            const quint32 mask = subnet.second == 0 ? 0 : quint32(0xffffffff) << (32 - subnet.second);
            input = QHostAddress(subnet.first.toIPv4Address() & mask).toString();
        } else {
            auto bytes = subnet.first.toIPv6Address();
            for (int i = 0; i < 16; ++i) {
                const int bits = qBound(0, subnet.second - i * 8, 8);
                bytes[i] &= bits == 0 ? 0 : (0xff << (8 - bits));
            }
            input = QHostAddress(bytes).toString();
        }
        input += "/" + QString::number(subnet.second);
    } else {
        kind = input.startsWith("*.") ? "suffix" : "domain";
        if (kind == "suffix") input.remove(0, 2);
        if (input.endsWith('.')) input.chop(1);
        input = QString::fromLatin1(QUrl::toAce(input.toLower()));
        static const QRegularExpression label("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$");
        if (input.isEmpty() || input.size() > 253) return {};
        for (const auto &part : input.split('.')) if (!label.match(part).hasMatch()) return {};
    }
    return {{"kind", kind}, {"value", input}, {"action", action}, {"disabled", !enabled}};
}

// Preserve hostname identity. Cached legacy DNS answers must never be emitted
// as IP rules for a hostname; canonical validation/precedence lives in Go.
inline QJsonObject fromLegacySites(bool enabled, RouteMode mode, const QVariantMap &sites)
{
    const bool inverse = enabled && mode == RouteMode::VpnOnlyForwardSites;
    QJsonArray rules;
    if (enabled && mode != RouteMode::VpnAllSites) {
        for (auto it = sites.cbegin(); it != sites.cend(); ++it) {
            const QString value = it.key().trimmed();
            const QHostAddress literal(value);
            const auto subnet = QHostAddress::parseSubnet(value);
            const QString kind = !literal.isNull() || subnet.second >= 0 ? QStringLiteral("cidr")
                    : value.startsWith("*.") ? QStringLiteral("suffix") : QStringLiteral("domain");
            rules.append(QJsonObject{{"kind", kind}, {"value", value},
                                     {"action", inverse ? "vpn" : "direct"}});
        }
    }
    return {{"version", 1}, {"default", inverse ? "direct" : "vpn"}, {"rules", rules}};
}
}
