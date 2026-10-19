#pragma once

#include <QHostAddress>
#include <QJsonArray>
#include <QJsonObject>
#include <QVariantMap>

#include "routeModes.h"

namespace amnezia::routing {

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
