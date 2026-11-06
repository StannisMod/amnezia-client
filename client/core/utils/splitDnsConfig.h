#pragma once

#include <QJsonArray>
#include <QJsonObject>
#include <QString>

namespace amnezia::dns {

// Input is the connection controller's effective DNS (AmneziaDNS when available,
// otherwise the existing DNS settings/profile), never a separate saved policy.
inline QJsonObject forSiteRoutes(const QJsonObject &routing, const QString &vpnDns)
{
    bool directNames = routing.value("default").toString() == "direct";
    for (const auto &item : routing.value("rules").toArray()) {
        const auto rule = item.toObject();
        const auto kind = rule.value("kind").toString();
        if (!rule.value("disabled").toBool() && rule.value("action") == "direct"
                && rule.value("ports").toString().isEmpty() && rule.value("network").toString().isEmpty()
                && (kind == "domain" || kind == "suffix")) directNames = true;
    }
    QJsonObject policies{{"vpn", QJsonObject{{"transport", "udp"}, {"server", vpnDns}, {"path", "vpn"}}}};
    QJsonObject config{{"version", 1}, {"default", "vpn"}, {"follow_routing", directNames},
                       {"policies", policies}, {"rules", QJsonArray{}}};
    if (directNames) {
        policies.insert("direct", QJsonObject{{"source", "network"}, {"server", ""},
                                              {"transport", "udp"}, {"path", "direct"}});
        config.insert("policies", policies);
        config.insert("direct", "direct");
        config.insert("vpn", "vpn");
    }
    // All-VPN DNS needs no physical-link discovery. Explicit DNS exceptions
    // and imported corporate rules are deliberately absent from this policy.
    return config;
}
}
