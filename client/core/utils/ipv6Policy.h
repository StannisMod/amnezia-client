#pragma once

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSet>
#include <QHostAddress>

namespace amnezia::ipv6Policy {

inline bool tunnelAvailable(const QJsonObject &config)
{
    if (!config.value("ipv6_enabled").toBool(true)) return false;
    if (config.value("proxyIpv6").toBool()) return true;
    if (config.value("openvpn_config_data").toObject().value("ipv6Tunnel").toBool()) return true;
    const auto protocol = config.value("protocol").toString();
    if (protocol != "awg" && protocol != "wireguard") return false;
    for (const auto &entry : config.value(protocol + "_config_data").toObject().value("client_ip").toString().split(',')) {
        const auto address = QHostAddress::parseSubnet(entry.trimmed()).first;
        if (address.protocol() == QAbstractSocket::IPv6Protocol && !address.isNull()
            && !address.isLinkLocal() && !address.isMulticast() && !address.isLoopback()
            && address.scopeId().isEmpty()) return true;
    }
    return false;
}

// Apply only to the connection copy, never to the stored/imported profile.
// Preserve native IPv6 capture and reject inside Xray instead of bypassing VPN.
inline QString disableXray(const QString &config)
{
    const auto document = QJsonDocument::fromJson(config.toUtf8());
    if (!document.isObject()) return config; // Still invalid: startup must fail.
    auto root = document.object();
    auto outbounds = root.value("outbounds").toArray();
    QSet<QString> tags;
    for (const auto &outbound : outbounds) tags.insert(outbound.toObject().value("tag").toString());
    QString tag = QStringLiteral("amnezia-ipv6-disabled");
    while (tags.contains(tag)) tag += QLatin1Char('_');
    outbounds.append(QJsonObject{{"tag", tag}, {"protocol", "blackhole"}, {"settings", QJsonObject()}});
    root.insert("outbounds", outbounds);
    auto routing = root.value("routing").toObject();
    auto rules = routing.value("rules").toArray();
    rules.prepend(QJsonObject{{"type", "field"}, {"ip", QJsonArray{"::/0"}}, {"outboundTag", tag}});
    routing.insert("rules", rules);
    root.insert("routing", routing);
    return QString::fromUtf8(QJsonDocument(root).toJson(QJsonDocument::Compact));
}
}
