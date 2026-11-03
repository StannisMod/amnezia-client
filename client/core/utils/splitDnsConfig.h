#pragma once

#include <QObject>
#include "domainRoutingConfig.h"

namespace amnezia::dns {

// UI validation gives useful feedback before saving. The shared native core
// repeats validation at every start, including imported/restored settings.
inline QString validate(const QJsonObject &config)
{
    if (config.value("version").toInt() != 1)
        return QObject::tr("Unsupported split DNS settings version.");
#if !defined(Q_OS_LINUX) || defined(Q_OS_ANDROID)
    if (config.value("preserve_network_domains").toBool())
        return QObject::tr("Automatic network DNS discovery is currently available on Linux only. Use explicit DNS servers on this platform.");
#endif
    const auto policies = config.value("policies").toObject();
    if (policies.isEmpty() || policies.size() > 64)
        return QObject::tr("Add between 1 and 64 DNS policies.");
    static const QRegularExpression identifier("^[a-z0-9_-]{1,64}$");
    for (auto it = policies.begin(); it != policies.end(); ++it) {
        const auto p = it.value().toObject();
        const auto path = p.value("path").toString();
        const auto transport = p.value("transport").toString();
        const auto server = p.value("server").toString();
        const auto port = p.value("port").toInt(-1);
        if (!identifier.match(it.key()).hasMatch() || (path != "direct" && path != "vpn")
            || (transport != "udp" && transport != "tcp" && transport != "tls" && transport != "https")
            || (p.contains("port") && (port < 1 || port > 65535)))
            return QObject::tr("Check the DNS policy identifier, transport, port and route.");
        if (p.value("source").toString() == "network") {
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
            if (path != "direct" || (transport != "udp" && transport != "tcp") || !server.isEmpty())
                return QObject::tr("DNS from the current network requires direct UDP or TCP.");
            continue;
#else
            return QObject::tr("Automatic network DNS discovery is currently available on Linux only. Use explicit DNS servers on this platform.");
#endif
        }
        const QHostAddress address(server);
        if (address.isNull()) {
            if (routing::destinationRule(server, "direct", true).value("kind") != "domain")
                return QObject::tr("Enter a DNS server IP address or hostname.");
            // Bootstrap must be an explicit numeric address with a port.
            const auto bootstrap = p.value("bootstrap").toString();
            const int colon = bootstrap.lastIndexOf(':');
            QString host = bootstrap.left(colon);
            if (host.startsWith('[') && host.endsWith(']')) host = host.mid(1, host.size() - 2);
            bool ok = false;
            const auto bootstrapPort = bootstrap.mid(colon + 1).toUInt(&ok);
            if (colon < 0 || QHostAddress(host).isNull() || !ok || bootstrapPort == 0 || bootstrapPort > 65535)
                return QObject::tr("A DNS hostname needs a numeric bootstrap server with a port, using the same route.");
        } else if (!address.scopeId().isEmpty() || address == QHostAddress::Any || address == QHostAddress::AnyIPv6
                   || address.isMulticast() || (address.isLoopback() && path == "vpn")
                   || address.isInSubnet(QHostAddress("198.18.0.0"), 15)
                   || address.isInSubnet(QHostAddress("fc00::"), 18)
                   || address.isInSubnet(QHostAddress("172.19.0.0"), 30)
                   || address.isInSubnet(QHostAddress("fdfe:dcba:9876::"), 126)
                   || address == QHostAddress("127.0.0.53") || address == QHostAddress("127.0.0.54")) {
            return QObject::tr("Use an upstream DNS server, not the VPN DNS address, FakeIP range or system stub.");
        }
    }
    const auto hasPolicy = [&](const QString &id) { return policies.contains(id); };
    if (!config.value("follow_routing").toBool() && !hasPolicy(config.value("default").toString()))
        return QObject::tr("Select a default DNS policy.");
    if (config.value("follow_routing").toBool()) {
        const auto direct = config.value("direct").toString(), vpn = config.value("vpn").toString();
        if (!hasPolicy(direct) || !hasPolicy(vpn) || policies.value(direct).toObject().value("path") != "direct"
            || policies.value(vpn).toObject().value("path") != "vpn")
            return QObject::tr("DNS by site route needs a direct policy and a VPN policy.");
    }
    QMap<QString, QString> seen;
    const auto rules = config.value("rules").toArray();
    if (rules.size() > 4096) return QObject::tr("Too many DNS rules.");
    for (const auto &item : rules) {
        const auto rule = item.toObject();
        const auto kind = rule.value("kind").toString(), policy = rule.value("policy").toString();
        const auto normalized = routing::destinationRule((kind == "suffix" ? "*." : "") + rule.value("value").toString(), "direct", true);
        if ((kind != "domain" && kind != "suffix") || normalized.isEmpty()
            || normalized.value("kind") != kind || !hasPolicy(policy))
            return QObject::tr("DNS rules need a domain or *.suffix and an existing policy.");
        if (!rule.value("disabled").toBool()) {
            const auto key = kind + ":" + normalized.value("value").toString();
            if (seen.contains(key) && seen.value(key) != policy)
                return QObject::tr("Conflicting DNS rules for the same domain.");
            seen.insert(key, policy);
        }
    }
    return {};
}
}
