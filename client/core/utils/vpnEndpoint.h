#ifndef VPNENDPOINT_H
#define VPNENDPOINT_H

#include <QHostAddress>
#include <QJsonObject>
#include <QRegularExpression>
#include <QStringList>
#include <QUrl>

namespace amnezia::vpnEndpoint
{
// Accept a host only. A port belongs to the selected protocol, not this field.
inline QString normalizeHost(const QString &input)
{
    QString host = input.trimmed();
    if (host.isEmpty()) return {};
    if (host.startsWith('[') && host.endsWith(']')) host = host.mid(1, host.size() - 2);
    const QHostAddress address(host);
    if (!address.isNull()) {
        if (!address.scopeId().isEmpty()) return {};
        return address.toString();
    }
    if (host.contains(':') || host.contains('/') || host.contains('@') || host.contains('%')) return {};
    if (host.endsWith('.')) host.chop(1);
    const QString ascii = QString::fromLatin1(QUrl::toAce(host)).toLower();
    if (ascii.isEmpty() || ascii.size() > 253) return {};
    static const QRegularExpression label(QStringLiteral("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"));
    const auto labels = ascii.split('.');
    if (labels.size() < 2) return {};
    // Do not treat a malformed IPv4 literal as a DNS hostname.
    static const QRegularExpression numeric(QStringLiteral("^[0-9.]+$"));
    if (numeric.match(ascii).hasMatch()) return {};
    for (const auto &part : labels) {
        if (!label.match(part).hasMatch()) return {};
    }
    return ascii;
}

// Legacy desktop WireGuard accepts IPv4 endpoints. Routed transport can also
// accept IPv6. Prefer A records on dual-stack domains for the legacy backend.
inline QString preferredAddress(const QList<QHostAddress> &addresses, bool allowIpv6)
{
    for (const auto &address : addresses) {
        if (address.protocol() == QAbstractSocket::IPv4Protocol) return address.toString();
    }
    if (allowIpv6) {
        for (const auto &address : addresses) {
            if (address.protocol() == QAbstractSocket::IPv6Protocol && address.scopeId().isEmpty()) return address.toString();
        }
    }
    return {};
}

// Return a disposable activation profile; never replace the persisted hostname
// (or the protocol object's reconnect configuration) with the resolved address.
inline QJsonObject activationConfig(QJsonObject config, const QString &address)
{
    const QString key = config.value(QStringLiteral("protocol")).toString() + QStringLiteral("_config_data");
    auto data = config.value(key).toObject();
    const auto original = normalizeHost(data.value(QStringLiteral("hostName")).toString());
    if (config.contains(QStringLiteral("sing_box_routing")) && !original.isEmpty() && QHostAddress(original).isNull())
        config[QStringLiteral("routing_endpoint_host")] = original;
    else config.remove(QStringLiteral("routing_endpoint_host"));
    data[QStringLiteral("hostName")] = address;
    config[key] = data;
    config[QStringLiteral("hostName")] = address;
    return config;
}

inline QString replacePeerHost(const QString &config, const QString &host)
{
    QStringList lines = config.split('\n');
    bool peer = false;
    static const QRegularExpression endpoint(QStringLiteral("^(\\s*Endpoint\\s*=\\s*)(?:\\[[^\\]]+\\]|[^\\s:]+):(\\d+)(\\s*(?:#.*)?\\r?)$"));
    for (auto &line : lines) {
        const QString trimmed = line.trimmed();
        if (trimmed.startsWith('[')) peer = trimmed == QStringLiteral("[Peer]");
        if (!peer) continue;
        const auto match = endpoint.match(line);
        if (!match.hasMatch()) continue;
        const QString formattedHost = host.contains(':') ? QStringLiteral("[%1]").arg(host) : host;
        line = match.captured(1) + formattedHost + ':' + match.captured(2) + match.captured(3);
    }
    return lines.join('\n');
}
} // namespace amnezia::vpnEndpoint
#endif
