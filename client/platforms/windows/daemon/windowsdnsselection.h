#ifndef WINDOWSDNSSELECTION_H
#define WINDOWSDNSSELECTION_H

#include <QHostAddress>
#include <QJsonArray>
#include <QJsonObject>
#include <QMap>
#include <QUrl>
#include <optional>

namespace WindowsDnsPolicy {
// Interpret only the original selected numeric servers and native known-server
// records. No discovery, hostname dial, guessed URI, or plaintext downgrade.
inline std::optional<QJsonArray> selectedResolverPolicy(
    const QList<QHostAddress> &servers, const QJsonArray &mappings, bool prohibitDoh)
{
    if (servers.isEmpty() || servers.size() > 32) return {};
    QMap<QString, QJsonObject> selected;
    for (const auto &value : mappings) {
        if (!value.isObject()) return {};
        const auto record = value.toObject();
        const QHostAddress ip(record["server"].toString());
        if (record.size() != 4 || ip.isNull() || !servers.contains(ip)
                || !record["template"].isString() || !record["auto_upgrade"].isBool()
                || !record["allow_fallback"].isBool() || selected.contains(ip.toString())) return {};
        selected.insert(ip.toString(), record);
    }
    QJsonArray result;
    for (const auto &server : servers) {
        if (server.isNull() || server.isMulticast() || server == QHostAddress::AnyIPv4
                || server == QHostAddress::AnyIPv6 || !server.scopeId().isEmpty()) return {};
        QJsonObject policy{{"server", server.toString()}, {"port", 53}, {"transport", "plain"}};
        const auto record = selected.value(server.toString());
        if (!prohibitDoh && record["auto_upgrade"].toBool()) {
            if (record["allow_fallback"].toBool()) return {}; // Not yet representable, never erase it.
            const auto original = record["template"].toString();
            auto text = original;
            const bool get = text.endsWith("{?dns}");
            if (get) text.chop(6);
            if (text.contains('{') || text.contains('}') || text.contains(QChar(0))
                    || text.contains('\r') || text.contains('\n')) return {};
            const QUrl uri(text, QUrl::StrictMode);
            const auto host = uri.host();
            const QHostAddress numericHost(host);
            if (!uri.isValid() || uri.scheme() != "https" || host.isEmpty()
                    || !uri.userInfo().isEmpty() || uri.hasFragment()
                    || (get && uri.hasQuery()) || uri.port(443) < 1 || uri.port(443) > 65535
                    || (!numericHost.isNull() && numericHost != server)) return {};
            policy = {{"server", server.toString()}, {"port", uri.port(443)},
                {"transport", "https"}, {"server_name", host}, {"https_url", original}};
        }
        result.append(policy); // Duplicate occurrences retain their original ordering.
    }
    return result;
}
}
#endif
