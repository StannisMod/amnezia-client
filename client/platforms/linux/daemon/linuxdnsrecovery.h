#ifndef LINUXDNSRECOVERY_H
#define LINUXDNSRECOVERY_H

#include <QJsonArray>
#include <QJsonObject>
#include <QHostAddress>
#include <functional>

namespace LinuxDnsRecovery {
// The transport is injectable so the same compare/restore algorithm can be
// exercised without changing host DNS. Production uses resolved's D-Bus API.
struct Backend {
    std::function<QJsonObject(int)> read;
    std::function<bool(int, const QString &, const QJsonValue &)> write;
};
Backend systemBackend();
QJsonObject capture(const QString &ifname, const QList<QHostAddress> &endpoints,
                    const QJsonObject &previous = {},
                    const QJsonObject &linkPolicy = {});

inline bool restore(const QJsonObject &snapshot, const Backend &backend)
{
    if (snapshot.value("backend") != QJsonValue("systemd-resolved-v1")
            || !snapshot.value("links").isArray() || snapshot["links"].toArray().isEmpty()
            || !backend.read || !backend.write) return false;
    const auto links = snapshot["links"].toArray();
    QList<int> indices;
    // Validate every affected link before changing any of them. Unknown state
    // cannot be treated as an already completed restore.
    for (const auto &value : links) {
        if (!value.isObject()) return false;
        const auto link = value.toObject();
        const int index = link["index"].toInt();
        if (index <= 0 || indices.contains(index) || !link["before"].isObject()
                || !link["after"].isObject()) return false;
        indices.append(index);
        const auto before = link["before"].toObject();
        const auto after = link["after"].toObject();
        if (before.isEmpty() || before.keys() != after.keys()) return false;
        const auto current = backend.read(index);
        if (current.isEmpty()) return false;
        if (current.value("removed") == QJsonValue(true)) continue;
        if (current["name"] != link["name"] || current["hardware"] != link["hardware"]) return false;
        if (link.contains("native_policy") && (!link["native_policy"].isObject()
                || current["native_policy"] != link["native_policy"])) return false;
        for (auto it = before.begin(); it != before.end(); ++it) {
            if (it.key() != "dns" && it.key() != "dns_ex"
                    && it.key() != "domains" && it.key() != "default_route") return false;
            if ((it.key() == "default_route" && (!it.value().isBool() || !after[it.key()].isBool()))
                    || (it.key() != "default_route" && (!it.value().isArray() || !after[it.key()].isArray())))
                return false;
            if (current[it.key()] != it.value() && current[it.key()] != after[it.key()]) return false;
        }
    }
    for (const auto &value : links) {
        const auto link = value.toObject();
        const int index = link["index"].toInt();
        const auto before = link["before"].toObject();
        const auto after = link["after"].toObject();
        for (auto it = before.begin(); it != before.end(); ++it) {
            auto current = backend.read(index);
            if (current.isEmpty()) return false;
            if (current.value("removed") == QJsonValue(true)) break;
            if (current["name"] != link["name"] || current["hardware"] != link["hardware"]) return false;
            if (link.contains("native_policy") && current["native_policy"] != link["native_policy"]) return false;
            if (current[it.key()] == it.value()) continue;
            if (current[it.key()] != after[it.key()] || !backend.write(index, it.key(), it.value()))
                return false;
            current = backend.read(index);
            if (current.isEmpty() || current["name"] != link["name"]
                    || current["hardware"] != link["hardware"] || current[it.key()] != it.value())
                return false;
            if (link.contains("native_policy") && current["native_policy"] != link["native_policy"]) return false;
        }
    }
    // A late platform/user change during another link's restoration must not
    // be reported as confirmation that aliases can now be removed.
    for (const auto &value : links) {
        const auto link = value.toObject();
        const auto current = backend.read(link["index"].toInt());
        if (current.isEmpty()) return false;
        if (current.value("removed") == QJsonValue(true)) continue;
        if (current["name"] != link["name"] || current["hardware"] != link["hardware"]) return false;
        if (link.contains("native_policy") && current["native_policy"] != link["native_policy"]) return false;
        const auto before = link["before"].toObject();
        for (auto it = before.begin(); it != before.end(); ++it)
            if (current[it.key()] != it.value()) return false;
    }
    return true;
}
}
#endif
