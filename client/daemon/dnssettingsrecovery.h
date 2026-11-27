#ifndef DNSSETTINGSRECOVERY_H
#define DNSSETTINGSRECOVERY_H

#include <QJsonArray>
#include <QJsonObject>
#include <QSet>
#include <functional>

namespace DnsSettingsRecovery {
// Undefined means unreadable/unknown; null means a confirmed absent setting.
struct Backend {
    std::function<QJsonValue(const QString &)> read;
    std::function<bool(const QString &, const QJsonValue &)> write;
    std::function<bool(const QJsonValue &, const QJsonValue &)> equal =
        [](const QJsonValue &a, const QJsonValue &b) { return a == b; };
};

inline bool apply(const QJsonObject &snapshot, const QString &kind,
                  const Backend &backend, bool restoring)
{
    if (snapshot["backend"] != QJsonValue(kind) || !snapshot["entries"].isArray()
            || !backend.read || !backend.write || !backend.equal) return false;
    const auto entries = snapshot["entries"].toArray();
    if (entries.isEmpty()) return false;
    QSet<QString> keys;
    for (const auto &item : entries) {
        const auto entry = item.toObject();
        const auto key = entry["key"].toString();
        if (!item.isObject() || key.isEmpty() || keys.contains(key)
                || !entry.contains("before") || !entry.contains("after")) return false;
        keys.insert(key);
        const auto current = backend.read(key);
        if (current.isUndefined() ||
                (!backend.equal(current, entry["before"]) && !backend.equal(current, entry["after"])))
            return false;
    }
    const QString desired = restoring ? "before" : "after";
    for (const auto &item : entries) {
        const auto entry = item.toObject();
        const auto key = entry["key"].toString();
        const auto current = backend.read(key);
        if (current.isUndefined() ||
                (!backend.equal(current, entry["before"]) && !backend.equal(current, entry["after"])))
            return false;
        if (!backend.equal(current, entry[desired]) &&
                !backend.write(key, entry[desired])) return false;
        const auto confirmed = backend.read(key);
        if (confirmed.isUndefined() || !backend.equal(confirmed, entry[desired])) return false;
    }
    for (const auto &item : entries) {
        const auto entry = item.toObject();
        const auto current = backend.read(entry["key"].toString());
        if (current.isUndefined() || !backend.equal(current, entry[desired])) return false;
    }
    return true;
}
}
#endif
