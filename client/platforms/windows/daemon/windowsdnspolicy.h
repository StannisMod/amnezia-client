#ifndef WINDOWSDNSPOLICY_H
#define WINDOWSDNSPOLICY_H

#include <QHostAddress>
#include <QJsonObject>
#include <QJsonArray>
#include <optional>

namespace WindowsDnsPolicy {
// Read, never rewrite, native security/profile policy. Unknown providers and
// unsupported encrypted/namespace policies must not become plaintext DNS.
std::optional<QJsonObject> capturePlain(const QString &interfaceName,
                                      const QList<QHostAddress> &originalServers);
struct Selection {
    QJsonObject snapshot;
    QJsonArray resolverPolicy;
};
std::optional<Selection> captureSelected(const QString &interfaceName,
                                        const QList<QHostAddress> &originalServers);
}

#endif
