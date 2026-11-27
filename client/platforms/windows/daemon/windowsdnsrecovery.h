#ifndef WINDOWSDNSRECOVERY_H
#define WINDOWSDNSRECOVERY_H

#include "daemon/dnssettingsrecovery.h"
#include <QHostAddress>

namespace WindowsDnsRecovery {
DnsSettingsRecovery::Backend backend();
QJsonObject capture(const QString &ifname, const QList<QHostAddress> &endpoints,
                    const QJsonObject &previous = {},
                    const QList<QHostAddress> &originalServers = {});
bool policyUnchanged(const QJsonObject &snapshot);
bool apply(const QJsonObject &snapshot, bool restoring);
}
#endif
