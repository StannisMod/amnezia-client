#ifndef MACOSDNSRECOVERY_H
#define MACOSDNSRECOVERY_H

#include <SystemConfiguration/SystemConfiguration.h>
#include "daemon/dnssettingsrecovery.h"
#include <QHostAddress>
#include <QStringList>

namespace MacosDnsRecovery {
DnsSettingsRecovery::Backend backend(SCDynamicStoreRef store);
QJsonObject capture(SCDynamicStoreRef store, const QList<QHostAddress> &endpoints,
                    const QJsonObject &previous = {});
// Explicit service set, also used by isolated native fixtures. Production's
// capture enumerates the complete original service set before calling this.
QJsonObject captureServices(SCDynamicStoreRef store, const QStringList &dnsKeys,
                            const QList<QHostAddress> &endpoints,
                            const QJsonObject &previous = {});
bool apply(SCDynamicStoreRef store, const QJsonObject &snapshot, bool restoring);
}
#endif
