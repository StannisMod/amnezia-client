#ifndef PROXYIPV6UPGRADE_H
#define PROXYIPV6UPGRADE_H
#include <QJsonObject>
#include <QString>
#include "core/utils/commonStructs.h"
#include "core/utils/containerEnum.h"
#include "core/utils/errorCodes.h"

namespace amnezia::proxyIpv6Upgrade {
bool supported(DockerContainer container);
bool parseProbeResponse(const QString &output, const QString &expectedRemote, QJsonObject &evidence);
// Adds the owned IPv6 bridge without changing proxy configuration or restarting
// its process. An unavailable IPv6 path is reported separately from IPv4 setup.
ErrorCode prepare(const ServerCredentials &credentials, DockerContainer container, QJsonObject &outcome);
}
#endif
