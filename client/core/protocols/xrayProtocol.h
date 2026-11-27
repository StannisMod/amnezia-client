#ifndef XRAYPROTOCOL_H
#define XRAYPROTOCOL_H

#include "QProcess"
#include <QtCore/qsharedpointer.h>
#include <QHostAddress>
#include <QList>

#include "core/utils/errorCodes.h"
#include "core/utils/routeModes.h"
#include "core/utils/commonStructs.h"
#include "core/utils/ipcClient.h"
#include "vpnProtocol.h"
#include "xrayStopSequence.h"

class XrayProtocol : public VpnProtocol
{
public:
    XrayProtocol(const QJsonObject &configuration, QObject *parent = nullptr);
    virtual ~XrayProtocol() override;

    ErrorCode start() override;
    void stop() override;

private:
    ErrorCode setupRouting(quint64 generation, const QString &owner);
    ErrorCode startTun2Socks();

    QJsonObject m_xrayConfig;
    amnezia::RouteMode m_routeMode;
    QList<QHostAddress> m_dnsServers;
    QString m_remoteAddress;

    QString m_socksUser;
    QString m_socksPassword;
    int m_socksPort = 10808;

    QSharedPointer<IpcProcessInterfaceReplica> m_tun2socksProcess;
    int m_tun2socksRetryCount = 0;
    bool m_tunPrepared = false;
    static constexpr int maxTun2SocksRetries = 5;
    static constexpr int tun2socksRetryDelayMs = 400;

    // Owner token of the shared xray engine; a late stop with a stale token
    // won't kill an engine restarted by another consumer (e.g. the local proxy).
    qint64 m_xrayToken = 0;
    QString m_dnsOwner;
    bool m_dnsAttempted = false;
    bool m_ipv6PolicyEnabled = true;
    quint64 m_tunGeneration = 0;
    bool m_routingApplied = false;
    QMetaObject::Connection m_dnsFailureConnection;
    XrayStopSequence m_stopSequence;
    bool m_stopRetryScheduled = false;
    bool m_destroying = false;
};

#endif // XRAYPROTOCOL_H
