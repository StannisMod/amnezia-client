#ifndef WIREGUARDPROTOCOL_H
#define WIREGUARDPROTOCOL_H

#include <QObject>
#include <QProcess>
#include <QString>
#include <QTemporaryFile>
#include <QTimer>

#include "vpnProtocol.h"
#include "core/utils/vpnEndpointSession.h"
#include <QElapsedTimer>

#include "mozilla/controllerimpl.h"

class WireguardProtocol : public VpnProtocol
{
    Q_OBJECT

public:
    explicit WireguardProtocol(const QJsonObject& configuration, QObject* parent = nullptr);
    virtual ~WireguardProtocol() override;

    ErrorCode start() override;
    void stop() override;
    void reconnect();

    ErrorCode startMzImpl();
    ErrorCode stopMzImpl();

private:

    QScopedPointer<ControllerImpl> m_impl;
    amnezia::VpnEndpointSession m_endpointSession;
    QTimer m_peerPoll;
    QElapsedTimer m_peerClock;
    bool m_domainEndpoint = false;
    void setupEndpointSession();
};

#endif // WIREGUARDPROTOCOL_H
