#ifndef OPENVPNDNSSESSION_H
#define OPENVPNDNSSESSION_H

#include <QObject>
#include <QJsonObject>
#include <QTimer>
#include <functional>
#include <utility>
#include "core/utils/managementServer.h"
#include "core/protocols/openVpnManagementEnvironment.h"

// Control-plane owner only. Native packet readers, routes and transport remain
// in OpenVPN. The existing service owns this object independently of GUI IPC.
class OpenVpnDnsSession final : public QObject {
    Q_OBJECT
public:
    struct Operations {
        std::function<bool(const QString &, const QJsonObject &)> publish;
        std::function<bool(const QString &)> restore;
    };
    explicit OpenVpnDnsSession(Operations operations, QObject *parent = nullptr);
    bool start();
    quint16 port() const { return m_port; }
    const QString &owner() const { return m_owner; }
    bool requestStop();
    bool nativeFinished();
    bool cleanupConfirmed() const { return !m_touched; }
    bool active() const { return m_active; }
    bool finished() const { return m_nativeFinished; }
    bool command(const QString &command);
    void guardFailed();
    const QJsonObject &nativeMetadata() const { return m_metadata; }

signals:
    void managementLine(const QString &line);
    void failed();
    void cleanupFinished();
    void disconnectedAfterRestore();
    void stopRestored();

private:
    void read();
    void retry();
    bool restore();
    void fail();
    QJsonObject selectedMetadata() const;
    Operations m_operations;
    ManagementServer m_management;
    QTimer m_retry;
    OpenVpnManagementEnvironment m_environment;
    const QString m_owner;
    quint16 m_port = 0;
    QString m_interface;
    QJsonObject m_frame, m_metadata;
    quint64 m_frameSerial = 0, m_consumedFrame = 0, m_lastRequest = 0;
    QString m_request, m_reply;
    enum class Action { None, Publish, Restore, Cancel };
    Action m_action = Action::None;
    bool m_touched = false, m_active = false, m_stopping = false;
    bool m_nativeFinished = false, m_failed = false, m_disconnected = false;
    bool m_retrying = false, m_stopSent = false, m_cleanupEmitted = false, m_disconnectEmitted = false;
    bool m_stopNotified = false;
};

#endif
