#ifndef CONNECTIONUPDATESCONTROLLER_H
#define CONNECTIONUPDATESCONTROLLER_H

#include <QObject>
#include <QNetworkAccessManager>
#include <QThreadPool>
#include <functional>
#include "core/repositories/secureServersRepository.h"

class ConnectionController;
class ConnectionUpdatesController : public QObject {
    Q_OBJECT
    Q_PROPERTY(bool busy READ busy NOTIFY busyChanged)
    Q_PROPERTY(QStringList enabledServers READ enabledServers NOTIFY configurationChanged)
    Q_PROPERTY(QStringList protectionServers READ protectionServers NOTIFY configurationChanged)
    Q_PROPERTY(QStringList updatableServers READ updatableServers NOTIFY configurationChanged)
public:
    using ProbeAddressReader = std::function<ErrorCode(const ServerCredentials &, DockerContainer, QString &)>;
    explicit ConnectionUpdatesController(SecureServersRepository *servers, ConnectionController *connection, QObject *parent = nullptr, ProbeAddressReader probeAddressReader = {});
    ~ConnectionUpdatesController() override;
    bool busy() const { return m_busy; }
    QStringList enabledServers() const;
    QStringList updatableServers() const;
    QStringList protectionServers() const;
    Q_INVOKABLE bool canEnableHeaderProtection(const QString &serverId, int container) const;
    Q_INVOKABLE void enableHeaderProtection(const QString &serverId, int container);
    static ErrorCode fetchPublicSettings(const ServerCredentials &credentials, DockerContainer container,
                                         const QString &host, QJsonObject &settings, QStringList *peers = nullptr, QString *pathMtuProbe = nullptr);
    static ErrorCode fetchPathMtuProbeAddress(const ServerCredentials &credentials, DockerContainer container, QString &address);
    Q_INVOKABLE bool available(const QString &serverId) const;
    Q_INVOKABLE bool enabled(const QString &serverId) const;
    Q_INVOKABLE void refresh(const QString &serverId);
    Q_INVOKABLE void install(const QString &serverId);
    Q_INVOKABLE void publish(const QString &serverId, int container);
    Q_INVOKABLE void revoke(const QString &serverId, int container, const QString &clientPublicKey);
    // Static SSH path can be used by the existing export controller.
    static ErrorCode command(const ServerCredentials &credentials, const QString &action, const QJsonObject &request, QJsonObject &response);
    bool needsRefreshBeforeConnect(const QString &serverId) const;
    void refreshBeforeConnect(const QString &serverId, const std::function<void()> &done);
signals:
    void busyChanged();
    void configurationChanged();
    void finished(bool success, const QString &message);
private:
    void fetch(const QString &serverId, bool report, std::function<void()> done = {});
    void setBusy(bool busy);
    void administer(const QString &serverId, const QString &action, int container = -1, const QString &clientPublicKey = {});
    SecureServersRepository *m_servers;
    ConnectionController *m_connection;
    ProbeAddressReader m_probeAddressReader;
    QNetworkAccessManager m_network;
    QThreadPool m_adminPool;
    bool m_busy = false;
};
#endif
