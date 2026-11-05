#ifndef SERVERMIGRATIONCONTROLLER_H
#define SERVERMIGRATIONCONTROLLER_H
#include <QObject>
#include <QJsonObject>
#include <QThreadPool>
#include <functional>
#include "core/repositories/secureServersRepository.h"
#include "secureQSettings.h"
class ConnectionController;

// A single durable operation. Secrets live in the same secure storage as server
// credentials; workers receive value copies and never touch repository objects.
class ServerMigrationController : public QObject {
    Q_OBJECT
    Q_PROPERTY(bool busy READ busy NOTIFY changed)
    Q_PROPERTY(QString phase READ phase NOTIFY changed)
    Q_PROPERTY(QString details READ details NOTIFY changed)
    Q_PROPERTY(QString serverId READ serverId NOTIFY changed)
    Q_PROPERTY(QString domain READ domain NOTIFY changed)
    Q_PROPERTY(QString targetAddress READ targetAddress NOTIFY changed)
public:
    ServerMigrationController(SecureServersRepository *, SecureQSettings *, ConnectionController *, QObject *parent = nullptr);
    ~ServerMigrationController() override;
    bool busy() const { return m_busy; }
    QString phase() const { return m_journal.value("phase").toString(); }
    QString details() const { return m_details; }
    QString domain() const { return m_journal.value("domain").toString(); }
    QString targetAddress() const { return m_journal.value("targetIdentity").toObject().value("address").toString(); }
    QString serverId() const { return m_journal.value("serverId").toString(); }
    Q_INVOKABLE void discover(const QString &id, const QString &host, int port, const QString &user, const QString &secret);
    Q_INVOKABLE void stage();
    Q_INVOKABLE void cutover();
    Q_INVOKABLE void recover();
    Q_INVOKABLE void rollback();
    Q_INVOKABLE void dismiss();
signals:
    void changed();
private:
    void work(const std::function<QJsonObject(QJsonObject)> &);
    void persist();
    SecureServersRepository *m_servers;
    SecureQSettings *m_settings;
    ConnectionController *m_connection;
    QThreadPool m_pool;
    QJsonObject m_journal;
    QString m_details;
    bool m_busy = false;
};
#endif
