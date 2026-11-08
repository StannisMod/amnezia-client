#pragma once

#include <QDateTime>
#include <QJsonObject>
#include <QObject>
#include <QProcess>

// The service owns this child across GUI IPC connections. The child owns the
// sole TUN reader, DNS link and policy routes for an experimental routed AWG.
class DesktopRoutingProcess final : public QObject {
    Q_OBJECT
public:
    static DesktopRoutingProcess *instance();
    bool start(const QJsonObject &profile, bool strictKillSwitch);
    void stop(bool notify = true);
    bool isActive() const;
    QJsonObject status() const;
    bool matchesRuntime(const QString &id) const;
    bool networkChanged(const QString &id);
signals:
    void connected(const QString &publicKey);
    void disconnected();
    void failed();
private:
    explicit DesktopRoutingProcess(QObject *parent);
    void readOutput();
    QProcess m_process;
    QByteArray m_buffer;
    QJsonObject m_status;
    bool m_stopping = false;
    bool m_owned = false;
    QString m_runtimeId;
    bool m_preservesConnections = false;
    quint64 m_controlId = 0;
};
