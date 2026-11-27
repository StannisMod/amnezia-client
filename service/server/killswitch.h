#ifndef KILLSWITCH_H
#define KILLSWITCH_H

#include <QJsonObject>
#include <QHostAddress>
#include <QSharedPointer>

class SecureQSettings;

class KillSwitch : public QObject
{
    Q_OBJECT
public:
    static KillSwitch *instance();
    bool init();
    bool refresh(bool enabled);
    bool disableKillSwitch();
    bool disableAllTraffic();
    bool enablePeerTraffic(const QJsonObject &configStr);
    bool enableKillSwitch(const QJsonObject &configStr, int vpnAdapterIndex);
    bool resetAllowedRange(const QStringList &ranges);
    bool addAllowedRange(const QStringList &ranges);
    bool isStrictKillSwitchEnabled();
    bool endpointDnsAllowed(quint16 port, const QHostAddress &resolver, bool enabled);
    bool beginRoutedSession(const QString &helperPath);
    bool routedInterfaceReady(const QString &captureId);
    bool endRoutedSession();
#if defined(Q_OS_MACOS) || defined(Q_OS_WIN)
    bool setNativeIpv6Blocked(bool blocked, const QStringList &endpoints = {});
#endif

private:
    KillSwitch(QObject* parent) {};
    QStringList m_allowedRanges;
    QSharedPointer<SecureQSettings> m_appSettigns;
    bool applyRoutedExemptions();
    bool m_routedSession = false;
    QString m_routingHelperPath;
    quint64 m_routingLuid = 0;
#ifdef Q_OS_MACOS
    bool m_nativeIpv6Blocked = false;
#endif

};

#endif // KILLSWITCH_H
