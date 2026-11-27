#ifndef ROUTER_H
#define ROUTER_H

#include <QTimer>
#include <QString>
#include <QSettings>
#include <QHash>
#include <QDebug>
#include <QObject>
#include <QHostAddress>
#include <QJsonObject>
#include <functional>
#include <utility>

/**
 * @brief The Router class - General class for handling ip routing
 */
class Router : public QObject
{
    Q_OBJECT
public:
    static int routeAddList(const QString &gw, const QStringList &ips);
    static bool clearSavedRoutes();
    static int routeDeleteList(const QString &gw, const QStringList &ips);
    static bool flushDns();
    static void resetIpStack();
    static bool createTun(const QString &dev, const QString &subnet);
    static bool configureProxyIpv6(const QStringList &included, const QStringList &excluded);
    static bool deleteTun(const QString &dev);
    static bool StartRoutingIpv6();
    static bool StopRoutingIpv6();
    static bool updateResolvers(const QString& ifname, const QList<QHostAddress>& resolvers,
                                bool ipv6Enabled = true, const QString &owner = {});
    static bool restoreResolvers(const QString &owner = {});
    static bool shutdownNativeDns();
    static bool shutdownNativeResources();
    static bool startIkev2Dns(const QString &owner, const QByteArray &phonebook, const QStringList &endpoints);
    static QString ikev2DnsState(const QString &owner);
    static bool stopIkev2Dns(const QString &owner);
    static bool prepareIkev2DnsRecovery();
    static bool finishIkev2DnsRecovery();
    static bool nativeDnsAdmissionReady();
    static bool nativeBackendOwnsLifecycle();
    static bool acknowledgeIkev2DnsStopped(const QString &owner);
    static bool publishOpenVpnDns(const QString &owner, const QJsonObject &environment);
    static void connectNativeDnsFailure(QObject *receiver,
                                       std::function<void(const QString &)> callback);
};

#endif // ROUTER_H
