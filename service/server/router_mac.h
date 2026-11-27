#ifndef ROUTERMAC_H
#define ROUTERMAC_H

#include <QTimer>
#include <QString>
#include <QSettings>
#include <QHash>
#include <QDebug>
#include <QObject>

#include "../client/platforms/macos/daemon/dnsutilsmacos.h"
#include "../client/platforms/macos/daemon/macproxyipv6.h"
#include <memory>

/**
 * @brief The Router class - General class for handling ip routing
 */
class RouterMac : public QObject
{
    Q_OBJECT
public:    
    static RouterMac& Instance();

    struct Route {
        QString dst;
        QString gw;
    };

    bool routeAdd(const QString &ip, const QString &gw);
    int routeAddList(const QString &gw, const QStringList &ips);
    bool clearSavedRoutes();
    bool routeDelete(const QString &ip, const QString &gw);
    bool routeDeleteList(const QString &gw, const QStringList &ips);
    bool flushDns();
    bool createTun(const QString &dev, const QString &subnet);
    bool configureProxyIpv6(const QStringList &included, const QStringList &excluded);
    bool deleteTun(const QString &dev);
    bool updateResolvers(const QString& ifname, const QList<QHostAddress>& resolvers,
                         bool ipv6Enabled = true, const QString &owner = {});
    bool restoreResolvers(const QString &owner = {});
    DnsUtils *nativeDnsUtility() { return m_dnsUtil; }
    bool routeAddXray(const QString& ifname, const QString& gateway);
    bool routeDeleteXray(const QString& ifname, const QString& gateway);
    
public slots:

private:
    RouterMac() {m_dnsUtil = new DnsUtilsMacos(this);}
    RouterMac(RouterMac const &) = delete;
    RouterMac& operator= (RouterMac const&) = delete;

    QList<Route> m_addedRoutes;
    DnsUtilsMacos *m_dnsUtil;    
    bool m_proxyTunConfigured = false;
    std::unique_ptr<MacProxyIpv6> m_proxyIpv6;
};

#endif // ROUTERMAC_H
