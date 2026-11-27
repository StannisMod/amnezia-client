#include "router.h"
#include "openvpndnsselection.h"

#ifdef Q_OS_WIN
#include "router_win.h"
#include "killswitch.h"
#include "windows/daemon/windowsdaemon.h"
#elif defined (Q_OS_MAC)
#include "router_mac.h"
#elif defined Q_OS_LINUX
#include "router_linux.h"
#endif


int Router::routeAddList(const QString &gw, const QStringList &ips)
{
#ifdef Q_OS_WIN
    return RouterWin::Instance().routeAddList(gw, ips);
#elif defined (Q_OS_MAC)
    return RouterMac::Instance().routeAddList(gw, ips);
#elif defined Q_OS_LINUX
    return RouterLinux::Instance().routeAddList(gw, ips);
#endif
}

bool Router::clearSavedRoutes()
{
#ifdef Q_OS_WIN
    return RouterWin::Instance().clearSavedRoutes();
#elif defined (Q_OS_MAC)
    return RouterMac::Instance().clearSavedRoutes();
#elif defined Q_OS_LINUX
    return RouterLinux::Instance().clearSavedRoutes();
#endif
}

int Router::routeDeleteList(const QString &gw, const QStringList &ips)
{
#ifdef Q_OS_WIN
    return RouterWin::Instance().routeDeleteList(gw, ips);
#elif defined (Q_OS_MAC)
    return RouterMac::Instance().routeDeleteList(gw, ips);
#elif defined Q_OS_LINUX
    return RouterLinux::Instance().routeDeleteList(gw, ips);
#endif
}

bool Router::flushDns()
{
#ifdef Q_OS_WIN
    return RouterWin::Instance().flushDns();
#elif defined (Q_OS_MAC)
    return RouterMac::Instance().flushDns();
#elif defined Q_OS_LINUX
    return RouterLinux::Instance().flushDns();
#endif
}

void Router::resetIpStack()
{
#ifdef Q_OS_WIN
    RouterWin::Instance().resetIpStack();
#elif defined (Q_OS_MAC)
    // todo fixme
#elif defined Q_OS_LINUX
    // todo fixme
#endif
}

bool Router::configureProxyIpv6(const QStringList &included, const QStringList &excluded)
{
#ifdef Q_OS_LINUX
    return RouterLinux::Instance().configureProxyIpv6(included, excluded);
#elif defined(Q_OS_MAC)
    return RouterMac::Instance().configureProxyIpv6(included, excluded);
#elif defined(Q_OS_WIN)
    return RouterWin::Instance().configureProxyIpv6(included, excluded);
#else
    Q_UNUSED(included)
    Q_UNUSED(excluded)
    return false;
#endif
}

bool Router::createTun(const QString &dev, const QString &subnet)
{
#ifdef Q_OS_WIN
    return RouterWin::Instance().createTun(dev, subnet);
#endif
#ifdef Q_OS_LINUX
    return RouterLinux::Instance().createTun(dev, subnet);
#endif
#ifdef Q_OS_MAC
    return RouterMac::Instance().createTun(dev, subnet);
#endif
    return true;
};

bool Router::deleteTun(const QString &dev)
{
#ifdef Q_OS_WIN
    return RouterWin::Instance().deleteTun(dev);
#endif
#ifdef Q_OS_LINUX
    return RouterLinux::Instance().deleteTun(dev);
#endif
#ifdef Q_OS_MAC
    return RouterMac::Instance().deleteTun(dev);
#endif
    return true;
};

namespace { bool nativeDnsShuttingDown = false; }

bool Router::updateResolvers(const QString& ifname, const QList<QHostAddress>& resolvers,
                             bool ipv6Enabled, const QString &owner)
{
    if (nativeDnsShuttingDown) return false;
#ifdef Q_OS_LINUX
    return RouterLinux::Instance().updateResolvers(ifname, resolvers, ipv6Enabled, owner);
#endif
#ifdef Q_OS_MACOS
    return RouterMac::Instance().updateResolvers(ifname, resolvers, ipv6Enabled, owner);
#endif
#ifdef Q_OS_WIN
    return RouterWin::Instance().updateResolvers(ifname, resolvers, ipv6Enabled, owner);
#endif
}

bool Router::restoreResolvers(const QString &owner) {
#ifdef Q_OS_LINUX
    return RouterLinux::Instance().restoreResolvers(owner);
#endif
#ifdef Q_OS_MACOS
    return RouterMac::Instance().restoreResolvers(owner);
#endif
#ifdef Q_OS_WIN
    return RouterWin::Instance().restoreResolvers(owner);
#endif
}

bool Router::publishOpenVpnDns(const QString &owner, const QJsonObject &environment)
{
    if (nativeDnsShuttingDown) return false;
    const auto selection = openVpnDnsSelection(environment,
#ifdef Q_OS_LINUX
        true
#else
        false
#endif
    );
    if (!selection) {
        qWarning("Native OpenVPN DNS policy cannot be represented without changing scope/security");
        return false;
    }
#ifdef Q_OS_WIN
    auto *utility = RouterWin::Instance().nativeDnsUtility();
#elif defined(Q_OS_MACOS)
    auto *utility = RouterMac::Instance().nativeDnsUtility();
#else
    auto *utility = RouterLinux::Instance().nativeDnsUtility();
#endif
    return utility->updateResolvers(selection->interfaceName, selection->servers, false, owner,
        QJsonObject{{"protocol", "openvpn"}, {"native", selection->metadata}}, selection->linkPolicy,
        selection->resolverPolicy);
}
bool Router::shutdownNativeDns()
{
    nativeDnsShuttingDown = true;
#ifdef Q_OS_WIN
    if (!RouterWin::Instance().ikev2Dns()->shutdown()) return false;
    auto *utility = RouterWin::Instance().nativeDnsUtility();
#elif defined(Q_OS_MACOS)
    auto *utility = RouterMac::Instance().nativeDnsUtility();
#else
    auto *utility = RouterLinux::Instance().nativeDnsUtility();
#endif
    return utility->restoreResolversForCurrentOwner();
}

bool Router::startIkev2Dns(const QString &owner, const QByteArray &phonebook, const QStringList &endpoints)
{
    if (nativeDnsShuttingDown) return false;
#ifdef Q_OS_WIN
    return RouterWin::Instance().ikev2Dns()->start(owner, phonebook, endpoints);
#else
    Q_UNUSED(owner); Q_UNUSED(phonebook); Q_UNUSED(endpoints);
    return false;
#endif
}
QString Router::ikev2DnsState(const QString &owner)
{
#ifdef Q_OS_WIN
    return RouterWin::Instance().ikev2Dns()->state(owner);
#else
    Q_UNUSED(owner);
    return "unsupported";
#endif
}
bool Router::stopIkev2Dns(const QString &owner)
{
#ifdef Q_OS_WIN
    return RouterWin::Instance().ikev2Dns()->stop(owner);
#else
    Q_UNUSED(owner);
    return false;
#endif
}
bool Router::prepareIkev2DnsRecovery()
{
#ifdef Q_OS_WIN
    return RouterWin::Instance().ikev2Dns()->prepareRecovery();
#else
    return true;
#endif
}
bool Router::finishIkev2DnsRecovery()
{
#ifdef Q_OS_WIN
    return RouterWin::Instance().ikev2Dns()->finishRecovery();
#else
    return true;
#endif
}
bool Router::nativeDnsAdmissionReady()
{
#ifdef Q_OS_WIN
    return RouterWin::Instance().ikev2Dns()->recoveryReady();
#else
    return true;
#endif
}
bool Router::nativeBackendOwnsLifecycle()
{
#ifdef Q_OS_WIN
    return RouterWin::Instance().ikev2Dns()->ownsNativeLifecycle()
        || WindowsDaemon::instance()->ownsNativeLifecycle();
#else
    return false;
#endif
}
bool Router::acknowledgeIkev2DnsStopped(const QString &owner)
{
#ifdef Q_OS_WIN
    return RouterWin::Instance().ikev2Dns()->acknowledgeStopped(owner);
#else
    Q_UNUSED(owner);
    return false;
#endif
}

bool Router::shutdownNativeResources()
{
#ifdef Q_OS_LINUX
    return RouterLinux::Instance().deleteTun("tun2"); // Does not remove unowned devices.
#elif defined(Q_OS_WIN)
    // LocalServer calls this only after startup DNS recovery, native DNS/RAS,
    // service-owned processes and Xray have all confirmed joined cleanup.
    if (!WindowsDaemon::instance()->deactivate(false)) return false;
    return KillSwitch::instance()->setNativeIpv6Blocked(false, {});
#else
    return true;
#endif
}
void Router::connectNativeDnsFailure(QObject *receiver,
                                    std::function<void(const QString &)> callback)
{
#ifdef Q_OS_WIN
    auto *utility = RouterWin::Instance().nativeDnsUtility();
#elif defined(Q_OS_MACOS)
    auto *utility = RouterMac::Instance().nativeDnsUtility();
#else
    auto *utility = RouterLinux::Instance().nativeDnsUtility();
#endif
    QObject::connect(utility, &DnsUtils::nativeDnsFailed, receiver, std::move(callback));
}

bool Router::StopRoutingIpv6()
{
#ifdef Q_OS_WIN
    return RouterWin::Instance().StopRoutingIpv6();
#elif defined (Q_OS_MAC)
    return true;// todo fixme
#elif defined Q_OS_LINUX
    return RouterLinux::Instance().StopRoutingIpv6();
#endif
}

bool Router::StartRoutingIpv6()
{
#ifdef Q_OS_WIN
    return RouterWin::Instance().StartRoutingIpv6();
#elif defined (Q_OS_MAC)
    return true;// todo fixme
#elif defined Q_OS_LINUX
    return RouterLinux::Instance().StartRoutingIpv6();
#endif
}
