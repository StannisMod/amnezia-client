#include "ipcserver.h"

#include <QDateTime>
#include <QDebug>
#include <QFileInfo>
#include <QHostAddress>
#include <QJsonObject>
#include <QLocalServer>
#include <QLocalSocket>
#include <QObject>
#include <QRemoteObjectHost>
#include <QRemoteObjectNode>
#include <QString>
#include <QStringList>

#include "logger.h"
#include "router.h"
#include "killswitch.h"
#include "xray.h"

#ifdef Q_OS_WIN
    #include "tapcontroller_win.h"
#endif


IpcServer::IpcServer(QObject *parent) : IpcInterfaceSource(parent)
{
    connect(&m_pingHelper, &PingHelper::connectionLose, this, &IpcServer::connectionLose);
    Router::connectNativeDnsFailure(this, [this](const QString &owner) { emit nativeDnsFailed(owner); });
}

int IpcServer::createPrivilegedProcess()
{
    if (m_shuttingDown) return -1;
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::createPrivilegedProcess";
#endif

    m_localpid++;

    ProcessDescriptor pd(this);

    pd.localServer->setSocketOptions(QLocalServer::WorldAccessOption);

    if (!pd.localServer->listen(amnezia::getIpcProcessUrl(m_localpid))) {
        qDebug() << QString("Unable to start the server: %1.").arg(pd.localServer->errorString());
        return -1;
    }

    // Register this source once. Reattaching replicas share the service-owned
    // source; registering it again reports a duplicate QtRO root source.
    // Make sure any connections are handed to QtRO
    QObject::connect(pd.localServer.data(), &QLocalServer::newConnection, this,
                     [pd, remotingEnabled = QSharedPointer<bool>::create(false)]() {
        qDebug() << "IpcServer new connection";
        if (pd.serverNode) {
            pd.serverNode->addHostSideConnection(pd.localServer->nextPendingConnection());
            if (!*remotingEnabled)
                *remotingEnabled = pd.serverNode->enableRemoting(pd.ipcProcess.data());
        }
    });

    QObject::connect(pd.serverNode.data(), &QRemoteObjectHost::error, this,
                     [pd](QRemoteObjectNode::ErrorCode errorCode) { qDebug() << "QRemoteObjectHost::error" << errorCode; });

    QObject::connect(pd.serverNode.data(), &QRemoteObjectHost::destroyed, this, [pd]() { qDebug() << "QRemoteObjectHost::destroyed"; });

    m_processes.insert(m_localpid, pd);

    return m_localpid;
}

void IpcServer::freezeForShutdown()
{
    m_shuttingDown = true;
    for (const auto &descriptor : m_processes) descriptor.ipcProcess->freezeForShutdown();
}

bool IpcServer::shutdownNativeProcesses()
{
    bool stopped = true;
    for (const auto &descriptor : m_processes) {
        if (!descriptor.ipcProcess->processStopped()) {
            descriptor.ipcProcess->terminate();
            stopped = false; // Native management remains live until joined.
        }
    }
    return stopped;
}

int IpcServer::routeAddList(const QString &gw, const QStringList &ips)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::routeAddList";
#endif

    return Router::routeAddList(gw, ips);
}

bool IpcServer::clearSavedRoutes()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::clearSavedRoutes";
#endif

    return Router::clearSavedRoutes();
}

bool IpcServer::routeDeleteList(const QString &gw, const QStringList &ips)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::routeDeleteList";
#endif

    return Router::routeDeleteList(gw, ips);
}

bool IpcServer::flushDns()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::flushDns";
#endif

    return Router::flushDns();
}

void IpcServer::resetIpStack()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::resetIpStack";
#endif

    Router::resetIpStack();
}

bool IpcServer::checkAndInstallDriver()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::checkAndInstallDriver";
#endif

#ifdef Q_OS_WIN
    return TapController::checkAndSetup();
#else
    return true;
#endif
}

QStringList IpcServer::getTapList()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::getTapList";
#endif

#ifdef Q_OS_WIN
    return TapController::getTapList();
#else
    return QStringList();
#endif
}

void IpcServer::cleanUp()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::cleanUp";
#endif

    Logger::deInit();
    Logger::cleanUp();
}

void IpcServer::clearLogs()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::clearLogs";
#endif

    Logger::clearLogs(true);
}

bool IpcServer::configureProxyIpv6(const QStringList &included, const QStringList &excluded)
{
    return Router::configureProxyIpv6(included, excluded);
}

bool IpcServer::createTun(const QString &dev, const QString &subnet)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::createTun";
#endif

    return Router::createTun(dev, subnet);
}

bool IpcServer::deleteTun(const QString &dev)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::deleteTun";
#endif

    return Router::deleteTun(dev);
}

bool IpcServer::updateResolvers(const QString &ifname, const QList<QHostAddress> &resolvers)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::updateResolvers";
#endif

    return Router::updateResolvers(ifname, resolvers);
}

bool IpcServer::restoreResolvers()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::restoreResolvers";
#endif

    return Router::restoreResolvers();
}

bool IpcServer::updateResolversWithPolicy(const QString &ifname, const QList<QHostAddress> &resolvers,
                                         bool ipv6Enabled, const QString &owner)
{
    // A generation identifier, not an authentication token.
    if (owner.isEmpty() || owner.size() > 128 || owner.contains(QChar(0))) return false;
    return Router::updateResolvers(ifname, resolvers, ipv6Enabled, owner);
}

bool IpcServer::restoreResolversWithOwner(const QString &owner)
{
    if (owner.isEmpty() || owner.size() > 128 || owner.contains(QChar(0))) return false;
    return Router::restoreResolvers(owner);
}

bool IpcServer::startIkev2Dns(const QString &owner, const QByteArray &phonebook, const QStringList &endpoints)
{
    return !m_shuttingDown && Router::startIkev2Dns(owner, phonebook, endpoints);
}
QString IpcServer::ikev2DnsState(const QString &owner) { return Router::ikev2DnsState(owner); }
bool IpcServer::stopIkev2Dns(const QString &owner) { return Router::stopIkev2Dns(owner); }
bool IpcServer::acknowledgeIkev2DnsStopped(const QString &owner)
{
    return Router::acknowledgeIkev2DnsStopped(owner);
}

bool IpcServer::StartRoutingIpv6()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::StartRoutingIpv6";
#endif

    return Router::StartRoutingIpv6();
}

bool IpcServer::StopRoutingIpv6()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::StopRoutingIpv6";
#endif

    return Router::StopRoutingIpv6();
}

bool IpcServer::setNativeIpv6Blocked(bool blocked, QStringList endpoints)
{
    if (!m_startupDnsRecoveryReady) return false;
#ifdef Q_OS_WIN
    if (Router::nativeBackendOwnsLifecycle()) return false;
#endif
#if defined(Q_OS_WIN) || defined(Q_OS_MACOS)
    return KillSwitch::instance()->setNativeIpv6Blocked(blocked, endpoints);
#else
    Q_UNUSED(blocked)
    Q_UNUSED(endpoints)
    return false;
#endif
}

void IpcServer::setLogsEnabled(bool enabled)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::setLogsEnabled";
#endif

    if (enabled) {
        Logger::init(true);
    } else {
        Logger::deInit();
    }
}

bool IpcServer::startNetworkCheck(const QString& serverIpv4Gateway, const QString& deviceIpv4Address)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::startNetworkCheck";
#endif

    m_pingHelper.start(serverIpv4Gateway, deviceIpv4Address);
    return true;
}

bool IpcServer::stopNetworkCheck()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::stopNetworkCheck";
#endif

    m_pingHelper.stop();
    return true;
}

bool IpcServer::resetKillSwitchAllowedRange(QStringList ranges)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::resetKillSwitchAllowedRange";
#endif

    return KillSwitch::instance()->resetAllowedRange(ranges);
}

bool IpcServer::addKillSwitchAllowedRange(QStringList ranges)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::addKillSwitchAllowedRange";
#endif

    return KillSwitch::instance()->addAllowedRange(ranges);
}

bool IpcServer::disableAllTraffic()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::disableAllTraffic";
#endif

    return KillSwitch::instance()->disableAllTraffic();
}

bool IpcServer::enableKillSwitch(const QJsonObject &configStr, int vpnAdapterIndex)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::enableKillSwitch";
#endif

    return KillSwitch::instance()->enableKillSwitch(configStr, vpnAdapterIndex);
}

bool IpcServer::disableKillSwitch()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::disableKillSwitch";
#endif

    return KillSwitch::instance()->disableKillSwitch();
}

bool IpcServer::enablePeerTraffic(const QJsonObject &configStr)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::enablePeerTraffic";
#endif

    return KillSwitch::instance()->enablePeerTraffic(configStr);
}

bool IpcServer::refreshKillSwitch(bool enabled)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::refreshKillSwitch";
#endif

    return KillSwitch::instance()->refresh(enabled);
}

bool IpcServer::xrayStart(const QString& cfg)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::xrayStart";
#endif

    return Xray::getInstance().start(cfg) != 0;
}

bool IpcServer::xrayStop()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::xrayStop";
#endif

    return Xray::getInstance().stopAny();
}

qint64 IpcServer::xrayStartOwned(const QString& cfg)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::xrayStartOwned";
#endif

    return Xray::getInstance().start(cfg);
}

bool IpcServer::xrayStopOwned(qint64 token)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::xrayStopOwned";
#endif

    return Xray::getInstance().stop(token);
}

qint64 IpcServer::xrayCurrentToken()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::xrayCurrentToken";
#endif

    return Xray::getInstance().currentToken();
}
