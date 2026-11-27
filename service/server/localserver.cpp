#include "localserver.h"

#include <QCoreApplication>
#include <QDebug>
#include <QFileInfo>
#include <QLocalServer>
#include <QLocalSocket>
#include <QObject>
#include <QSharedPointer>
#include <QString>

#include "ipc.h"
#include "killswitch.h"
#include "logger.h"
#include "nativednsservice.h"
#include "daemon/dnsutils.h"
#include <QStandardPaths>
#include <QTimer>
#include "router.h"
#include "xray.h"
#ifdef Q_OS_LINUX
#include "desktoproutingprocess.h"
#endif

#ifdef Q_OS_WIN
    #include "tapcontroller_win.h"
#endif

namespace {
Logger logger("WgDaemonServer");
}

LocalServer::LocalServer(QObject *parent) : QObject(parent),
    m_ipcServer(this)
{
    // All entry points (SCM, launchd/systemd and console) construct LocalServer.
    // Recover durable DNS ownership before exposing a new IPC publisher.
#ifdef Q_OS_WIN
    // Re-establish pending RAS protection before restoring its published OS DNS.
    // Native hangup follows confirmed DNS/alias retirement, never precedes it.
    KillSwitch::instance()->init();
#endif
    const bool recovered = recoverStartupDns();
    m_ipcServer.setStartupDnsRecoveryReady(recovered);
    const bool dnsRecovered = m_startupDnsRestored;
    if (!recovered) qCritical("Native DNS recovery requires attention; new managed DNS is disabled");
    DnsUtils::setNativeDnsFactory([dnsRecovered]() -> std::unique_ptr<NativeDnsGuard> {
        return dnsRecovered && Router::nativeDnsAdmissionReady() ? createNativeDnsServiceGuard() : nullptr;
    });
    if (!recovered) return; // No publishers while durable native recovery is unresolved.
    // Create the server and listen outside of QtRO
    m_server = QSharedPointer<QLocalServer>(new QLocalServer(this));
    m_server->setSocketOptions(QLocalServer::WorldAccessOption);

    if (!m_server->listen(amnezia::getIpcServiceUrl())) {
        qDebug() << QString("Unable to start the server: %1.").arg(m_server->errorString());
        return;
    }

    QObject::connect(m_server.data(), &QLocalServer::newConnection, this, [this]() {
        qDebug() << "LocalServer new connection";
        m_serverNode.addHostSideConnection(m_server->nextPendingConnection());

        if (!m_isRemotingEnabled) {
            m_isRemotingEnabled = true;
            m_serverNode.enableRemoting(&m_ipcServer);
        }
    });

    // Init Mozilla Wireguard Daemon
    if (!server.initialize()) {
        logger.error() << "Failed to initialize the server";
        return;
    }

    m_networkWatcher.initialize();
    connect(&m_networkWatcher, &NetworkWatcher::networkChanged, &m_ipcServer, &IpcServer::networkChanged);
    connect(&m_networkWatcher, &NetworkWatcher::wakeup, &m_ipcServer, &IpcServer::wakeup);
#ifdef Q_OS_LINUX
    // The service-owned tunnel must receive hints even when no GUI is attached.
    // A GUI may forward the same signal; the native owner coalesces duplicates.
    auto *routing = DesktopRoutingProcess::instance();
    const auto hint = [routing] {
        routing->networkChanged(routing->status().value("runtime_id").toString());
    };
    connect(&m_networkWatcher, &NetworkWatcher::networkChanged, routing, hint);
    connect(&m_networkWatcher, &NetworkWatcher::wakeup, routing, hint);
#endif
#ifndef Q_OS_WIN
    KillSwitch::instance()->init();
#endif

#ifdef Q_OS_LINUX
    // Signal handling for a proper shutdown.
    QObject::connect(qApp, &QCoreApplication::aboutToQuit,
                     []() { LinuxDaemon::instance()->deactivate(); });
#endif

#ifdef Q_OS_MAC
    // Signal handling for a proper shutdown.
    QObject::connect(qApp, &QCoreApplication::aboutToQuit,
                     []() { MacOSDaemon::instance()->deactivate(); });
#endif

#ifdef Q_OS_WIN
    // Signal handling for a proper shutdown.
    QObject::connect(qApp, &QCoreApplication::aboutToQuit,
                     []() { WindowsDaemon::instance()->deactivate(); });
#endif
}

LocalServer::~LocalServer()
{
    qDebug() << "Local server stopped";
}

bool LocalServer::recoverStartupDns()
{
    if (m_startupDnsCompleted) return true;
    if (!m_startupDnsPrepared) {
        if (!Router::prepareIkev2DnsRecovery()) return false;
        m_startupDnsPrepared = true;
    }
    if (!m_startupDnsRestored) {
        const auto directory = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation) + "/native-dns";
        if (!recoverNativeDnsServiceOnStartup(directory)) return false;
        m_startupDnsRestored = true;
    }
    if (!Router::finishIkev2DnsRecovery()) return false;
#ifdef Q_OS_WIN
    // WindowsTunnelService construction can stop an orphaned WG worker and
    // remove its adapter. Restore the adapter's durable DNS owner FIRST.
    if (!daemon) daemon = std::make_unique<WindowsDaemon>();
#endif
    m_startupDnsCompleted = true;
    return true;
}

void LocalServer::requestShutdown()
{
    if (!m_shuttingDown) {
        m_shuttingDown = true;
        m_ipcServer.freezeForShutdown();
        if (m_server) m_server->close();
        m_serverNode.disableRemoting(&m_ipcServer);
    }
    // A newly constructed DnsUtils has no in-memory owner after a crash. Its
    // empty state is not evidence that durable startup recovery succeeded.
    if (!recoverStartupDns() || !Router::shutdownNativeDns()) {
        qWarning("Service shutdown waiting for confirmed native DNS restoration");
        QTimer::singleShot(250, this, &LocalServer::requestShutdown);
        return;
    }
    qInfo("Service shutdown: native DNS restoration confirmed");
    if (!m_ipcServer.shutdownNativeProcesses() || !Xray::getInstance().stopAny()
            || !Router::shutdownNativeResources()) {
        QTimer::singleShot(250, this, &LocalServer::requestShutdown);
        return;
    }
    qInfo("Service shutdown: native processes joined and owned resources retired");
    qApp->quit();
}
