#include <QCoreApplication>
#include <QFileInfo>
#include <QProcess>
#include <QRandomGenerator>
#include <QTcpServer>
#include <QTcpSocket>
#include <QNetworkInterface>
#include <QPointer>

#include "core/utils/networkUtilities.h"
#include "ipc.h"
#include "openVpnProtocol.h"
#include "core/utils/utilities.h"
#include "core/protocols/protocolUtils.h"
#include "version.h"

OpenVpnProtocol::OpenVpnProtocol(const QJsonObject &configuration, QObject *parent) : VpnProtocol(configuration, parent)
{
    readOpenVpnConfiguration(configuration);
    connect(&m_managementServer, &ManagementServer::readyRead, this,
            &OpenVpnProtocol::onReadyReadDataFromManagementServer);
}

OpenVpnProtocol::~OpenVpnProtocol()
{
    OpenVpnProtocol::stop();
    QThread::msleep(200);
}

void OpenVpnProtocol::addResolvedIpv6Hosts(const QStringList &hosts, bool throughVpn, std::function<void(bool)> done)
{
    if (!supportsIpv6HostUpdates() || !isConnected() || !m_openVpnProcess) { done(false); return; }
    const auto reply = m_openVpnProcess->addOpenVpnIpv6Hosts(vpnLocalAddress(), hosts, throughVpn);
    auto *watcher = new QRemoteObjectPendingCallWatcher(reply, this);
    connect(watcher, &QRemoteObjectPendingCallWatcher::finished, this,
        [done = std::move(done)](QRemoteObjectPendingCallWatcher *call) {
            const bool success = call->error() == QRemoteObjectPendingCall::NoError && call->returnValue().toBool();
            call->deleteLater();
            done(success);
        });
}

bool OpenVpnProtocol::supportsIpv6HostUpdates() const
{
#if (defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)) || defined(Q_OS_WIN) || (defined(Q_OS_MACOS) && !defined(MACOS_NE))
    return m_configData.value("ipv6_enabled").toBool(true)
        && m_configData.value(ProtocolUtils::key_proto_config_data(Proto::OpenVpn)).toObject().value("ipv6Tunnel").toBool();
#else
    return false;
#endif
}

QString OpenVpnProtocol::defaultConfigFileName()
{
    return defaultConfigPath() + QString("/%1.ovpn").arg(APPLICATION_NAME);
}

QString OpenVpnProtocol::defaultConfigPath()
{
    QString p = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/config";
    Utils::initializePath(p);

    return p;
}

void OpenVpnProtocol::cleanupResources()
{
    if (m_serviceManagement) {
        // The service keeps management, DNS and interface ownership even when
        // this GUI/replica disappears. close() requests checked stop; it is not
        // permission to kill the native process before resolver restoration.
        if (m_openVpnProcess) m_openVpnProcess->close();
        return;
    }
    if (m_openVpnProcess || openVpnProcessIsRunning()) {
        if (!sendTermSignal()) {
            killOpenVpnProcess();
        }
        QThread::msleep(10);
    }
    m_managementServer.stop();

#if defined(Q_OS_WIN) || defined(Q_OS_LINUX) || defined(Q_OS_MACOS)
    IpcClient::withInterface([](QSharedPointer<IpcInterfaceReplica> iface) {
        QRemoteObjectPendingReply<bool> reply = iface->disableKillSwitch();
        if (!reply.waitForFinished(1000) || !reply.returnValue()) {
            qWarning() << "OpenVpnProtocol::cleanupResources(): Failed to disable killswitch";
        }
    });
#endif
}

void OpenVpnProtocol::stop()
{
    if (guardStop()) {
        return;
    }

    qDebug() << "OpenVpnProtocol::stop()";

    const bool wasActive = m_connectionState == Vpn::ConnectionState::Preparing
            || m_connectionState == Vpn::ConnectionState::Connecting
            || m_connectionState == Vpn::ConnectionState::Connected
            || m_connectionState == Vpn::ConnectionState::Reconnecting;

    if (wasActive) {
        setConnectionState(Vpn::ConnectionState::Disconnecting);
    }

    cleanupResources();
    if (m_serviceManagement && m_managedConfigured && m_openVpnProcess) return;

    if (wasActive || m_connectionState == Vpn::ConnectionState::Disconnecting) {
        setConnectionState(Vpn::ConnectionState::Disconnected);
    }
}

ErrorCode OpenVpnProtocol::prepare()
{
    return IpcClient::withInterface([](QSharedPointer<IpcInterfaceReplica> iface) {
        QRemoteObjectPendingReply<QStringList> listReply = iface->getTapList();
        if (!listReply.waitForFinished(1000)) {
            return ErrorCode::InternalError;
        }

        QStringList list = listReply.returnValue();
        if (list.empty()) {
            QRemoteObjectPendingReply<bool> installReply = iface->checkAndInstallDriver();
            if (!installReply.waitForFinished() || !installReply.returnValue()) {
                return ErrorCode::OpenVpnTapAdapterError;
            }
        }

        return ErrorCode::NoError;
    }, [] () {
        return ErrorCode::AmneziaServiceConnectionFailed;
    });
}

void OpenVpnProtocol::killOpenVpnProcess()
{
    if (m_openVpnProcess) {
        m_openVpnProcess->close();
    }
}

void OpenVpnProtocol::readOpenVpnConfiguration(const QJsonObject &configuration)
{
    if (configuration.contains(ProtocolUtils::key_proto_config_data(Proto::OpenVpn))) {
        m_configData = configuration;
        QJsonObject jConfig = configuration.value(ProtocolUtils::key_proto_config_data(Proto::OpenVpn)).toObject();

        m_configFile.open();
        m_configFile.write(jConfig.value(configKey::config).toString().toUtf8());
        m_configFile.close();
        m_configFileName = m_configFile.fileName();
        qDebug().noquote() << QString("Set config data") << m_configFileName;
    }
}

bool OpenVpnProtocol::openVpnProcessIsRunning() const
{
    return Utils::processIsRunning("openvpn");
}

void OpenVpnProtocol::disconnectFromManagementServer()
{
    m_managementServer.stop();
}

QString OpenVpnProtocol::configPath() const
{
    return m_configFileName;
}

void OpenVpnProtocol::sendManagementCommand(const QString &command)
{
    if (m_serviceManagement) {
        if (m_openVpnProcess) m_openVpnProcess->managedOpenVpnCommand(command);
        return;
    }
    QIODevice *device = dynamic_cast<QIODevice *>(m_managementServer.socket().data());
    if (device) {
        QTextStream stream(device);
        stream << command << Qt::endl;
    }
}

uint OpenVpnProtocol::selectMgmtPort()
{
    for (int i = 0; i < 100; ++i) {
        quint32 port = QRandomGenerator::global()->generate();
        port = (double)(65000 - 15001) * port / UINT32_MAX + 15001;

        QTcpServer s;
        bool ok = s.listen(QHostAddress::LocalHost, port);
        if (ok)
            return port;
    }
    return m_managementPort;
}

void OpenVpnProtocol::updateRouteGateway(QString line)
{
    if (line.contains("net_route_v4_best_gw")) {
        QStringList params = line.split(" ");
        if (params.size() == 6) {
            m_routeGateway = params.at(3);
        }
    } else {
        line = line.split("ROUTE_GATEWAY", Qt::SkipEmptyParts).at(1);
        if (!line.contains("/"))
            return;
        m_routeGateway = line.split("/", Qt::SkipEmptyParts).first();
        m_routeGateway.replace(" ", "");
    }
    qDebug() << "Set VPN route gateway" << m_routeGateway;
}

ErrorCode OpenVpnProtocol::start()
{
    bool serviceManagement = false;
#if (defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)) || defined(Q_OS_WIN) || (defined(Q_OS_MACOS) && !defined(MACOS_NE))
    serviceManagement = !m_configData.value("ipv6_enabled").toBool(true);
#endif
    if (m_serviceManagement && m_openVpnProcess) {
        auto stopped = m_openVpnProcess->managedOpenVpnStopped();
        if (!stopped.waitForFinished(1000) || !stopped.returnValue())
            return ErrorCode::InternalError;
    }
    resetStopGuard();
    m_serverAssignedIpv6 = false;
    m_nativeEnvironment.reset();
    m_nativeUpEnvironment.clear();

    if (m_openVpnProcess || !serviceManagement) cleanupResources();
    m_openVpnProcess.reset();
    m_serviceManagement = serviceManagement;
    m_managedConfigured = false;
    m_managedLines.clear();
    const auto generation = ++m_processGeneration;

    if (!QFileInfo::exists(configPath())) {
        setLastError(ErrorCode::OpenVpnConfigMissing);
        return lastError();
    }

#ifdef AMNEZIA_DESKTOP
    const ErrorCode res = IpcClient::withInterface([&](QSharedPointer<IpcInterfaceReplica> iface) {
        QString ip = NetworkUtilities::getIPAddress(m_configData.value(amnezia::configKey::hostName).toString());
        QRemoteObjectPendingReply<bool> reply = iface->addKillSwitchAllowedRange(QStringList(ip));
        if (!reply.waitForFinished(1000) || !reply.returnValue()) {
            return ErrorCode::AmneziaServiceConnectionFailed;
        }
        return ErrorCode::NoError;
    });
    if (res != ErrorCode::NoError) {
        return res;
    }
#endif

    // Detect default gateway
#ifdef Q_OS_MAC
    QProcess p;
    p.setProcessChannelMode(QProcess::MergedChannels);

    p.start("route",
            QStringList() << "-n"
                          << "get"
                          << "default");
    p.waitForFinished();
    QString s = p.readAll();

    QRegularExpression rx(R"(gateway:\s*(\d+\.\d+\.\d+\.\d+))");
    QRegularExpressionMatch match = rx.match(s);
    if (match.hasMatch()) {
        m_routeGateway = match.captured(1);
        qDebug() << "Set VPN route gateway" << m_routeGateway;
    } else {
        qWarning() << "Unable to set VPN route gateway, output:\n" << s;
    }
#endif

#ifdef Q_OS_WIN
    // In "all except sites" mode the config uses redirect-gateway !ipv4, so OpenVPN
    // never reports net_route_v4_best_gw and m_routeGateway would stay empty
    const QString winGateway = NetworkUtilities::getGatewayAndIface().first;
    if (!winGateway.isEmpty()) {
        m_routeGateway = winGateway;
        qDebug() << "Set VPN route gateway" << m_routeGateway;
    } else {
        qWarning() << "Unable to detect physical default gateway";
    }
#endif

    uint mgmtPort = selectMgmtPort();
    qDebug() << "OpenVpnProtocol::start mgmt port selected:" << mgmtPort;

    if (!m_serviceManagement && !m_managementServer.start(m_managementHost, mgmtPort)) {
        setLastError(ErrorCode::OpenVpnManagementServerError);
        return lastError();
    }

    setConnectionState(Vpn::ConnectionState::Connecting);

    m_openVpnProcess = IpcClient::CreatePrivilegedProcess();

    if (!m_openVpnProcess) {
        setLastError(ErrorCode::AmneziaServiceConnectionFailed);
        return ErrorCode::AmneziaServiceConnectionFailed;
    }

    m_openVpnProcess->setProgram(PermittedProcess::OpenVPN);
    QStringList arguments({"--config", configPath()});
    if (!m_serviceManagement)
        arguments << "--management" << m_managementHost << QString::number(mgmtPort) << "--management-client";
    m_openVpnProcess->setArguments(arguments);
    const QPointer<IpcProcessInterfaceReplica> process(m_openVpnProcess.data());
    if (m_serviceManagement) {
        connect(process.data(), &IpcProcessInterfaceReplica::managedOpenVpnLine, this,
            [this, process, generation](const QString &line) {
                if (!process || process != m_openVpnProcess.data() || generation != m_processGeneration
                    || !m_managedConfigured) return;
                m_managedLines.append(line);
                onReadyReadDataFromManagementServer();
            });
        connect(process.data(), &IpcProcessInterfaceReplica::managedOpenVpnFailed, this,
            [this, process, generation] {
                if (process && process == m_openVpnProcess.data() && generation == m_processGeneration)
                    emit protocolError(ErrorCode::OpenVpnUnknownError);
            });
        auto configured = process->configureManagedOpenVpn();
        if (!configured.waitForFinished() || !configured.returnValue())
            return ErrorCode::AmneziaServiceConnectionFailed;
        m_managedConfigured = true;
    }

    qDebug() << arguments.join(" ");
    connect(m_openVpnProcess.data(), &IpcProcessInterfaceReplica::errorOccurred,
            [&](QProcess::ProcessError error) { qDebug() << "PrivilegedProcess errorOccurred" << error; });

    connect(m_openVpnProcess.data(), &IpcProcessInterfaceReplica::stateChanged,
            [&](QProcess::ProcessState newState) { qDebug() << "PrivilegedProcess stateChanged" << newState; });

    connect(m_openVpnProcess.data(), &IpcProcessInterfaceReplica::finished, this,
            [this, process, generation]() {
                if (!process || process != m_openVpnProcess.data() || generation != m_processGeneration) return;
                m_managedConfigured = false;
                if (m_serviceManagement) {
                    IpcClient::withInterface([](QSharedPointer<IpcInterfaceReplica> iface) {
                        auto reply = iface->disableKillSwitch();
                        if (!reply.waitForFinished(1000) || !reply.returnValue())
                            qWarning("Failed to disable OpenVPN killswitch after confirmed DNS/interface teardown");
                    });
                }
                setConnectionState(Vpn::ConnectionState::Disconnected);
            });

    m_openVpnProcess->start();

    return ErrorCode::NoError;
}

bool OpenVpnProtocol::sendTermSignal()
{
    if (m_serviceManagement && m_openVpnProcess) {
        auto reply = m_openVpnProcess->managedOpenVpnCommand("signal SIGTERM");
        return reply.waitForFinished(1000) && reply.returnValue();
    }
    return m_managementServer.writeCommand("signal SIGTERM");
}

void OpenVpnProtocol::sendByteCount()
{
    sendManagementCommand("bytecount 1");
}

void OpenVpnProtocol::sendInitialData()
{
    sendManagementCommand("state on");
    sendManagementCommand("log on");
}

void OpenVpnProtocol::onReadyReadDataFromManagementServer()
{
    for (;;) {
        if (m_serviceManagement && m_managedLines.isEmpty()) return;
        QString line = m_serviceManagement ? m_managedLines.takeFirst() : m_managementServer.readLine();
        while (line.endsWith('\n') || line.endsWith('\r'))
            line.chop(1);

        const auto environmentResult = m_nativeEnvironment.consume(line.toStdString());
        if (environmentResult != OpenVpnManagementEnvironment::Result::Ignored) {
            if (environmentResult == OpenVpnManagementEnvironment::Result::Invalid) {
                m_nativeUpEnvironment.clear();
                emit protocolError(ErrorCode::OpenVpnUnknownError);
                return;
            }
            if (environmentResult == OpenVpnManagementEnvironment::Result::Complete) {
                if (m_nativeEnvironment.isUp())
                    m_nativeUpEnvironment = m_nativeEnvironment.values();
                else
                    m_nativeUpEnvironment.clear();
            }
            // Do not leak complete native environments into the log, or treat
            // UP as proof of successful routes/DNS publication.
            continue;
        }
        line = line.simplified();

        if (line.isEmpty()) {
            return;
        }

        if (!line.contains(">BYTECOUNT")) {
            qDebug().noquote() << line;
        }

        if (line.contains(">INFO:OpenVPN Management Interface")) {
            sendInitialData();
        } else if (line.startsWith(">STATE")) {
            if (line.contains("CONNECTED,SUCCESS")) {
                sendByteCount();
                stopTimeoutTimer();
                setConnectionState(Vpn::ConnectionState::Connected);
                continue;
            } else if (line.contains("EXITING,SIGTER")) {
                // openVpnStateSigTermHandler();
                setConnectionState(Vpn::ConnectionState::Disconnecting);
                continue;
            } else if (line.contains("RECONNECTING")) {
                m_serverAssignedIpv6 = false;
                m_nativeEnvironment.reset();
                m_nativeUpEnvironment.clear();
                setConnectionState(Vpn::ConnectionState::Reconnecting);
                continue;
            }
        }

        if (line.contains("ROUTE_GATEWAY") || line.contains("net_route_v4_best_gw")) {
            updateRouteGateway(line);
        }

        if (line.contains("PUSH: Received control message")) {
            updateVpnGateway(line);
        }

        if (line.contains("FATAL")) {
            if (line.contains("tap-windows6 adapters on this system are currently in use or disabled")) {
                emit protocolError(ErrorCode::OpenVpnAdaptersInUseError);
            } else {
                emit protocolError(ErrorCode::OpenVpnUnknownError);
            }
            return;
        }

        QByteArray data(line.toStdString().c_str());
        if (data.contains(">BYTECOUNT:")) {
            int beg = data.lastIndexOf(">BYTECOUNT:");
            int end = data.indexOf("\n", beg);

            beg += sizeof(">BYTECOUNT:") - 1;
            QList<QByteArray> count = data.mid(beg, end - beg + 1).split(',');

            quint64 r = static_cast<quint64>(count.at(0).trimmed().toULongLong());
            quint64 s = static_cast<quint64>(count.at(1).trimmed().toULongLong());

            setBytesChanged(r, s);
        }
    }
}

void OpenVpnProtocol::updateVpnGateway(const QString &line)
{
    // line looks like
    // PUSH: Received control message: 'PUSH_REPLY,route 10.8.0.1,topology net30,ping 10,ping-restart
    // 120,ifconfig 10.8.0.6 10.8.0.5,peer-id 0,cipher AES-256-GCM'
    const auto payload = line.endsWith('\'') ? line.chopped(1) : line;
    const QStringList params = payload.split(",");
    for (const QString &l : params) {
        const auto fields = l.simplified().split(' ');
        if (fields.value(0) == QLatin1String("ifconfig-ipv6") && fields.size() == 3) {
            const auto subnet = QHostAddress::parseSubnet(fields[1]);
            const QHostAddress peer(fields[2]);
            m_serverAssignedIpv6 = subnet.first.protocol() == QAbstractSocket::IPv6Protocol
                && subnet.second > 0 && !subnet.first.isNull() && !subnet.first.isMulticast()
                && !subnet.first.isLoopback() && !subnet.first.isLinkLocal()
                && peer.protocol() == QAbstractSocket::IPv6Protocol && !peer.isNull()
                && !peer.isMulticast() && !peer.isLoopback() && !peer.isLinkLocal();
        }
        // ifconfig-ipv6 is a separate directive, never an IPv4 gateway update.
        if (fields.value(0) == QLatin1String("ifconfig")) {
            if (fields.size() == 3
                && QHostAddress(fields[1]).protocol() == QAbstractSocket::IPv4Protocol
                && QHostAddress(fields[2]).protocol() == QAbstractSocket::IPv4Protocol) {
                m_vpnLocalAddress = fields[1];
                m_vpnGateway = fields[2];
#ifdef Q_OS_WIN
                QThread::msleep(300);
                IpcClient::withInterface([&](QSharedPointer<IpcInterfaceReplica> iface) {
                    QList<QNetworkInterface> netInterfaces = QNetworkInterface::allInterfaces();
                    for (int i = 0; i < netInterfaces.size(); i++) {
                        for (int j=0; j < netInterfaces.at(i).addressEntries().size(); j++)
                        {
                            // killSwitch toggle
                            if (m_vpnLocalAddress == netInterfaces.at(i).addressEntries().at(j).ip().toString()) {
                                if (QVariant(m_configData.value(configKey::killSwitchOption).toString()).toBool()) {
                                    iface->enableKillSwitch(m_configData, netInterfaces.at(i).index());
                                }
                                m_configData.insert("vpnAdapterIndex", netInterfaces.at(i).index());
                                m_configData.insert("vpnGateway", m_vpnGateway);
                                m_configData.insert("vpnServer",
                                                    NetworkUtilities::getIPAddress(m_configData.value(amnezia::configKey::hostName).toString()));
                                iface->enablePeerTraffic(m_configData);
                            }
                        }
                    }
                });
#endif
#if defined(Q_OS_LINUX) || defined(Q_OS_MACOS)
                // killSwitch toggle
                if (QVariant(m_configData.value(configKey::killSwitchOption).toString()).toBool()) {
                    m_configData.insert("vpnServer",
                                        NetworkUtilities::getIPAddress(m_configData.value(amnezia::configKey::hostName).toString()));
                    IpcClient::withInterface([&](QSharedPointer<IpcInterfaceReplica> iface) {
                        QRemoteObjectPendingReply<bool> reply = iface->enableKillSwitch(m_configData, 0);
                        if (!reply.waitForFinished(1000) || !reply.returnValue()) {
                            qWarning() << "OpenVpnProtocol::updateVpnGateway(): Failed to enable killswitch";
                        }
                    });
                }
#endif
                qDebug() << QString("Set vpn local address %1, gw %2").arg(m_vpnLocalAddress).arg(vpnGateway());
            }
        }
    }
}
