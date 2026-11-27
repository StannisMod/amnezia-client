#include "xrayProtocol.h"

#include "core/models/protocols/xrayProtocolConfig.h"
#include "core/protocols/protocolUtils.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/constants/protocolConstants.h"
#include "core/utils/ipcClient.h"
#include "core/utils/networkUtilities.h"
#include "core/utils/serialization/serialization.h"
#include "ipc.h"

#include <QCryptographicHash>
#include <QJsonDocument>
#include <QTimer>
#include <QEventLoop>
#include <QUuid>
#include <QPointer>
#include <QJsonObject>
#include <QJsonArray>
#include <QNetworkInterface>
#include <QtCore/qlogging.h>
#include <QtCore/qobjectdefs.h>
#include <QtCore/qprocess.h>

#include <exception>

#ifdef Q_OS_MACOS
static const QString tunName = "utun22";
#else
static const QString tunName = "tun2";
#endif

XrayProtocol::XrayProtocol(const QJsonObject &configuration, QObject *parent) : VpnProtocol(configuration, parent)
{
    m_vpnGateway = amnezia::protocols::xray::defaultLocalAddr;
    m_vpnLocalAddress = amnezia::protocols::xray::defaultLocalAddr;
    m_routeGateway = NetworkUtilities::getGatewayAndIface().first;

    m_routeMode = static_cast<amnezia::RouteMode>(configuration.value(amnezia::configKey::splitTunnelType).toInt());
    m_remoteAddress = NetworkUtilities::getIPAddress(m_rawConfig.value(amnezia::configKey::hostName).toString());

    const QString primaryDns = configuration.value(amnezia::configKey::dns1).toString();
    m_dnsServers.push_back(QHostAddress(primaryDns));
    if (primaryDns != amnezia::protocols::dns::amneziaDnsIp) {
        const QString secondaryDns = configuration.value(amnezia::configKey::dns2).toString();
        m_dnsServers.push_back(QHostAddress(secondaryDns));
    }

    QJsonObject xrayConfiguration = configuration.value(ProtocolUtils::key_proto_config_data(Proto::Xray)).toObject();
    if (xrayConfiguration.isEmpty()) {
        xrayConfiguration = configuration.value(ProtocolUtils::key_proto_config_data(Proto::SSXray)).toObject();
    }

    if (xrayConfiguration.isEmpty()) {
        qWarning() << "Xray config wrapper is empty";
        m_xrayConfig = {};
    }

    m_xrayConfig = QJsonDocument::fromJson(xrayConfiguration.value(amnezia::configKey::config).toString().toUtf8()).object();
    if (m_xrayConfig.isEmpty()) {
        qWarning() << "Xray config string is not a valid JSON object";
        m_xrayConfig = {};
    }
}

XrayProtocol::~XrayProtocol()
{
    qDebug() << "XrayProtocol::~XrayProtocol()";
    m_destroying = true;
    XrayProtocol::stop();
    // Like the native service's restore barrier, destruction is not permission
    // to discard uncertain DNS ownership. Keep the owner alive for retries.
    while (!m_stopSequence.complete()) {
        QEventLoop wait;
        QTimer::singleShot(250, &wait, &QEventLoop::quit);
        wait.exec();
        XrayProtocol::stop();
    }
}

ErrorCode XrayProtocol::start()
{
    if (m_destroying || m_stopRetryScheduled || !m_dnsOwner.isEmpty()
        || m_xrayToken != 0 || m_tun2socksProcess) return ErrorCode::InternalError;
    m_stopSequence.reset();
    resetStopGuard();
    m_dnsOwner = QUuid::createUuid().toString(QUuid::WithoutBraces);
    m_dnsAttempted = false;
    m_ipv6PolicyEnabled = m_rawConfig.value("ipv6_enabled").toBool(true);

    qDebug() << "XrayProtocol::start()";

    // Inject SOCKS5 auth into the inbound before starting xray.
    // Re-uses existing credentials if the config already has them (e.g. imported config).
    amnezia::serialization::inbounds::InboundCredentials creds;
    try {
        creds = amnezia::serialization::inbounds::EnsureInboundAuth(m_xrayConfig);
    } catch (const std::exception &e) {
        qCritical() << "EnsureInboundAuth failed:" << e.what();
        return ErrorCode::InternalError;
    }
    m_socksUser = creds.username;
    m_socksPassword = creds.password;
    m_socksPort = creds.port;

    QString xrayConfigStr = QJsonDocument(m_xrayConfig).toJson(QJsonDocument::Compact);
    if (xrayConfigStr.isEmpty()) {
        qCritical() << "Xray config is empty";
        return ErrorCode::XrayExecutableCrashed;
    }

    xrayConfigStr = amnezia::sanitizeNativeConfig(xrayConfigStr);

    return IpcClient::withInterface(
            [&](QSharedPointer<IpcInterfaceReplica> iface) {
                QObject::disconnect(m_dnsFailureConnection);
                const auto owner = m_dnsOwner;
                m_dnsFailureConnection = connect(iface.data(), &IpcInterfaceReplica::nativeDnsFailed,
                    this, [this, owner](const QString &failedOwner) {
                        if (owner.isEmpty() || owner != m_dnsOwner || failedOwner != owner) return;
                        stop();
                        setLastError(ErrorCode::InternalError);
                    });
                auto xrayStart = iface->xrayStartOwned(xrayConfigStr);
                if (!xrayStart.waitForFinished() || xrayStart.returnValue() == 0) {
                    qCritical() << "Failed to start xray";
                    return ErrorCode::XrayExecutableCrashed;
                }
                m_xrayToken = xrayStart.returnValue();
                return startTun2Socks();
            },
            []() { return ErrorCode::AmneziaServiceConnectionFailed; });
}

void XrayProtocol::stop()
{
    if (guardStop()) {
        return;
    }

    qDebug() << "XrayProtocol::stop()";
    ++m_tunGeneration;
    m_routingApplied = false;
    const bool complete = IpcClient::withInterface([this](QSharedPointer<IpcInterfaceReplica> iface) {
        return m_stopSequence.run({{
            [this, iface] {
                if (!m_dnsAttempted) return true;
                if (m_dnsOwner.isEmpty()) return false;
                auto restored = iface->restoreResolversWithOwner(m_dnsOwner);
                if (!restored.waitForFinished() || !restored.returnValue()) return false;
                m_dnsAttempted = false;
                return true;
            },
            [this] {
                if (!m_tun2socksProcess) return true;
                m_tun2socksProcess->blockSignals(true);
                const auto confirmedStopped = [this] {
                    auto stopped = m_tun2socksProcess->processStopped();
                    return stopped.waitForFinished() && stopped.returnValue();
                };
                if (confirmedStopped()) {
                    m_tun2socksProcess->close();
                    m_tun2socksProcess.reset();
                    return true;
                }
#ifndef Q_OS_WIN
                m_tun2socksProcess->terminate();
                auto graceful = m_tun2socksProcess->waitForFinished(1000);
                const bool stopped = graceful.waitForFinished() && graceful.returnValue();
                if (!stopped) m_tun2socksProcess->kill();
#else
                const bool stopped = false;
                m_tun2socksProcess->kill();
#endif
                if (!stopped) {
                    auto joined = m_tun2socksProcess->waitForFinished(1000);
                    const bool joinedReply = joined.waitForFinished() && joined.returnValue();
                    if (!joinedReply && !confirmedStopped()) return false;
                }
                m_tun2socksProcess->close();
                m_tun2socksProcess.reset();
                return true;
            },
            [this, iface] {
                if (!m_tunPrepared) return true;
                auto removed = iface->deleteTun(tunName);
                if (!removed.waitForFinished() || !removed.returnValue()) return false;
                m_tunPrepared = false;
                return true;
            },
            [this, iface] {
                if (!m_xrayToken) return true;
                auto stopped = iface->xrayStopOwned(m_xrayToken);
                if (!stopped.waitForFinished() || !stopped.returnValue()) return false;
                m_xrayToken = 0;
                return true;
            },
            [this, iface] {
                if (m_dnsOwner.isEmpty()) return true;
                auto disabled = iface->disableKillSwitch();
                return disabled.waitForFinished() && disabled.returnValue();
            }
        }});
    }, [this] {
        // An unused object owns nothing and needs no service-side cleanup.
        if (!m_dnsOwner.isEmpty() || m_xrayToken || m_tunPrepared || m_tun2socksProcess) return false;
        return m_stopSequence.run({{[] { return true; }, [] { return true; },
            [] { return true; }, [] { return true; }, [] { return true; }}});
    });
    if (!complete) {
        qWarning() << "Xray cleanup unconfirmed; retaining owner/resources for retry";
        resetStopGuard();
        if (!m_destroying && !m_stopRetryScheduled) {
            m_stopRetryScheduled = true;
            QTimer::singleShot(250, this, [this] {
                m_stopRetryScheduled = false;
                stop();
            });
        }
        return;
    }
    m_dnsOwner.clear();
    QObject::disconnect(m_dnsFailureConnection);
    setConnectionState(Vpn::ConnectionState::Disconnected);
}

ErrorCode XrayProtocol::startTun2Socks()
{
    const auto owner = m_dnsOwner;
    if (owner.isEmpty()) return ErrorCode::InternalError;
    const auto generation = ++m_tunGeneration;
    m_routingApplied = false;
    if (m_tun2socksProcess) {
        m_tun2socksProcess->blockSignals(true);
        m_tun2socksProcess->close();
        m_tun2socksProcess.reset();
    }
    m_tun2socksProcess = IpcClient::CreatePrivilegedProcess();
    const QPointer<IpcProcessInterfaceReplica> process(m_tun2socksProcess.data());
    if (!m_tun2socksProcess->waitForSource()) {
        return ErrorCode::AmneziaServiceConnectionFailed;
    }

#ifdef Q_OS_LINUX
    // tun2socks opens the device before emitting STACK readiness. Establish
    // service ownership first; createTun must never adopt an arbitrary tun2.
    if (!m_tunPrepared) {
        const auto result = IpcClient::withInterface(
                [this](QSharedPointer<IpcInterfaceReplica> iface) -> ErrorCode {
                    auto created = iface->createTun(tunName, amnezia::protocols::xray::defaultLocalAddr);
                    if (!created.waitForFinished() || !created.returnValue()) {
                        auto cleanup = iface->deleteTun(tunName);
                        cleanup.waitForFinished();
                        return ErrorCode::InternalError;
                    }
                    m_tunPrepared = true;
                    return ErrorCode::NoError;
                }, []() { return ErrorCode::AmneziaServiceConnectionFailed; });
        if (result != ErrorCode::NoError) return result;
    }
#endif

    const QString proxyUrl = QString("socks5://%1:%2@127.0.0.1:%3").arg(m_socksUser, m_socksPassword, QString::number(m_socksPort));

    m_tun2socksProcess->setProgram(PermittedProcess::Tun2Socks);
    m_tun2socksProcess->setArguments({ "-device", QString("tun://%1").arg(tunName), "-proxy", proxyUrl });

    connect(
            m_tun2socksProcess.data(), &IpcProcessInterfaceReplica::readyReadStandardError, this, 
            [this, process, generation, owner]() {
                if (!process || process != m_tun2socksProcess.data() ||
                    generation != m_tunGeneration || owner != m_dnsOwner) return;
                auto readAllStandardError = process->readAllStandardError();
                if (!readAllStandardError.waitForFinished()) {
                    qWarning() << "Failed to read output from tun2socks";
                    return;
                }

                const QString line = readAllStandardError.returnValue();
                if (!process || process != m_tun2socksProcess.data() ||
                    generation != m_tunGeneration || owner != m_dnsOwner) return;

                if (!line.contains("[TCP]") && !line.contains("[UDP]"))
                    qDebug() << "[tun2socks]:" << line;

                if (!m_routingApplied && line.contains("[STACK] tun://") && line.contains("<-> socks5://")) {
                    m_routingApplied = true;
                    disconnect(m_tun2socksProcess.data(), &IpcProcessInterfaceReplica::readyReadStandardOutput, this, nullptr);

                    const auto res = setupRouting(generation, owner);
                    if (generation != m_tunGeneration || owner != m_dnsOwner) return;
                    if (res != ErrorCode::NoError) {
                        stop();
                        setLastError(res);
                    } else {
                        setConnectionState(Vpn::ConnectionState::Connected);
                    }
                }
            },
            Qt::QueuedConnection);

    connect(
            m_tun2socksProcess.data(), &IpcProcessInterfaceReplica::finished, this,
            [this, process, generation, owner](int exitCode, QProcess::ExitStatus exitStatus) {
                if (!process || process != m_tun2socksProcess.data() ||
                    generation != m_tunGeneration || owner != m_dnsOwner) return;
                // Check stdout for "resource busy" — the TUN device was not yet released
                // by the previous tun2socks instance. Retry after a short delay.
                bool resourceBusy = false;
                if (m_tun2socksProcess) {
                    auto readOut = m_tun2socksProcess->readAllStandardOutput();
                    if (readOut.waitForFinished()) {
                        resourceBusy = readOut.returnValue().contains("resource busy");
                    }
                }

                if (generation != m_tunGeneration || owner != m_dnsOwner) return;
                if (resourceBusy && m_tun2socksRetryCount < maxTun2SocksRetries) {
                    m_tun2socksRetryCount++;
                    qWarning() << QString("Tun2socks: TUN resource busy, retrying (%1/%2) in %3ms...")
                                      .arg(m_tun2socksRetryCount)
                                      .arg(maxTun2SocksRetries)
                                      .arg(tun2socksRetryDelayMs);
                    QTimer::singleShot(tun2socksRetryDelayMs, this, [this, generation, owner]() {
                        if (generation != m_tunGeneration || owner != m_dnsOwner) return;
                        if (ErrorCode err = startTun2Socks(); err != ErrorCode::NoError) {
                            stop();
                            setLastError(err);
                        }
                    });
                    return;
                }

                m_tun2socksRetryCount = 0;

                if (exitStatus == QProcess::ExitStatus::CrashExit) {
                    qCritical() << "Tun2socks process crashed!";
                } else {
                    qCritical() << QString("Tun2socks process was closed with %1 exit code").arg(exitCode);
                }
                stop();
                setLastError(ErrorCode::Tun2SockExecutableCrashed);
            },
            Qt::QueuedConnection);

    m_tun2socksProcess->start();
    return ErrorCode::NoError;
}

ErrorCode XrayProtocol::setupRouting(quint64 generation, const QString &owner)
{
    return IpcClient::withInterface(
            [this, generation, owner](QSharedPointer<IpcInterfaceReplica> iface) -> ErrorCode {
                const auto current = [&] { return !owner.isEmpty() && owner == m_dnsOwner
                    && generation == m_tunGeneration; };
                if (!current()) return ErrorCode::InternalError;
#ifdef Q_OS_WIN
                const int inetAdapterIndex = NetworkUtilities::AdapterIndexTo(QHostAddress(m_remoteAddress));
#endif
#ifdef Q_OS_LINUX
                if (!m_tunPrepared) return ErrorCode::InternalError;
#else
                auto createTun = iface->createTun(tunName, amnezia::protocols::xray::defaultLocalAddr);
                if (!createTun.waitForFinished() || !createTun.returnValue()) {
                    qCritical() << "Failed to assign IP address for TUN";
                    return ErrorCode::InternalError;
                }
#endif

                const auto publishDns = [&]() -> bool {
                    if (!current()) return false;
                    m_dnsAttempted = true;
                    auto update = iface->updateResolversWithPolicy(
                        tunName, m_dnsServers, m_ipv6PolicyEnabled, owner);
                    return update.waitForFinished() && update.returnValue() && current();
                };
                if (m_ipv6PolicyEnabled && !publishDns()) return ErrorCode::InternalError;

#ifdef Q_OS_WIN
                int vpnAdapterIndex = -1;
                QList<QNetworkInterface> netInterfaces = QNetworkInterface::allInterfaces();
                for (auto &netInterface : netInterfaces) {
                    for (auto &address : netInterface.addressEntries()) {
                        if (m_vpnLocalAddress == address.ip().toString())
                            vpnAdapterIndex = netInterface.index();
                    }
                }
#else
                static const int vpnAdapterIndex = 0;
#endif
                const bool killSwitchEnabled = QVariant(m_rawConfig.value(configKey::killSwitchOption).toString()).toBool();
                if (killSwitchEnabled) {
                    if (vpnAdapterIndex != -1) {
                        QJsonObject config = m_rawConfig;
                        config.insert("vpnServer", m_remoteAddress);
#if (defined(Q_OS_LINUX) || defined(Q_OS_MACOS) || defined(Q_OS_WIN)) && !defined(Q_OS_ANDROID)
                        config.insert("proxyIpv6", true);
#endif

                        auto enableKillSwitch = IpcClient::Interface()->enableKillSwitch(config, vpnAdapterIndex);
                        if (!enableKillSwitch.waitForFinished() || !enableKillSwitch.returnValue()) {
                            qCritical() << "Failed to enable killswitch";
                            return ErrorCode::InternalError;
                        }
                    } else
                        qWarning() << "Failed to get vpnAdapterIndex. Killswitch disabled";
                }

                if (m_routeMode == amnezia::RouteMode::VpnAllSites) {
                    static const QStringList subnets = { "1.0.0.0/8",  "2.0.0.0/7",  "4.0.0.0/6",  "8.0.0.0/5",
                                                         "16.0.0.0/4", "32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/1" };

                    auto routeAddList = iface->routeAddList(m_vpnGateway, subnets);
                    if (!routeAddList.waitForFinished() || routeAddList.returnValue() != subnets.count()) {
                        qCritical() << "Failed to set routes for TUN";
                        return ErrorCode::InternalError;
                    }
                }

#if (defined(Q_OS_LINUX) || defined(Q_OS_MACOS) || defined(Q_OS_WIN)) && !defined(Q_OS_ANDROID)
                QStringList includedIpv6, excludedIpv6;
                const bool ipv6Enabled = m_ipv6PolicyEnabled;
                if (!ipv6Enabled || m_routeMode != amnezia::RouteMode::VpnOnlyForwardSites) includedIpv6 << "::/0";
                const auto sites = m_rawConfig.value(configKey::splitTunnelSites).toArray();
                for (const auto &site : sites) {
                    const auto subnet = QHostAddress::parseSubnet(site.toString());
                    if (subnet.first.protocol() != QAbstractSocket::IPv6Protocol) continue;
                    if (!ipv6Enabled) continue; // OFF must not create native IPv6 exclusions.
                    if (m_routeMode == amnezia::RouteMode::VpnOnlyForwardSites) includedIpv6 << site.toString();
                    else if (m_routeMode == amnezia::RouteMode::VpnAllExceptSites) excludedIpv6 << site.toString();
                }
                const QHostAddress endpoint(m_remoteAddress);
                if (endpoint.protocol() == QAbstractSocket::IPv6Protocol) excludedIpv6 << endpoint.toString() + "/128";
                auto ipv6 = iface->configureProxyIpv6(includedIpv6, excludedIpv6);
                if (!ipv6.waitForFinished() || !ipv6.returnValue()) return ErrorCode::InternalError;
#else
                auto StopRoutingIpv6 = iface->StopRoutingIpv6();
                if (!StopRoutingIpv6.waitForFinished() || !StopRoutingIpv6.returnValue()) {
                    qCritical() << "Failed to disable IPv6 routing";
                    return ErrorCode::InternalError;
                }
#endif

#ifdef Q_OS_WIN
                if (inetAdapterIndex != -1 && vpnAdapterIndex != -1) {
                    QJsonObject config = m_rawConfig;
                    config.insert("inetAdapterIndex", inetAdapterIndex);
                    config.insert("vpnAdapterIndex", vpnAdapterIndex);
                    config.insert("vpnGateway", m_vpnGateway);
                    config.insert("vpnServer", m_remoteAddress);

                    auto enablePeerTraffic = iface->enablePeerTraffic(config);
                    if (!enablePeerTraffic.waitForFinished() || !enablePeerTraffic.returnValue()) {
                        qCritical() << "Failed to enable peer traffic";
                        return ErrorCode::InternalError;
                    }
                } else
                    qWarning() << "Failed to get adapter indexes. Split-tunneling disabled";
#endif
                // OFF must plan from the final native split routes and prepare
                // the DNS-only listeners before any managed settings are visible.
                if (!m_ipv6PolicyEnabled && !publishDns()) return ErrorCode::InternalError;
                return ErrorCode::NoError;
            },
            []() { return ErrorCode::AmneziaServiceConnectionFailed; });
}
