#include "vpnConnection.h"

#include <QDebug>
#include <QEventLoop>
#include <QFile>
#include <QHostInfo>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>
#include <QObject>
#include <QSharedPointer>
#include <QPointer>
#include <utility>
#include <QString>
#include <QStringList>
#include <QTimer>

#include <core/configurators/openVpnConfigurator.h>
#include <core/configurators/wireguardConfigurator.h>

#ifdef AMNEZIA_DESKTOP
    #include <core/protocols/openVpnProtocol.h>
    #include "core/utils/ipcClient.h"
    #include <core/protocols/wireGuardProtocol.h>
    #include <QRemoteObjectPendingCallWatcher>
#endif

#ifdef Q_OS_ANDROID
    #include "platforms/android/android_controller.h"
    #include <QThread>

#endif

#if defined(Q_OS_IOS) || defined(MACOS_NE)
    #include "platforms/ios/ios_controller.h"
#endif

#include "core/utils/networkUtilities.h"
#include "core/utils/domainRoutingConfig.h"
#include "core/utils/serverConfigUtils.h"
#include "vpnConnection.h"
#include "core/utils/splitDnsConfig.h"

using namespace ProtocolUtils;

VpnConnection::VpnConnection(SecureServersRepository* serversRepository, SecureAppSettingsRepository* appSettingsRepository, QObject *parent)
    : QObject(parent),
      m_serversRepository(serversRepository),
      m_appSettingsRepository(appSettingsRepository),
      m_checkTimer(this),
      m_ipv6SiteRefreshTimer(this),
      m_connectionState(Vpn::ConnectionState::Disconnected)
{
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
    m_ipv6SiteRefreshTimer.setObjectName("ipv6SiteRefresh");
    m_ipv6SiteRefreshTimer.setInterval(30000);
    connect(&m_ipv6SiteRefreshTimer, &QTimer::timeout, this, &VpnConnection::refreshIpv6Sites);
#endif
    connect(this, &VpnConnection::connectionStateChanged, this, [this](Vpn::ConnectionState state) {
        if (state != Vpn::ConnectionState::Connected) {
            m_ipv6SiteRefreshTimer.stop();
            ++m_siteLookupGeneration;
            m_siteLookupPending = false;
            for (int id : std::exchange(m_siteLookupIds, {})) QHostInfo::abortHostLookup(id);
        }
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
        else if (m_vpnProtocol && m_vpnProtocol->supportsIpv6HostUpdates()) m_ipv6SiteRefreshTimer.start();
#endif
    });
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    m_checkTimer.setInterval(1000);
    connect(IosController::Instance(), &IosController::connectionStateChanged, this, &VpnConnection::setConnectionState);
    connect(IosController::Instance(), &IosController::bytesChanged, this, &VpnConnection::onBytesChanged);
#endif
}

VpnConnection::~VpnConnection()
{
    ++m_siteLookupGeneration;
    m_ipv6SiteRefreshTimer.stop();
    for (int id : std::exchange(m_siteLookupIds, {})) QHostInfo::abortHostLookup(id);
    if (m_vpnProtocol) {
        m_vpnProtocol->stop(); // Keep the normal route/resolver rollback signals.
        m_vpnProtocol->disconnect(this);
    }
    // A protocol destructor can wait for IPC; release it while our members
    // still exist and any queued DNS callbacks have already been invalidated.
    m_vpnProtocol.clear();
}

void VpnConnection::onBytesChanged(quint64 receivedBytes, quint64 sentBytes)
{
    emit bytesChanged(receivedBytes, sentBytes);
}

void VpnConnection::onKillSwitchModeChanged(bool enabled)
{
#ifdef AMNEZIA_DESKTOP
    IpcClient::withInterface([enabled](QSharedPointer<IpcInterfaceReplica> iface){
        QRemoteObjectPendingReply<bool> reply = iface->refreshKillSwitch(enabled);
        if (reply.waitForFinished() && reply.returnValue())
            qDebug() << "VpnConnection::onKillSwitchModeChanged: Killswitch refreshed";
        else
            qWarning() << "VpnConnection::onKillSwitchModeChanged: Failed to execute remote refreshKillSwitch call";
    });
#endif
}

void VpnConnection::onConnectionStateChanged(Vpn::ConnectionState state)
{
#ifdef AMNEZIA_DESKTOP
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
    // The routed child owns DNS and every tracked OS entry, including rollback.
    // Legacy GUI cleanup must not reset that state or a replacement owner.
    if (m_vpnConfiguration.contains("sing_box_routing")) return;
#endif
    if (auto *wireguard = qobject_cast<WireguardProtocol *>(m_vpnProtocol.data());
            wireguard && (wireguard->usesRoutedBackend() || wireguard->runtimeWasReplaced())) return;
    if (!m_serversRepository || !m_appSettingsRepository) {
        qCritical() << "VpnConnection::onConnectionStateChanged: repositories not initialized";
        return;
    }

    const QString defaultServerId = m_serversRepository->defaultServerId();
    DockerContainer container = DockerContainer::None;
    switch (m_serversRepository->serverKind(defaultServerId)) {
    case serverConfigUtils::ConfigType::SelfHostedAdmin: {
        const auto cfg = m_serversRepository->selfHostedAdminConfig(defaultServerId);
        if (cfg.has_value()) {
            container = cfg->defaultContainer;
        }
        break;
    }
    case serverConfigUtils::ConfigType::SelfHostedUser: {
        const auto cfg = m_serversRepository->selfHostedUserConfig(defaultServerId);
        if (cfg.has_value()) {
            container = cfg->defaultContainer;
        }
        break;
    }
    case serverConfigUtils::ConfigType::Native: {
        const auto cfg = m_serversRepository->nativeConfig(defaultServerId);
        if (cfg.has_value()) {
            container = cfg->defaultContainer;
        }
        break;
    }
    case serverConfigUtils::ConfigType::AmneziaPremiumV2:
    case serverConfigUtils::ConfigType::AmneziaFreeV3:
    case serverConfigUtils::ConfigType::ExternalPremium: {
        const auto cfg = m_serversRepository->apiV2Config(defaultServerId);
        if (cfg.has_value()) {
            container = cfg->defaultContainer;
        }
        break;
    }
    case serverConfigUtils::ConfigType::AmneziaPremiumV1:
    case serverConfigUtils::ConfigType::AmneziaFreeV2:
        break;
    case serverConfigUtils::ConfigType::Invalid:
    default:
        break;
    }

    IpcClient::withInterface([&](QSharedPointer<IpcInterfaceReplica> iface) {
        switch (state) {
            case Vpn::ConnectionState::Connected: {
                iface->resetIpStack();

                auto flushDns = iface->flushDns();
                if (flushDns.waitForFinished() && flushDns.returnValue())
                    qDebug() << "VpnConnection::onConnectionStateChanged: Successfully flushed DNS";
                else
                    qWarning() << "VpnConnection::onConnectionStateChanged: Failed to flush DNS";

                if (!ContainerUtils::isAwgContainer(container) && container != DockerContainer::WireGuard) {
                    QString dns1 = m_vpnConfiguration.value(configKey::dns1).toString();
                    QString dns2 = m_vpnConfiguration.value(configKey::dns2).toString();

#ifdef Q_OS_MACOS
                    if (!m_appSettingsRepository->isSitesSplitTunnelingEnabled() || m_appSettingsRepository->routeMode() != amnezia::RouteMode::VpnAllExceptSites) {
                        iface->routeAddList(m_vpnProtocol->vpnGateway(), QStringList() << dns1 << dns2);
                    }
#else
                    iface->routeAddList(m_vpnProtocol->vpnGateway(), QStringList() << dns1 << dns2);
#endif

                    if (m_appSettingsRepository->isSitesSplitTunnelingEnabled()) {
                        iface->routeDeleteList(m_vpnProtocol->vpnGateway(), QStringList() << "0.0.0.0");
                        RouteMode routeMode = m_appSettingsRepository->routeMode();
                        if (routeMode == amnezia::RouteMode::VpnOnlyForwardSites) {
                            QTimer::singleShot(1000, m_vpnProtocol.data(),
                                               [this, routeMode]() { addSitesRoutes(m_vpnProtocol->vpnGateway(), routeMode); });
                        } else if (routeMode == amnezia::RouteMode::VpnAllExceptSites) {
                            iface->routeAddList(m_vpnProtocol->vpnGateway(), QStringList() << "0.0.0.0/1");
                            iface->routeAddList(m_vpnProtocol->vpnGateway(), QStringList() << "128.0.0.0/1");

                            iface->routeAddList(m_vpnProtocol->routeGateway(), QStringList() << remoteAddress());
#ifdef Q_OS_MACOS
                            iface->routeAddList(m_vpnProtocol->routeGateway(), QStringList() << dns1 << dns2);
#endif
                            addSitesRoutes(m_vpnProtocol->routeGateway(), routeMode);
                        }
                    }
                }
            } break;
            case Vpn::ConnectionState::Disconnected:
            case Vpn::ConnectionState::Error: {
                auto flushDns = iface->flushDns();
                if (flushDns.waitForFinished() && flushDns.returnValue())
                    qDebug() << "VpnConnection::onConnectionStateChanged: Successfully flushed DNS";
                else
                    qWarning() << "VpnConnection::onConnectionStateChanged: Failed to flush DNS";

                auto clearSavedRoutes = iface->clearSavedRoutes();
                if (clearSavedRoutes.waitForFinished() && clearSavedRoutes.returnValue())
                    qDebug() << "VpnConnection::onConnectionStateChanged: Successfully cleared saved routes";
                else
                    qWarning() << "VpnConnection::onConnectionStateChanged: Failed to clear saved routes";
            } break;
            default:
                break;
        }
    });
#endif

#if defined(Q_OS_IOS) || defined(MACOS_NE)
    if (state == Vpn::ConnectionState::Connected ||
        state == Vpn::ConnectionState::Connecting ||
        state == Vpn::ConnectionState::Reconnecting) {
        m_checkTimer.start();
    } else {
        m_checkTimer.stop();
    }
#endif
}

const QString &VpnConnection::remoteAddress() const
{
    return m_remoteAddress;
}

void VpnConnection::setRepositories(SecureServersRepository* serversRepository, SecureAppSettingsRepository* appSettingsRepository)
{
    m_serversRepository = serversRepository;
    m_appSettingsRepository = appSettingsRepository;
}

int VpnConnection::lookupSiteAddresses(const QString &site, std::function<void(const QHostInfo &)> done)
{
    return QHostInfo::lookupHost(site, this, std::move(done));
}

void VpnConnection::refreshIpv6Sites()
{
#ifdef AMNEZIA_DESKTOP
    if (m_connectionState != Vpn::ConnectionState::Connected || !m_vpnProtocol
        || !m_vpnProtocol->isConnected() || !m_vpnProtocol->supportsIpv6HostUpdates()
        || !m_appSettingsRepository || !m_appSettingsRepository->isSitesSplitTunnelingEnabled()) return;
    const auto mode = m_appSettingsRepository->routeMode();
    if (mode != RouteMode::VpnOnlyForwardSites && mode != RouteMode::VpnAllExceptSites) return;
    addSitesRoutes({}, mode, true);
#endif
}

void VpnConnection::addSitesRoutes(const QString &gw, amnezia::RouteMode mode, bool ipv6Only)
{
#ifdef AMNEZIA_DESKTOP
    if (!m_appSettingsRepository) {
        qCritical() << "VpnConnection::addSitesRoutes: repositories not initialized";
        return;
    }

    if (m_siteLookupPending) return;
    m_siteLookupPending = true;
    const auto generation = ++m_siteLookupGeneration;
    QTimer::singleShot(20000, this, [this, generation] {
        if (generation != m_siteLookupGeneration || !m_siteLookupPending) return;
        ++m_siteLookupGeneration;
        m_siteLookupPending = false;
        for (int id : std::exchange(m_siteLookupIds, {})) QHostInfo::abortHostLookup(id);
    });
    QStringList ips;
    QStringList sites;
    const QVariantMap &m = m_appSettingsRepository->vpnSites(mode);
    for (auto i = m.constBegin(); i != m.constEnd(); ++i) {
        if (NetworkUtilities::checkIpSubnetFormat(i.key())) {
            ips.append(i.key());
        } else {
            const QStringList siteIps = SecureAppSettingsRepository::siteIpList(i.value());
            for (const QString &ip : siteIps) {
                if (NetworkUtilities::checkIpSubnetFormat(ip)) {
                    ips.append(ip);
                }
            }
            sites.append(i.key());
        }
    }
    ips.removeDuplicates();
    const auto knownIps = ips;
    // These legacy IPC helpers install IPv4 routes. IPv6 capture is configured
    // by the protocol; keep IPv6 rules in the shared profile/site list.
    ips.removeIf([](const QString &value) {
        return QHostAddress::parseSubnet(value).first.protocol() != QAbstractSocket::IPv4Protocol;
    });


    if (!ipv6Only) IpcClient::withInterface([&](QSharedPointer<IpcInterfaceReplica> iface) {
        iface->routeAddList(gw, ips);
    });
    if (sites.isEmpty()) { m_siteLookupPending = false; return; }

    auto remainingLookups = QSharedPointer<int>::create(sites.size());
    auto needFlush = QSharedPointer<bool>::create(false);

    const QPointer<VpnProtocol> protocol(m_vpnProtocol.data());
    const QPointer<VpnConnection> self(this);
    // Each answer belongs to this connection and policy, never a later session.
    for (const QString &site : sites) {
        const auto cbResolv = [self, protocol, site, gw, mode, knownIps, remainingLookups, needFlush, generation, ipv6Only](const QHostInfo &hostInfo) {
            const auto release = [self, generation, remainingLookups] {
                if (!self || self->m_siteLookupGeneration != generation) return false;
                if (--(*remainingLookups) != 0) return false;
                self->m_siteLookupPending = false;
                self->m_siteLookupIds.clear();
                return true;
            };
            const auto current = [self, protocol, mode, site, generation] {
                return self && self->m_siteLookupGeneration == generation && protocol
                    && self->m_vpnProtocol.data() == protocol.data() && protocol->isConnected()
                    && self->m_appSettingsRepository && self->m_appSettingsRepository->isSitesSplitTunnelingEnabled()
                    && self->m_appSettingsRepository->routeMode() == mode
                    && self->m_appSettingsRepository->vpnSites(mode).contains(site);
            };
            if (!current()) { release(); return; }
            QStringList ipv4, ipv6;
            for (const auto &address : hostInfo.addresses()) {
                if (knownIps.contains(address.toString())) continue;
                if (!ipv6Only && address.protocol() == QAbstractSocket::IPv4Protocol) ipv4 << address.toString();
                else if (address.protocol() == QAbstractSocket::IPv6Protocol && address.scopeId().isEmpty()
                         && !address.isLinkLocal() && !address.isMulticast() && !address.isLoopback()) ipv6 << address.toString();
            }
            ipv4.removeDuplicates(); ipv6.removeDuplicates();
            if (!ipv4.isEmpty()) IpcClient::withInterface([&](QSharedPointer<IpcInterfaceReplica> iface) { iface->routeAddList(gw, ipv4); });
            const auto finish = [self, current, release, site, mode, ipv4, ipv6, needFlush](bool installedIpv6) {
                if (!current()) { release(); return; }
                auto added = ipv4;
                if (installedIpv6) added << ipv6;
                else if (!ipv6.isEmpty()) qWarning() << "IPv6 domain routes were not installed" << site;
                if (!added.isEmpty()) {
                    self->m_appSettingsRepository->addVpnSite(mode, site, added);
                    *needFlush = true;
                }
                if (!release() || !*needFlush) return;
                IpcClient::withInterface([self](QSharedPointer<IpcInterfaceReplica> iface) {
                    auto *watcher = new QRemoteObjectPendingCallWatcher(iface->flushDns(), self);
                    QObject::connect(watcher, &QRemoteObjectPendingCallWatcher::finished, self,
                        [](QRemoteObjectPendingCallWatcher *call) {
                            if (call->error() != QRemoteObjectPendingCall::NoError || !call->returnValue().toBool())
                                qWarning() << "VpnConnection::addSitesRoutes: Failed to flush DNS";
                            call->deleteLater();
                        });
                });
            };
            if (ipv6.isEmpty()) finish(true);
            else protocol->addResolvedIpv6Hosts(ipv6, mode == RouteMode::VpnOnlyForwardSites, finish);
        };
        const int id = lookupSiteAddresses(site, cbResolv);
        if (id >= 0) m_siteLookupIds.append(id);
    }
#endif
}

QSharedPointer<VpnProtocol> VpnConnection::vpnProtocol() const
{
    return m_vpnProtocol;
}

void VpnConnection::disconnectSlots()
{
    if (m_vpnProtocol) {
        m_vpnProtocol->disconnect();
    }
}

ErrorCode VpnConnection::lastError() const
{
#ifdef Q_OS_ANDROID
    return ErrorCode::AndroidError;
#endif

    if (m_vpnProtocol.isNull()) {
        return ErrorCode::InternalError;
    }

    return m_vpnProtocol.data()->lastError();
}

Vpn::ConnectionState VpnConnection::connectionState() const
{
    return m_connectionState;
}

void VpnConnection::connectToVpn(const QString &serverId, DockerContainer container, const QJsonObject &vpnConfiguration)
{
    if (!m_appSettingsRepository || !m_serversRepository) {
        qCritical() << "VpnConnection::connectToVpn: repositories not initialized";
        setConnectionState(Vpn::ConnectionState::Error);
        return;
    }

    qDebug() << QString("Trying to connect to VPN, server id is %1, container is %2, route mode is")
                        .arg(serverId)
                        .arg(ContainerUtils::containerToString(container))
             << m_appSettingsRepository->routeMode();

#if defined(Q_OS_WIN) || (defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID))
    // These desktop app modes require the flow engine. Never silently start a
    // legacy backend that cannot enforce the saved application scope.
    const bool routedSession = m_appSettingsRepository->isSingBoxRoutingEnabled()
        && ProtocolUtils::supportsDomainRouting(ProtocolUtils::protoFromString(vpnConfiguration.value(configKey::vpnProto).toString()));
    if (m_appSettingsRepository->isAppsSplitTunnelingEnabled() && !routedSession
        && !m_appSettingsRepository->vpnApps(m_appSettingsRepository->appsRouteMode()).isEmpty()
        && (m_appSettingsRepository->appsRouteMode() == AppsRouteMode::VpnOnlyForwardApps
#ifndef Q_OS_WIN
            || m_appSettingsRepository->appsRouteMode() != AppsRouteMode::VpnAllApps
#endif
            )) {
        setConnectionState(Vpn::ConnectionState::Error);
        emit vpnProtocolError(ErrorCode::NotSupportedOnThisPlatform);
        return;
    }
#endif

    const Proto transport = ProtocolUtils::protoFromString(vpnConfiguration.value(configKey::vpnProto).toString());
    // AWG/WireGuard owns asynchronous endpoint resolution before activation.
    // remoteAddress is used below only by the non-WireGuard legacy route path.
    m_remoteAddress = (transport == Proto::Awg || transport == Proto::WireGuard)
        ? vpnConfiguration.value(configKey::hostName).toString()
        : NetworkUtilities::getIPAddress(vpnConfiguration.value(configKey::hostName).toString());
    setConnectionState(Vpn::ConnectionState::Connecting);

    m_vpnConfiguration = vpnConfiguration;

#ifdef AMNEZIA_DESKTOP
    if (m_vpnProtocol) {
        disconnect(m_vpnProtocol.data(), &VpnProtocol::protocolError, this, &VpnConnection::vpnProtocolError);
        m_vpnProtocol->stop();
        m_vpnProtocol.reset();
    }
    appendKillSwitchConfig();
#endif

    appendSplitTunnelingConfig();

#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS) && !defined(MACOS_NE)
    m_vpnProtocol.reset(VpnProtocol::factory(container, m_vpnConfiguration));
    if (!m_vpnProtocol) {
        setConnectionState(Vpn::ConnectionState::Error);
        return;
    }
    m_vpnProtocol->prepare();
#elif defined Q_OS_ANDROID
    androidVpnProtocol = createDefaultAndroidVpnProtocol();
    createAndroidConnections();

    m_vpnProtocol.reset(androidVpnProtocol);
#elif defined Q_OS_IOS || defined(MACOS_NE)
    Proto proto = ContainerUtils::defaultProtocol(container);
    IosController::Instance()->connectVpn(proto, m_vpnConfiguration);
    connect(&m_checkTimer, &QTimer::timeout, IosController::Instance(), &IosController::checkStatus);
    return;
#endif

    createProtocolConnections();

#ifdef AMNEZIA_DESKTOP
    if (auto *openvpn = qobject_cast<OpenVpnProtocol *>(m_vpnProtocol.data()); openvpn && container == DockerContainer::OpenVpn) {
        const auto expected = m_serversRepository->serverJsonById(serverId);
        if (expected) {
            connect(openvpn, &VpnProtocol::connectionStateChanged, this,
                [this, openvpn, serverId, expected = *expected](Vpn::ConnectionState state) {
                    if (m_vpnProtocol.data() == openvpn && state == Vpn::ConnectionState::Connected
                        && openvpn->serverAssignedIpv6()) rememberOpenVpnIpv6Capability(serverId, expected);
                });
        }
    }
#endif

    if (ErrorCode err = m_vpnProtocol->start(); err != ErrorCode::NoError) {
        setConnectionState(Vpn::ConnectionState::Error);
        emit vpnProtocolError(err);
    }
}

void VpnConnection::rememberOpenVpnIpv6Capability(const QString &serverId, const QJsonObject &expected)
{
    if (!m_serversRepository || m_serversRepository->serverJsonById(serverId) != std::optional<QJsonObject>(expected)) return;
    const auto kind = m_serversRepository->serverKind(serverId);
    switch (kind) {
    case serverConfigUtils::ConfigType::SelfHostedAdmin:
    case serverConfigUtils::ConfigType::SelfHostedUser:
    case serverConfigUtils::ConfigType::Native:
    case serverConfigUtils::ConfigType::AmneziaPremiumV2:
    case serverConfigUtils::ConfigType::AmneziaFreeV3:
    case serverConfigUtils::ConfigType::ExternalPremium: break;
    default: return;
    }
    // Preserve opaque provider/legacy fields: changing a local observation
    // must not round-trip the whole record through a narrower typed model.
    auto containers = expected.value(configKey::containers).toArray();
    int index = -1;
    for (int i = 0; i < containers.size(); ++i) {
        if (containers[i].toObject().value(configKey::container).toString()
            != ContainerUtils::containerToString(DockerContainer::OpenVpn)) continue;
        if (index != -1) return; // Ambiguous duplicate owner.
        index = i;
    }
    if (index == -1) return;
    auto container = containers[index].toObject();
    const auto protocolName = ProtocolUtils::protoToString(Proto::OpenVpn);
    auto protocol = container.value(protocolName).toObject();
    const auto document = QJsonDocument::fromJson(protocol.value(configKey::lastConfig).toString().toUtf8());
    if (!document.isObject()) return;
    auto client = document.object();
    if (!client.value(configKey::config).isString() || client.value("ipv6Tunnel").toBool()) return;
    client.insert("ipv6Tunnel", true);
    protocol.insert(configKey::lastConfig, QString::fromUtf8(QJsonDocument(client).toJson(QJsonDocument::Compact)));
    container.insert(protocolName, protocol);
    containers[index] = container;
    auto updated = expected;
    updated.insert(configKey::containers, containers);
    // Learn only for the next connection, without notifying transport restart
    // observers (including an unrelated local proxy owned by this record).
    m_serversRepository->editServer(serverId, updated, kind, SecureServersRepository::EditEffect::ObservedCapability);
}

void VpnConnection::createProtocolConnections()
{
    connect(m_vpnProtocol.data(), &VpnProtocol::protocolError, this, &VpnConnection::vpnProtocolError);
    connect(m_vpnProtocol.data(), &VpnProtocol::connectionStateChanged, this, &VpnConnection::setConnectionState);
    connect(m_vpnProtocol.data(), SIGNAL(bytesChanged(quint64, quint64)), this, SLOT(onBytesChanged(quint64, quint64)));

#ifdef AMNEZIA_DESKTOP
    IpcClient::withInterface([this](QSharedPointer<IpcInterfaceReplica> rep) {
        connect(rep.data(), &IpcInterfaceReplica::networkChanged, this, &VpnConnection::reconnectToVpn, Qt::QueuedConnection);
        connect(rep.data(), &IpcInterfaceReplica::wakeup, this, &VpnConnection::reconnectToVpn, Qt::QueuedConnection);
    });
#endif
}

void VpnConnection::appendKillSwitchConfig()
{
    if (!m_appSettingsRepository) {
        qCritical() << "VpnConnection::appendKillSwitchConfig: repositories not initialized";
        return;
    }

    m_vpnConfiguration.insert(configKey::killSwitchOption, QVariant(m_appSettingsRepository->isKillSwitchEnabled()).toString());
    m_vpnConfiguration.insert(configKey::allowedDnsServers, QVariant(m_appSettingsRepository->getAllowedDnsServers()).toJsonValue());
}

void VpnConnection::appendSplitTunnelingConfig()
{
    if (!m_appSettingsRepository) {
        qCritical() << "VpnConnection::appendSplitTunnelingConfig: repositories not initialized";
        return;
    }

    bool allowSiteBasedSplitTunneling = true;

    // this block is for old native configs and for old self-hosted configs
    auto protocolName = m_vpnConfiguration.value(configKey::vpnProto).toString();
    if (protocolName == ProtocolUtils::protoToString(Proto::Awg) || protocolName == ProtocolUtils::protoToString(Proto::WireGuard)) {
        allowSiteBasedSplitTunneling = false;
        auto configData = m_vpnConfiguration.value(protocolName + "_config_data").toObject();
        if (configData.value(configKey::allowedIps).isString()) {
            QJsonArray allowedIpsJsonArray = QJsonArray::fromStringList(configData.value(configKey::allowedIps).toString().split(", "));
            configData.insert(configKey::allowedIps, allowedIpsJsonArray);
            m_vpnConfiguration.insert(protocolName + "_config_data", configData);
        } else if (configData.value(configKey::allowedIps).isUndefined()) {
            auto nativeConfig = configData.value(configKey::config).toString();
            auto nativeConfigLines = nativeConfig.split("\n");
            for (auto &line : nativeConfigLines) {
                auto allowedIpsString = line.split("=", Qt::KeepEmptyParts);
                if (allowedIpsString.size() >= 2 && allowedIpsString.first().trimmed() == QStringLiteral("AllowedIPs")) {
                    QJsonArray allowedIpsJsonArray;
                    const QString allowedIps = allowedIpsString.mid(1).join(QStringLiteral("=")).trimmed();
                    for (const QString &allowedIp : allowedIps.split(",", Qt::SkipEmptyParts)) {
                        allowedIpsJsonArray.append(allowedIp.trimmed());
                    }
                    configData.insert(configKey::allowedIps, allowedIpsJsonArray);
                    m_vpnConfiguration.insert(protocolName + "_config_data", configData);
                    break;
                }
            }
        }

        if (configData.value(configKey::persistentKeepAlive).isUndefined()) {
            auto nativeConfig = configData.value(configKey::config).toString();
            auto nativeConfigLines = nativeConfig.split("\n");
            for (auto &line : nativeConfigLines) {
                auto persistentKeepaliveString = line.split("=", Qt::KeepEmptyParts);
                if (persistentKeepaliveString.size() >= 2
                        && persistentKeepaliveString.first().trimmed() == QStringLiteral("PersistentKeepalive")) {
                    configData.insert(configKey::persistentKeepAlive,
                                      persistentKeepaliveString.mid(1).join(QStringLiteral("=")).trimmed());
                    m_vpnConfiguration.insert(protocolName + "_config_data", configData);
                    break;
                }
            }
        }

        QJsonArray allowedIpsJsonArray = configData.value(configKey::allowedIps).toArray();
        if (allowedIpsJsonArray.contains("0.0.0.0/0") && allowedIpsJsonArray.contains("::/0")) {
            allowSiteBasedSplitTunneling = true;
        }
    }

    amnezia::RouteMode routeMode = amnezia::RouteMode::VpnAllSites;
    QJsonArray sitesJsonArray;
    if (m_appSettingsRepository->isSitesSplitTunnelingEnabled()) {
        routeMode = m_appSettingsRepository->routeMode();

        if (allowSiteBasedSplitTunneling) {
            QStringList sites;
            const QVariantMap &m = m_appSettingsRepository->vpnSites(routeMode);
            for (auto i = m.constBegin(); i != m.constEnd(); ++i) {
                if (NetworkUtilities::checkIpSubnetFormat(i.key())) {
                    sites.append(i.key());
                } else {
                    const QStringList siteIps = SecureAppSettingsRepository::siteIpList(i.value());
                    for (const QString &ip : siteIps) {
                        if (NetworkUtilities::checkIpSubnetFormat(ip)) {
                            sites.append(ip);
                        }
                    }
                }
            }
            sites.removeDuplicates();
            for (const auto &site : sites) {
                sitesJsonArray.append(site);
            }

            if (sitesJsonArray.isEmpty()) {
                routeMode = amnezia::RouteMode::VpnAllSites;
            } else if (routeMode == amnezia::RouteMode::VpnOnlyForwardSites) {
                // Allow traffic to Amnezia DNS
                sitesJsonArray.append(m_vpnConfiguration.value(configKey::dns1).toString());
                sitesJsonArray.append(m_vpnConfiguration.value(configKey::dns2).toString());
            }
        }
    }

    m_vpnConfiguration.insert(configKey::splitTunnelType, routeMode);
    m_vpnConfiguration.insert(configKey::splitTunnelSites, sitesJsonArray);

#if defined(Q_OS_ANDROID) || defined(Q_OS_IOS) || defined(Q_OS_LINUX) || defined(Q_OS_WIN) || (defined(Q_OS_MACOS) && defined(MACOS_NE))
    if ((m_appSettingsRepository->isSingBoxRoutingEnabled() || !m_appSettingsRepository->isIpv6Enabled())
            && ProtocolUtils::supportsDomainRouting(ProtocolUtils::protoFromString(protocolName))) {
        m_vpnConfiguration.insert("sing_box_routing", m_appSettingsRepository->isSitesSplitTunnelingEnabled()
            ? m_appSettingsRepository->domainRoutingConfig()
            : QJsonObject{{"version", 1}, {"default", "vpn"}, {"rules", QJsonArray()}});
        m_vpnConfiguration.insert("sing_box_dns_path", "vpn");
        // Derive every routed session from the effective Amnezia DNS choice.
        // Saved per-domain DNS overrides must never bypass the site's route.
        m_vpnConfiguration.insert("sing_box_dns", amnezia::dns::forSiteRoutes(
            m_vpnConfiguration.value("sing_box_routing").toObject(),
            m_vpnConfiguration.value(configKey::dns1).toString()));
        // Only the flow engine applies destinations. The OS captures all flows
        // selected by the existing per-application VPN scope.
        m_vpnConfiguration.insert(configKey::splitTunnelType, amnezia::RouteMode::VpnAllSites);
        m_vpnConfiguration.insert(configKey::splitTunnelSites, QJsonArray());
    } else {
        m_vpnConfiguration.remove("sing_box_routing");
        m_vpnConfiguration.remove("sing_box_dns_path");
        m_vpnConfiguration.remove("sing_box_dns");
    }
#endif

    amnezia::AppsRouteMode appsRouteMode = amnezia::AppsRouteMode::VpnAllApps;
    QJsonArray appsJsonArray;
    if (m_appSettingsRepository->isAppsSplitTunnelingEnabled()) {
        appsRouteMode = m_appSettingsRepository->appsRouteMode();

        auto apps = m_appSettingsRepository->vpnApps(appsRouteMode);
        for (const auto &app : apps) {
            appsJsonArray.append(app.appPath.isEmpty() ? app.packageName : app.appPath);
        }

        if (appsJsonArray.isEmpty()) {
            appsRouteMode = amnezia::AppsRouteMode::VpnAllApps;
        }
    }

    m_vpnConfiguration.insert(configKey::appSplitTunnelType, appsRouteMode);
    m_vpnConfiguration.insert(configKey::splitTunnelApps, appsJsonArray);
#ifdef Q_OS_ANDROID
    m_vpnConfiguration.remove("android_app_routing");
    if (appsRouteMode == amnezia::AppsRouteMode::VpnOnlyForwardApps
        && (protocolName == ProtocolUtils::protoToString(Proto::Awg)
            || protocolName == ProtocolUtils::protoToString(Proto::WireGuard))) {
        const auto appPolicy = m_appSettingsRepository->androidAppRoutingPolicy();
        if (!appPolicy.isEmpty()) m_vpnConfiguration.insert("android_app_routing", appPolicy);
    }
#endif

    qDebug() << QString("Site split tunneling is %1, route mode is %2")
                        .arg(m_appSettingsRepository->isSitesSplitTunnelingEnabled() ? "enabled" : "disabled")
                        .arg(routeMode);
    qDebug() << QString("App split tunneling is %1, route mode is %2")
                        .arg(m_appSettingsRepository->isAppsSplitTunnelingEnabled() ? "enabled" : "disabled")
                        .arg(appsRouteMode);
}

#ifdef Q_OS_ANDROID
void VpnConnection::restoreConnection()
{
    createAndroidConnections();

    m_vpnProtocol.reset(androidVpnProtocol);

    createProtocolConnections();
}

void VpnConnection::createAndroidConnections()
{
    androidVpnProtocol = createDefaultAndroidVpnProtocol();

    connect(AndroidController::instance(), &AndroidController::connectionStateChanged, androidVpnProtocol,
            &AndroidVpnProtocol::setConnectionState);
    connect(AndroidController::instance(), &AndroidController::statisticsUpdated, androidVpnProtocol, &AndroidVpnProtocol::setBytesChanged);
}

AndroidVpnProtocol *VpnConnection::createDefaultAndroidVpnProtocol()
{
    return new AndroidVpnProtocol(m_vpnConfiguration);
}
#endif

QString VpnConnection::bytesPerSecToText(quint64 bytes)
{
    double mbps = bytes * 8 / 1e6;
    return QString("%1 %2").arg(QString::number(mbps, 'f', 2)).arg(tr("Mbps")); // Mbit/s
}

void VpnConnection::reconnectToVpn() {
    if (m_vpnProtocol.isNull())
        return;

#ifdef AMNEZIA_DESKTOP
    if (auto *wireguard = qobject_cast<WireguardProtocol *>(m_vpnProtocol.data());
            wireguard && wireguard->preservesConnectionState()) {
        wireguard->reconnect();
        return;
    }
#endif

    if (m_connectionState != Vpn::ConnectionState::Connected) {
        qWarning() << QString("Reconnect triggered on %1 during inappropriate state: %2; ignoring slot")
                              .arg(QMetaEnum::fromType<Vpn::ConnectionState>().valueToKey(m_connectionState));
        return;
    }

    qDebug() << "Reconnect triggered. Reconnecting to the server";

    setConnectionState(Vpn::ConnectionState::Reconnecting);

#ifdef AMNEZIA_DESKTOP
    if (auto *wireguard = qobject_cast<WireguardProtocol *>(m_vpnProtocol.data())) {
        wireguard->reconnect();
        return;
    }
#endif
    m_vpnProtocol->stop();
    if (ErrorCode err = m_vpnProtocol->start(); err != ErrorCode::NoError) {
        setConnectionState(Vpn::ConnectionState::Error);
        emit vpnProtocolError(err);
    }
}

void VpnConnection::disconnectFromVpn()
{
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    // iOS/macOS NE use IosController directly; m_vpnProtocol is not set there.
    IosController::Instance()->disconnectVpn();
    disconnect(&m_checkTimer, &QTimer::timeout, IosController::Instance(), &IosController::checkStatus);
#endif

    if (m_vpnProtocol.isNull()) {
        setConnectionState(Vpn::ConnectionState::Disconnected);
        return;
    }

    setConnectionState(Vpn::ConnectionState::Disconnecting);

#ifdef Q_OS_ANDROID
    auto *const connection = new QMetaObject::Connection;
    *connection = connect(AndroidController::instance(), &AndroidController::vpnStateChanged, this,
                          [this, connection](AndroidController::ConnectionState state) {
                              if (state == AndroidController::ConnectionState::DISCONNECTED) {
                                  setConnectionState(Vpn::ConnectionState::Disconnected);
                                  disconnect(*connection);
                                  delete connection;
                              }
                          });
#endif

#ifdef AMNEZIA_DESKTOP
    // Domain endpoints stop asynchronously: the service must acknowledge real
    // teardown before the protocol/socket owner can be released. Use queued
    // completion so neither a synchronous stop nor an error destroys a signal
    // sender while its own stop/notification stack is still running.
    auto *waiter = new QObject(this);
    const auto expected = m_vpnProtocol.toWeakRef();
    const auto finished = [this, waiter, expected] {
        const auto stopped = expected.toStrongRef();
        if (stopped && m_vpnProtocol == stopped) m_vpnProtocol.clear();
        waiter->deleteLater();
    };
    connect(m_vpnProtocol.data(), &VpnProtocol::connectionStateChanged, waiter,
            [finished](Vpn::ConnectionState state) {
                if (state == Vpn::Disconnected || state == Vpn::Error) finished();
            }, Qt::QueuedConnection);
    connect(m_vpnProtocol.data(), &VpnProtocol::protocolError, waiter,
            [finished](ErrorCode) { finished(); }, Qt::QueuedConnection);
    m_vpnProtocol->stop();
    // Some protocols are already stopped and emit no state transition.
    if (m_vpnProtocol && (m_vpnProtocol->connectionState() == Vpn::Disconnected
                          || m_vpnProtocol->connectionState() == Vpn::Error))
        QTimer::singleShot(0, waiter, finished);
    return;
#else
    m_vpnProtocol->stop();
#endif

#if !defined(Q_OS_ANDROID) && !defined(AMNEZIA_DESKTOP)
    m_vpnProtocol->deleteLater();
#endif

    m_vpnProtocol = nullptr;
}

void VpnConnection::setConnectionState(Vpn::ConnectionState state) {
    onConnectionStateChanged(state);

    if (state == Vpn::Disconnected && m_connectionState == Vpn::Reconnecting)
        return;

    m_connectionState = state;
    emit connectionStateChanged(state);
}
