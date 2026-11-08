#include <QCoreApplication>
#include <QFileInfo>
#include <QProcess>
#include <QTcpSocket>
#include <QThread>
#include <QHostInfo>

#include "wireGuardProtocol.h"
#include "core/utils/vpnEndpoint.h"

#include "mozilla/localsocketcontroller.h"

WireguardProtocol::WireguardProtocol(const QJsonObject &configuration, QObject *parent, ControllerImpl *controller)
    : VpnProtocol(configuration, parent)
{
    m_impl.reset(controller ? controller : new LocalSocketController());
    setupEndpointSession();
    connect(m_impl.get(), &ControllerImpl::connected, this,
            [this](const QString &pubkey, const QDateTime &connectionTimestamp) {
                if (m_stopped) return;
                if (usesEndpointSession()) {
                    using Phase=amnezia::VpnEndpointSession::Phase;
                    if (!m_endpointSession.wanted() || (m_endpointSession.phase()!=Phase::Connecting && m_endpointSession.phase()!=Phase::Connected)) return;
                }
                m_backendEstablished = true;
                if (usesRoutedBackend() && m_impl->routingRecoverySupported() && !m_impl->routingRuntimeId().isEmpty())
                    m_preservedRuntimeId=m_impl->routingRuntimeId();
                // Bind before Connected is observable: a queued network event
                // must never enter legacy teardown in the first status roundtrip.
                if (usesEndpointSession()) m_endpointSession.connected();
                else setConnectionState(Vpn::ConnectionState::Connected);
                m_impl->checkStatus();
            });
    connect(m_impl.get(), &ControllerImpl::statusUpdated, this,
            [this](const QString& serverIpv4Gateway,
                   const QString& deviceIpv4Address, uint64_t txBytes,
                   uint64_t rxBytes) {
                const QString previousGateway = m_vpnGateway;
                const QString previousLocal = m_vpnLocalAddress;

                if (!serverIpv4Gateway.isEmpty()) {
                    m_vpnGateway = serverIpv4Gateway;
                }
                if (!deviceIpv4Address.isEmpty()) {
                    m_vpnLocalAddress = deviceIpv4Address;
                }

                if ((!m_vpnGateway.isEmpty() && m_vpnGateway != previousGateway) ||
                    (!m_vpnLocalAddress.isEmpty() && m_vpnLocalAddress != previousLocal)) {
                    emit tunnelAddressesUpdated(m_vpnGateway, m_vpnLocalAddress);
                }
            });

    connect(m_impl.get(), &ControllerImpl::disconnected, this,
            [this]() {
                if (preservesConnectionState()) { m_impl->checkStatus(); return; }
                if (usesEndpointSession()) m_endpointSession.recover();
                else setConnectionState(Vpn::ConnectionState::Disconnected);
            });
    m_impl->initialize(nullptr, nullptr);
    connect(m_impl.get(), &ControllerImpl::routingRuntimeStatus, this,
            [this](const QString &id, bool alive, bool preserves) {
        if (!usesEndpointSession()) return;
        if (m_preservedRuntimeId.isEmpty() && !m_impl->routingRuntimeId().isEmpty() && id!=m_impl->routingRuntimeId()) {
            m_backendEstablished=false;m_runtimeReplaced=true;m_peerPoll.stop();
            m_endpointSession.abandonReplacedBackend();
            setLastError(ErrorCode::VpnEndpointCleanupFailed);
            emit protocolError(ErrorCode::VpnEndpointCleanupFailed);
            return;
        }
        if (!m_backendEstablished) return;
        if (m_preservedRuntimeId.isEmpty()) {
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
            if (alive && preserves && !id.isEmpty() && m_impl->routingRuntimeId() == id)
                m_preservedRuntimeId = id;
#endif
            return;
        }
        if (id != m_preservedRuntimeId) {
            // Another owner or service generation is not ours to tear down.
            m_backendEstablished = false;
            m_peerPoll.stop();
            m_runtimeReplaced = true;
            m_endpointSession.abandonReplacedBackend();
            setLastError(ErrorCode::VpnEndpointCleanupFailed);
            emit protocolError(ErrorCode::VpnEndpointCleanupFailed);
            return;
        }
        if (!alive) {
            m_preservedRuntimeId.clear();
            m_backendEstablished = false;
            m_endpointSession.recover(); // Proven dead child, with matching ownership.
        }
    });
}

WireguardProtocol::~WireguardProtocol()
{
    WireguardProtocol::stop();
    QThread::msleep(200);
}

void WireguardProtocol::stop()
{
    m_backendEstablished = false;
    m_preservedRuntimeId.clear();
    m_peerPoll.stop();
    if (guardStop()) {
        return;
    }
    if (usesEndpointSession()) m_endpointSession.stop();
    else stopMzImpl();
}

ErrorCode WireguardProtocol::startMzImpl()
{
    const QString protocolName = m_rawConfig.value(configKey::vpnProto).toString();
    const auto configData = m_rawConfig.value(protocolName + "_config_data").toObject();
    const QString host = configData.value(configKey::hostName).toString();
    const bool allowIpv6 = m_rawConfig.contains("sing_box_routing");
    const QHostAddress literal(host);
    m_domainEndpoint = literal.isNull();
    if (usesEndpointSession()) {
        m_endpointSession.start(host, allowIpv6);
        return ErrorCode::NoError;
    }
    const QList<QHostAddress> addresses = literal.isNull()
        ? QHostInfo::fromName(host).addresses() : QList<QHostAddress>{literal};
    const QString address = amnezia::vpnEndpoint::preferredAddress(addresses, allowIpv6);
    if (address.isEmpty()) {
        setLastError(ErrorCode::VpnEndpointResolutionFailed);
        return ErrorCode::VpnEndpointResolutionFailed;
    }

    // Resolve before capture, retaining the domain for subsequent starts.
    m_impl->activate(amnezia::vpnEndpoint::activationConfig(m_rawConfig, address));
    return ErrorCode::NoError;
}

ErrorCode WireguardProtocol::stopMzImpl()
{
    m_impl->deactivate();
    return ErrorCode::NoError;
}


ErrorCode WireguardProtocol::start()
{
    m_runtimeReplaced = false;
    resetStopGuard();
    return startMzImpl();
}

void WireguardProtocol::setupEndpointSession()
{
    using Session = amnezia::VpnEndpointSession;
    m_endpointSession.resolver = [this](const QString &host, Session::Completion complete) {
        const QHostAddress literal(host);
        if (!literal.isNull()) { complete({literal}); return; }
        m_impl->resolveEndpoint(host, std::move(complete));
    };
    m_endpointSession.cancelResolver = [this] { m_impl->cancelEndpointLookup(); };
    m_peerClock.start();
    m_peerPoll.setInterval(5000);
    connect(&m_peerPoll, &QTimer::timeout, this, [this] { m_impl->checkStatus(); });
    m_endpointSession.changed = [this](Session::Phase phase) {
        m_peerPoll.stop();
        switch (phase) {
        case Session::Phase::Idle: setConnectionState(Vpn::Disconnected); break;
        case Session::Phase::Connected:
            m_peerPoll.start();
            setConnectionState(Vpn::Connected);
            break;
        case Session::Phase::Stopping:
            setConnectionState(m_endpointSession.wanted() ? Vpn::Reconnecting : Vpn::Disconnecting);
            break;
        case Session::Phase::Resolving:
        case Session::Phase::Connecting:
            setConnectionState(m_connectionState == Vpn::Connected || m_connectionState == Vpn::Reconnecting
                               ? Vpn::Reconnecting : Vpn::Connecting);
            break;
        case Session::Phase::Waiting: setConnectionState(Vpn::Reconnecting); break;
        case Session::Phase::Failed: break; // failed callback supplies the reason.
        }
    };
    m_endpointSession.activate = [this](const QString &address) {
        m_impl->activate(amnezia::vpnEndpoint::activationConfig(m_rawConfig, address));
    };
    m_endpointSession.deactivate = [this] { m_impl->deactivateWithAck(); };
    m_endpointSession.failed = [this](Session::Failure failure) {
        const auto error = failure == Session::Failure::Cleanup ? ErrorCode::VpnEndpointCleanupFailed
            : failure == Session::Failure::Resolution ? ErrorCode::VpnEndpointResolutionFailed
            : ErrorCode::VpnEndpointRecoveryFailed;
        setLastError(error);
        emit protocolError(error);
    };
    connect(m_impl.get(), &ControllerImpl::deactivated, this, [this] {
        if (usesEndpointSession()) m_endpointSession.deactivated();
    });
    connect(m_impl.get(), &ControllerImpl::handshakeUpdated, this, [this](qint64 handshakeMs, quint64 tx, quint64 rx) {
        if (usesEndpointSession() && !preservesConnectionState())
            m_endpointSession.observePeer(handshakeMs, tx, rx, m_peerClock.elapsed());
    });
    // Honour longer AWG protocol timers instead of treating a valid slow rekey
    // as an outage. A range's upper bound is the conservative boundary.
    const QString protocol = m_rawConfig.value(configKey::vpnProto).toString();
    const auto data = m_rawConfig.value(protocol + "_config_data").toObject();
    for (const auto &key : {QStringLiteral("RejectAfterTime"), QStringLiteral("RekeyAfterTime")}) {
        bool ok = false;
        const qint64 seconds = data.value(key).toString().section('-', -1).toLongLong(&ok);
        if (ok && seconds > 0 && seconds <= 86400)
            m_endpointSession.timing.staleMs = qMax(m_endpointSession.timing.staleMs, (seconds * 2 + 30) * 1000);
    }
}

void WireguardProtocol::reconnect()
{
    if (preservesConnectionState()) { m_impl->hintRoutingNetwork(m_preservedRuntimeId); return; }
    if (usesEndpointSession()) {
        const QString protocol = m_rawConfig.value(configKey::vpnProto).toString();
        const QString host = m_rawConfig.value(protocol + "_config_data").toObject().value(configKey::hostName).toString();
        m_endpointSession.start(host, m_rawConfig.contains("sing_box_routing"));
        return;
    }
    stop();
    if (const auto error = start(); error != ErrorCode::NoError) emit protocolError(error);
}

bool WireguardProtocol::usesEndpointSession() const {
    return usesRoutedBackend() || m_domainEndpoint;
}

bool WireguardProtocol::usesRoutedBackend() const {
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
    return m_rawConfig.contains("sing_box_routing");
#else
    return false;
#endif
}

bool WireguardProtocol::preservesConnectionState() const {
    return m_backendEstablished && !m_preservedRuntimeId.isEmpty();
}
