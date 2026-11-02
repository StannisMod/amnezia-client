#include <QCoreApplication>
#include <QFileInfo>
#include <QProcess>
#include <QTcpSocket>
#include <QThread>
#include <QHostInfo>

#include "wireGuardProtocol.h"
#include "core/utils/networkUtilities.h"
#include "core/utils/vpnEndpoint.h"

#include "mozilla/localsocketcontroller.h"

WireguardProtocol::WireguardProtocol(const QJsonObject &configuration, QObject *parent)
    : VpnProtocol(configuration, parent)
{
    m_impl.reset(new LocalSocketController());
    connect(m_impl.get(), &ControllerImpl::connected, this,
            [this](const QString &pubkey, const QDateTime &connectionTimestamp) {
                setConnectionState(Vpn::ConnectionState::Connected);
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
            [this]() { setConnectionState(Vpn::ConnectionState::Disconnected); });
    m_impl->initialize(nullptr, nullptr);
}

WireguardProtocol::~WireguardProtocol()
{
    WireguardProtocol::stop();
    QThread::msleep(200);
}

void WireguardProtocol::stop()
{
    if (guardStop()) {
        return;
    }
    stopMzImpl();
}

ErrorCode WireguardProtocol::startMzImpl()
{
    const QString protocolName = m_rawConfig.value(configKey::vpnProto).toString();
    const auto configData = m_rawConfig.value(protocolName + "_config_data").toObject();
    const QString host = configData.value(configKey::hostName).toString();
    const bool allowIpv6 = m_rawConfig.contains("sing_box_routing");
    const QHostAddress literal(host);
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
    resetStopGuard();
    return startMzImpl();
}
