#include "exportController.h"
#include "connectionUpdatesController.h"
#include "core/utils/connectionUpdates.h"
#include <QUrl>
#include "core/utils/vpnEndpoint.h"

#include <QJsonArray>
#include <QJsonDocument>

#include "core/configurators/configuratorBase.h"
#include "core/utils/selfhosted/sshSession.h"
#include "core/utils/qrCodeUtils.h"
#include "core/utils/serialization/serialization.h"
#include "core/utils/protocolEnum.h"
#include "core/protocols/protocolUtils.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/constants/protocolConstants.h"
#include "core/models/selfhosted/selfHostedAdminServerConfig.h"
#include "core/models/containerConfig.h"
#include "core/models/protocolConfig.h"
#include "version.h"

using namespace amnezia;

ExportController::ExportController(SecureServersRepository* serversRepository,
                                   SecureAppSettingsRepository* appSettingsRepository,
                                   QObject *parent)
    : QObject(parent),
      m_serversRepository(serversRepository),
      m_appSettingsRepository(appSettingsRepository)
{
}

ExportController::ExportResult ExportController::generateFullAccessConfig(const QString &serverId)
{
    ExportResult result;

    auto adminConfig = m_serversRepository->selfHostedAdminConfig(serverId);
    if (!adminConfig.has_value()) {
        result.errorCode = ErrorCode::InternalError;
        return result;
    }
    for (auto it = adminConfig->containers.begin(); it != adminConfig->containers.end(); ++it) {
        it.value().protocolConfig.clearClientConfig();
    }

    QJsonObject serverJson = adminConfig->toJson();
    QByteArray compressedConfig = QJsonDocument(serverJson).toJson();
    compressedConfig = qCompress(compressedConfig, 8);
    result.config = generateVpnUrl(compressedConfig);
    result.qrCodes = generateQrCodesFromConfig(compressedConfig);

    return result;
}

ExportController::ExportResult ExportController::generateConnectionConfig(const QString &serverId, int containerIndex, const QString &clientName, bool updatable)
{
    ExportResult result;

    DockerContainer container = static_cast<DockerContainer>(containerIndex);
    auto adminConfig = m_serversRepository->selfHostedAdminConfig(serverId);
    if (!adminConfig.has_value()) {
        result.errorCode = ErrorCode::InternalError;
        return result;
    }
    const auto updateMetadata = adminConfig->connectionUpdates;
    if (updatable && (updateMetadata.value("version").toInt() != 1 || (container != DockerContainer::WireGuard && container != DockerContainer::Awg2))) {
        result.errorCode = ErrorCode::InternalError;
        return result;
    }
    adminConfig->connectionUpdates = {};
    const ServerCredentials credentials = adminConfig->credentials();
    if (!credentials.isValid()) {
        result.errorCode = ErrorCode::InternalError;
        return result;
    }
    bool individualIPv6Supported = false;
    if (updatable) {
        QJsonObject info;
        result.errorCode = ConnectionUpdatesController::command(credentials, "info", {}, info);
        if (result.errorCode != ErrorCode::NoError) return result;
        if (info.value("publicKey") != updateMetadata.value("publicKey")
            || info.value("certificate") != updateMetadata.value("certificate")) {
            result.errorCode = ErrorCode::InternalError;
            return result;
        }
        individualIPv6Supported = info.value("features").toArray().contains("client-ipv6-v1");
    }
    ContainerConfig containerConfig = adminConfig->containerConfig(container);

    if (ContainerUtils::containerService(container) != ServiceType::Other) {
        SshSession sshSession;
        Proto protocol = ContainerUtils::defaultProtocol(container);

        DnsSettings dnsSettings = {
            m_appSettingsRepository->primaryDns(),
            m_appSettingsRepository->secondaryDns()
        };

        auto configurator = ConfiguratorBase::create(protocol, &sshSession);
        ProtocolConfig newProtocolConfig = configurator->createConfig(credentials, container, containerConfig, dnsSettings, result.errorCode);
        if (result.errorCode != ErrorCode::NoError) {
            return result;
        }

        containerConfig.protocolConfig = newProtocolConfig;
        
        QString clientId = newProtocolConfig.clientId();
        if (!clientId.isEmpty()) {
            emit appendClientRequested(serverId, clientId, clientName, container);
        }
    }

    const QPair<QString, QString> dns = adminConfig->getDnsPair(m_appSettingsRepository->useAmneziaDns(),
                                                               m_appSettingsRepository->primaryDns(),
                                                               m_appSettingsRepository->secondaryDns());

    const Proto exportedProto = ContainerUtils::defaultProtocol(container);
    if (!adminConfig->vpnHostName.isEmpty() && (exportedProto == Proto::Awg || exportedProto == Proto::WireGuard)) {
        containerConfig.protocolConfig.setVpnHostName(adminConfig->vpnHostName);
        adminConfig->hostName = adminConfig->vpnHostName;
    }

    adminConfig->containers.clear();
    adminConfig->containers[container] = containerConfig;
    adminConfig->defaultContainer = container;
    adminConfig->userName.clear();
    adminConfig->password.clear();
    adminConfig->port = 0;

    adminConfig->dns1 = dns.first;
    adminConfig->dns2 = dns.second;

    QJsonObject serverJson = adminConfig->toJson();
    if (updatable) {
        const auto client = containerConfig.protocolConfig.getClientConfigJson();
        QJsonObject response;
        QString probe;
        result.errorCode = ConnectionUpdatesController::fetchPathMtuProbeAddress(credentials, container, probe);
        if (result.errorCode != ErrorCode::NoError) return result;
        QJsonObject request { { "pathMtuProbe", probe }, { "container", ContainerUtils::containerToString(container) },
            { "clientPublicKey", client.value(configKey::clientPubKey) },
            { "settings", connectionUpdates::publicSettings(client, container == DockerContainer::Awg2) } };
        QString generatedIPv6;
        if (individualIPv6Supported) {
            QJsonObject assignments, individual;
            result.errorCode = ConnectionUpdatesController::fetchPeerIPv6Assignments(credentials, container, assignments);
            if (result.errorCode != ErrorCode::NoError) return result;
            if (!connectionUpdates::individualIPv6Assignment(assignments, client.value(configKey::clientPubKey).toString(), individual)) {
                result.errorCode = ErrorCode::InternalError; return result;
            }
            generatedIPv6 = individual.value(client.value(configKey::clientPubKey).toString()).toString();
            QStringList generatedAddresses;
            for (const auto &entry : client.value(configKey::clientIp).toString().split(',')) generatedAddresses << entry.trimmed();
            if ((!generatedIPv6.isEmpty() && !generatedAddresses.contains(generatedIPv6 + "/128"))
                || (generatedIPv6.isEmpty() && client.value(configKey::clientIp).toString().contains(':'))) {
                result.errorCode = ErrorCode::InternalError; return result;
            }
            request["clientIpv6"] = individual;
        }
        result.errorCode = ConnectionUpdatesController::command(credentials, "issue", request, response);
        if (result.errorCode != ErrorCode::NoError) return result;
        // Detect server identity changes; a reinstallation must be explicitly trusted.
        if (response.value("publicKey") != updateMetadata.value("publicKey") || response.value("certificate") != updateMetadata.value("certificate")) {
            result.errorCode = ErrorCode::InternalError; return result;
        }
        auto metadata = connectionUpdates::invitationMetadata(updateMetadata);
        metadata["id"] = response.value("id"); metadata["token"] = response.value("token");
        metadata["container"] = request.value("container"); metadata["clientPublicKey"] = request.value("clientPublicKey");
        metadata["revision"] = "0";
        if (individualIPv6Supported) {
            metadata["clientIpv6"] = generatedIPv6;
            if (!generatedIPv6.isEmpty()) metadata["managedClientIpv6"] = generatedIPv6;
        }
        QUrl url(metadata.value("url").toString()); url.setPath("/v1/connections/" + response.value("id").toString()); metadata["url"] = url.toString();
        serverJson[connectionUpdates::metadataKey] = metadata;
        if (!connectionUpdates::validateProfile(serverJson)) { result.errorCode = ErrorCode::InternalError; return result; }
    }

    QByteArray compressedConfig = QJsonDocument(serverJson).toJson();
    compressedConfig = qCompress(compressedConfig, 8);
    result.config = generateVpnUrl(compressedConfig);
    result.qrCodes = generateQrCodesFromConfig(compressedConfig);

    return result;
}

ExportController::ExportResult ExportController::generateConnectionUpdates(const QString &serverId, int containerIndex, const QString &clientPublicKey)
{
    ExportResult result;
    auto admin = m_serversRepository->selfHostedAdminConfig(serverId);
    const auto container = static_cast<DockerContainer>(containerIndex);
    if (!admin || !admin->credentials().isValid() || !admin->containers.contains(container)
        || (container != DockerContainer::WireGuard && container != DockerContainer::Awg2)
        || admin->connectionUpdates.value("version").toInt() != 1) { result.errorCode = ErrorCode::InternalError; return result; }
    QJsonObject info;
    result.errorCode = ConnectionUpdatesController::command(admin->credentials(), "info", {}, info);
    if (result.errorCode != ErrorCode::NoError) return result;
    if (info.value("publicKey") != admin->connectionUpdates.value("publicKey") || info.value("certificate") != admin->connectionUpdates.value("certificate")) {
        result.errorCode = ErrorCode::InternalError; return result;
    }
    const auto host = vpnEndpoint::normalizeHost(admin->vpnHostName.isEmpty() ? admin->hostName : admin->vpnHostName);
    QJsonObject settings; QStringList peers; QString probe;
    result.errorCode = ConnectionUpdatesController::fetchPublicSettings(admin->credentials(), container, host, settings, &peers, &probe);
    if (result.errorCode != ErrorCode::NoError) return result;
    if (!peers.contains(clientPublicKey)) { result.errorCode = ErrorCode::InternalError; return result; }
    QJsonObject response;
    QJsonObject request { { "pathMtuProbe", probe }, { "container", ContainerUtils::containerToString(container) },
        { "clientPublicKey", clientPublicKey }, { "settings", settings } };
    if (info.value("features").toArray().contains("client-ipv6-v1")) {
        QJsonObject assignments, individual;
        result.errorCode = ConnectionUpdatesController::fetchPeerIPv6Assignments(admin->credentials(), container, assignments);
        if (result.errorCode != ErrorCode::NoError) return result;
        if (!connectionUpdates::individualIPv6Assignment(assignments, clientPublicKey, individual)) {
            result.errorCode = ErrorCode::InternalError; return result;
        }
        request["clientIpv6"] = individual;
    }
    result.errorCode = ConnectionUpdatesController::command(admin->credentials(), "issue", request, response);
    if (result.errorCode != ErrorCode::NoError) return result;
    if (response.value("publicKey") != admin->connectionUpdates.value("publicKey") || response.value("certificate") != admin->connectionUpdates.value("certificate")) {
        result.errorCode = ErrorCode::InternalError; return result;
    }
    auto metadata = connectionUpdates::invitationMetadata(admin->connectionUpdates);
    for (const auto *key : { "id", "token" }) metadata[key] = response.value(key);
    metadata["clientPublicKey"] = clientPublicKey; metadata["container"] = ContainerUtils::containerToString(container); metadata["revision"] = "0";
    QUrl url(metadata.value("url").toString()); url.setPath("/v1/connections/" + response.value("id").toString()); metadata["url"] = url.toString();
    const QJsonObject invitation { { "type", "amnezia-update-invitation" }, { "version", 1 },
        { "existingServerPublicKey", settings.value("server_pub_key") }, { connectionUpdates::metadataKey, metadata } };
    const auto compressed = qCompress(QJsonDocument(invitation).toJson(QJsonDocument::Compact), 8);
    result.config = generateVpnUrl(compressed); result.qrCodes = generateQrCodesFromConfig(compressed);
    return result;
}

ExportController::NativeConfigResult ExportController::generateNativeConfig(const QString &serverId, DockerContainer container,
                                                                             const ContainerConfig &containerConfig,
                                                                             const QString &clientName)
{
    NativeConfigResult result;

    if (ContainerUtils::containerService(container) == ServiceType::Other) {
        return result;
    }

    Proto protocol = ContainerUtils::defaultProtocol(container);

    auto adminConfig = m_serversRepository->selfHostedAdminConfig(serverId);
    if (!adminConfig.has_value()) {
        result.errorCode = ErrorCode::InternalError;
        return result;
    }
    const ServerCredentials credentials = adminConfig->credentials();
    if (!credentials.isValid()) {
        result.errorCode = ErrorCode::InternalError;
        return result;
    }
    const QPair<QString, QString> dns = adminConfig->getDnsPair(m_appSettingsRepository->useAmneziaDns(),
                                                                m_appSettingsRepository->primaryDns(),
                                                                m_appSettingsRepository->secondaryDns());

    ContainerConfig modifiedContainerConfig = containerConfig;
    modifiedContainerConfig.container = container;

    DnsSettings dnsSettings = {
        m_appSettingsRepository->primaryDns(),
        m_appSettingsRepository->secondaryDns()
    };

    SshSession sshSession;
    auto configurator = ConfiguratorBase::create(protocol, &sshSession);

    ProtocolConfig newProtocolConfig = configurator->createConfig(credentials, container, modifiedContainerConfig, dnsSettings, result.errorCode);
    if (result.errorCode != ErrorCode::NoError) {
        return result;
    }

    if (!adminConfig->vpnHostName.isEmpty()) {
        newProtocolConfig.setVpnHostName(adminConfig->vpnHostName);
    }

    ExportSettings exportSettings = { { dns.first, dns.second } };
    ProtocolConfig processedConfig = configurator->processConfigWithExportSettings(exportSettings, newProtocolConfig);

    if (protocol == Proto::OpenVpn || protocol == Proto::WireGuard || protocol == Proto::Awg) {
        result.jsonNativeConfig[configKey::config] = processedConfig.nativeConfig();
    } else {
        result.jsonNativeConfig = QJsonDocument::fromJson(processedConfig.nativeConfig().toUtf8()).object();
    }

    if (protocol == Proto::OpenVpn || protocol == Proto::WireGuard || protocol == Proto::Awg || protocol == Proto::Xray) {
        QString clientId = newProtocolConfig.clientId();
        if (!clientId.isEmpty()) {
            emit appendClientRequested(serverId, clientId, clientName, container);
        }
    }
    return result;
}

ExportController::ExportResult ExportController::generateOpenVpnConfig(const QString &serverId, const QString &clientName)
{
    ExportResult result;

    DockerContainer container = DockerContainer::OpenVpn;
    auto adminConfig = m_serversRepository->selfHostedAdminConfig(serverId);
    if (!adminConfig.has_value()) {
        result.errorCode = ErrorCode::InternalError;
        return result;
    }
    ContainerConfig containerConfig = adminConfig->containerConfig(container);

    auto nativeResult = generateNativeConfig(serverId, container, containerConfig, clientName);
    if (nativeResult.errorCode != ErrorCode::NoError) {
        result.errorCode = nativeResult.errorCode;
        return result;
    }

    QStringList lines = nativeResult.jsonNativeConfig.value(configKey::config).toString().replace("\r", "").split("\n");
    for (const QString &line : std::as_const(lines)) {
        result.config.append(line + "\n");
    }

    result.qrCodes = generateQrCodesFromConfig(result.config.toUtf8());
    return result;
}

ExportController::ExportResult ExportController::generateWireGuardConfig(const QString &serverId, const QString &clientName)
{
    ExportResult result;

    auto adminConfig = m_serversRepository->selfHostedAdminConfig(serverId);
    if (!adminConfig.has_value()) {
        result.errorCode = ErrorCode::InternalError;
        return result;
    }
    ContainerConfig containerConfig = adminConfig->containerConfig(DockerContainer::WireGuard);

    auto nativeResult = generateNativeConfig(serverId, DockerContainer::WireGuard, containerConfig, clientName);
    if (nativeResult.errorCode != ErrorCode::NoError) {
        result.errorCode = nativeResult.errorCode;
        return result;
    }

    QStringList lines = nativeResult.jsonNativeConfig.value(configKey::config).toString().replace("\r", "").split("\n");
    for (const QString &line : std::as_const(lines)) {
        result.config.append(line + "\n");
    }

    const QString qr = qrCodeUtils::generatePlainQrCodeImage(result.config.toUtf8());
    if (!qr.isEmpty()) {
        result.qrCodes << qr;
    }
    return result;
}

ExportController::ExportResult ExportController::generateAwgConfig(const QString &serverId, int containerIndex, const QString &clientName)
{
    ExportResult result;

    DockerContainer container = static_cast<DockerContainer>(containerIndex);
    if (container != DockerContainer::Awg && container != DockerContainer::Awg2) {
        result.errorCode = ErrorCode::InternalError;
        return result;
    }
    auto adminConfig = m_serversRepository->selfHostedAdminConfig(serverId);
    if (!adminConfig.has_value()) {
        result.errorCode = ErrorCode::InternalError;
        return result;
    }
    ContainerConfig containerConfig = adminConfig->containerConfig(container);

    auto nativeResult = generateNativeConfig(serverId, container, containerConfig, clientName);
    if (nativeResult.errorCode != ErrorCode::NoError) {
        result.errorCode = nativeResult.errorCode;
        return result;
    }

    QStringList lines = nativeResult.jsonNativeConfig.value(configKey::config).toString().replace("\r", "").split("\n");
    for (const QString &line : std::as_const(lines)) {
        result.config.append(line + "\n");
    }

    const QString qr = qrCodeUtils::generatePlainQrCodeImage(result.config.toUtf8());
    if (!qr.isEmpty()) {
        result.qrCodes << qr;
    }
    return result;
}


ExportController::ExportResult ExportController::generateXrayConfig(const QString &serverId, const QString &clientName)
{
    ExportResult result;

    auto adminConfig = m_serversRepository->selfHostedAdminConfig(serverId);
    if (!adminConfig.has_value()) {
        result.errorCode = ErrorCode::InternalError;
        return result;
    }
    ContainerConfig containerConfig = adminConfig->containerConfig(DockerContainer::Xray);

    auto nativeResult = generateNativeConfig(serverId, DockerContainer::Xray, containerConfig, clientName);
    if (nativeResult.errorCode != ErrorCode::NoError) {
        result.errorCode = nativeResult.errorCode;
        return result;
    }

    QStringList lines = QString(QJsonDocument(nativeResult.jsonNativeConfig).toJson()).replace("\r", "").split("\n");
    for (const QString &line : std::as_const(lines)) {
        result.config.append(line + "\n");
    }

    // Parse the Xray data to extract VLESS parameters and generate string
    QJsonObject xrayConfig = nativeResult.jsonNativeConfig;
    QJsonArray outbounds = xrayConfig.value(amnezia::protocols::xray::outbounds).toArray();

    if (outbounds.isEmpty()) {
        result.errorCode = ErrorCode::InternalError;
        return result;
    }

    QJsonObject outbound = outbounds[0].toObject();
    QJsonObject settings = outbound.value(amnezia::protocols::xray::settings).toObject();
    QJsonObject streamSettings = outbound.value(amnezia::protocols::xray::streamSettings).toObject();

    QJsonArray vnext = settings.value(amnezia::protocols::xray::vnext).toArray();
    if (vnext.isEmpty()) {
        result.errorCode = ErrorCode::InternalError;
        return result;
    }

    QJsonObject server = vnext[0].toObject();
    QJsonArray users = server.value(amnezia::protocols::xray::users).toArray();
    if (users.isEmpty()) {
        result.errorCode = ErrorCode::InternalError;
        return result;
    }

    QJsonObject user = users[0].toObject();

    amnezia::serialization::VlessServerObject vlessServer;
    vlessServer.address = server.value(amnezia::protocols::xray::address).toString();
    vlessServer.port = server.value(amnezia::protocols::xray::port).toInt();
    vlessServer.id = user.value(amnezia::protocols::xray::id).toString();
    vlessServer.flow = user.value(amnezia::protocols::xray::flow).toString("xtls-rprx-vision");
    vlessServer.encryption = user.value(amnezia::protocols::xray::encryption).toString("none");

    vlessServer.network = streamSettings.value(amnezia::protocols::xray::network).toString("tcp");
    vlessServer.security = streamSettings.value(amnezia::protocols::xray::security).toString("reality");

    if (vlessServer.security == "reality") {
        QJsonObject realitySettings = streamSettings.value(amnezia::protocols::xray::realitySettings).toObject();
        vlessServer.serverName = realitySettings.value(amnezia::protocols::xray::serverName).toString();
        vlessServer.publicKey = realitySettings.value(amnezia::protocols::xray::publicKey).toString();
        vlessServer.shortId = realitySettings.value(amnezia::protocols::xray::shortId).toString();
        vlessServer.fingerprint = realitySettings.value(amnezia::protocols::xray::fingerprint).toString("chrome");
        vlessServer.spiderX = realitySettings.value(amnezia::protocols::xray::spiderX).toString("");
    } else if (vlessServer.security == "tls") {
        QJsonObject tlsSettings = streamSettings.value("tlsSettings").toObject();
        vlessServer.serverName = tlsSettings.value(amnezia::protocols::xray::serverName).toString();
        vlessServer.fingerprint = tlsSettings.value(amnezia::protocols::xray::fingerprint).toString();
        // alpn: serialize array back to comma-separated for VLESS URI
        QJsonArray alpnArr = tlsSettings.value("alpn").toArray();
        QStringList alpnList;
        for (const QJsonValue &v : alpnArr) {
            alpnList << v.toString();
        }
        // alpn goes into vless URI query param — handled by Serialize via serverName/alpn fields
        // VlessServerObject doesn't have alpn field, so we embed in serverName if needed
    }

    result.nativeConfigString = amnezia::serialization::vless::Serialize(vlessServer, APPLICATION_NAME);

    return result;
}

void ExportController::updateClientManagementModel(const QString &serverId, int containerIndex)
{
    DockerContainer container = static_cast<DockerContainer>(containerIndex);
    emit updateClientsRequested(serverId, container);
}

void ExportController::revokeConfig(int row, const QString &serverId, int containerIndex)
{
    DockerContainer container = static_cast<DockerContainer>(containerIndex);
    emit revokeClientRequested(serverId, row, container);
}

void ExportController::renameClient(int row, const QString &clientName, const QString &serverId, int containerIndex)
{
    DockerContainer container = static_cast<DockerContainer>(containerIndex);
    emit renameClientRequested(serverId, row, clientName, container);
}

QString ExportController::generateVpnUrl(const QByteArray &compressedConfig)
{
    return QString("vpn://%1").arg(QString(compressedConfig.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals)));
}

QList<QString> ExportController::generateQrCodesFromConfig(const QByteArray &data)
{
    return qrCodeUtils::generateQrCodeImageSeries(data);
}
