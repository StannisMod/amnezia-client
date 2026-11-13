#include "wireguardConfigurator.h"

#include <algorithm>
#include <utility>

#include <QDebug>
#include <QJsonDocument>
#include <QProcess>
#include <QRegularExpression>
#include <QRandomGenerator>
#include <QString>
#include <QTemporaryDir>
#include <QTemporaryFile>

#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "core/utils/containerEnum.h"
#include "core/utils/containers/containerUtils.h"
#include "core/utils/protocolEnum.h"
#include "core/utils/selfhosted/sshSession.h"
#include "core/utils/selfhosted/scriptsRegistry.h"
#include "core/utils/protocolEnum.h"
#include "core/protocols/protocolUtils.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/constants/protocolConstants.h"
#include "core/utils/utilities.h"
#include "core/utils/connectionUpdates.h"
#include "core/models/containerConfig.h"
#include "core/models/protocols/wireGuardProtocolConfig.h"
#include "core/models/protocols/awgProtocolConfig.h"
#include <QJsonArray>

using namespace amnezia;

WireguardConfigurator::WireguardConfigurator(SshSession* sshSession, bool isAwg,
                                             QObject *parent)
    : ConfiguratorBase(sshSession, parent), m_isAwg(isAwg)
{
    m_serverConfigPath =
            m_isAwg ? amnezia::protocols::awg::serverConfigPath : amnezia::protocols::wireguard::serverConfigPath;
    m_serverPublicKeyPath =
            m_isAwg ? amnezia::protocols::awg::serverPublicKeyPath : amnezia::protocols::wireguard::serverPublicKeyPath;
    m_serverPskKeyPath =
            m_isAwg ? amnezia::protocols::awg::serverPskKeyPath : amnezia::protocols::wireguard::serverPskKeyPath;
    m_configTemplate = m_isAwg ? ProtocolScriptType::awg_template : ProtocolScriptType::wireguard_template;

    m_protocolName = m_isAwg ? configKey::awg : configKey::wireguard;
    m_defaultPort = m_isAwg ? protocols::awg::defaultPort : protocols::wireguard::defaultPort;
}

void WireguardConfigurator::setPendingPeerExport(const QJsonObject &state, std::function<bool(const QJsonObject &)> persist)
{
    m_pendingPeerExport = state;
    m_persistPendingPeerExport = std::move(persist);
}

namespace {
QString pendingPeerCandidate(QString original, const WireguardConfigurator::ConnectionData &data)
{
    if (!original.endsWith('\n')) original += '\n';
    auto addresses=data.clientIP+"/32";
    if (!data.clientIPv6.isEmpty()) addresses+=", "+data.clientIPv6+"/128";
    return original+QString("[Peer]\nPublicKey = %1\nPresharedKey = %2\nAllowedIPs = %3\n\n")
        .arg(data.clientPubKey,data.pskKey,addresses);
}
bool pendingPeerKeyPair(const QString &privateKey, const QString &publicKey)
{
    const auto raw=QByteArray::fromBase64(privateKey.toLatin1());
    if (raw.size()!=32 || QString::fromLatin1(raw.toBase64())!=privateKey) return false;
    auto *key=EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519,nullptr,reinterpret_cast<const unsigned char *>(raw.constData()),raw.size());
    if (!key) return false;
    QByteArray derived(32,'\0'); size_t size=32;
    const bool ok=EVP_PKEY_get_raw_public_key(key,reinterpret_cast<unsigned char *>(derived.data()),&size)==1;
    EVP_PKEY_free(key);
    return ok && size==32 && QString::fromLatin1(derived.toBase64())==publicKey;
}
}

WireguardConfigurator::ConnectionData WireguardConfigurator::genClientKeys()
{
    // TODO review
    constexpr size_t EDDSA_KEY_LENGTH = 32;

    ConnectionData connData;

    unsigned char buff[EDDSA_KEY_LENGTH];
    int ret = RAND_priv_bytes(buff, EDDSA_KEY_LENGTH);
    if (ret <= 0)
        return connData;

    EVP_PKEY *pKey = EVP_PKEY_new();
    q_check_ptr(pKey);
    pKey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, &buff[0], EDDSA_KEY_LENGTH);

    size_t keySize = EDDSA_KEY_LENGTH;

    // save private key
    unsigned char priv[EDDSA_KEY_LENGTH];
    EVP_PKEY_get_raw_private_key(pKey, priv, &keySize);
    connData.clientPrivKey = QByteArray::fromRawData((char *)priv, keySize).toBase64();

    // save public key
    unsigned char pub[EDDSA_KEY_LENGTH];
    EVP_PKEY_get_raw_public_key(pKey, pub, &keySize);
    connData.clientPubKey = QByteArray::fromRawData((char *)pub, keySize).toBase64();

    return connData;
}

QList<QHostAddress> WireguardConfigurator::getIpsFromConf(const QString &input)
{
    const QRegularExpression regex(QStringLiteral("(?m)^[\\t ]*AllowedIPs[\\t ]*=[\\t ]*([^\\r\\n#]*)"));
    auto matchIterator = regex.globalMatch(input);
    QList<QHostAddress> ips;
    while (matchIterator.hasNext()) {
        const auto routes = matchIterator.next().captured(1).split(',');
        for (const auto &route : routes) {
            const QHostAddress address(route.section('/', 0, 0).trimmed());
            if (address.protocol() == QAbstractSocket::IPv4Protocol) ips << address;
        }
    }

    // Native showconf does not promise peer order. Allocation uses the highest
    // assigned IPv4, rather than the last peer returned by the protocol backend.
    std::sort(ips.begin(), ips.end(), [](const QHostAddress &a, const QHostAddress &b) {
        return a.toIPv4Address() < b.toIPv4Address();
    });
    return ips;
}

QString WireguardConfigurator::pathMtuProbeFromInterfaceConfig(const QString &configuration)
{
    const auto targets = pathMtuProbesFromInterfaceConfig(configuration);
    return targets.isEmpty() ? QString() : targets.first();
}

QStringList WireguardConfigurator::pathMtuProbesFromInterfaceConfig(const QString &configuration)
{
    QString ipv4, ipv6;
    // A server can expose only an IPv6 tunnel address. Use its configured
    // interface address, never an address inferred from a client's AllowedIPs.
    QString section = "[Interface]";
    for (const auto &rawLine : configuration.split('\n')) {
        const auto line = rawLine.section('#', 0, 0).trimmed();
        if (line.startsWith('[')) { section = line; continue; }
        if (section != "[Interface]" || line.section('=', 0, 0).trimmed() != "Address" || !line.contains('=')) continue;
        for (const auto &entry : line.section('=', 1).split(',')) {
            const auto cidr = entry.trimmed();
            const auto subnet = QHostAddress::parseSubnet(cidr);
            const QHostAddress address(cidr.section('/', 0, 0));
            bool mapped = false; address.toIPv4Address(&mapped);
            if (subnet.second < 0 || address.isNull() || address == QHostAddress::AnyIPv4 || address == QHostAddress::AnyIPv6
                || address == QHostAddress::Broadcast || address.isLoopback() || address.isMulticast()
                || address.isLinkLocal() || !address.scopeId().isEmpty()) continue;
            if (address.protocol() == QAbstractSocket::IPv4Protocol && ipv4.isEmpty()) ipv4 = address.toString();
            if (address.protocol() == QAbstractSocket::IPv6Protocol && !mapped && ipv6.isEmpty()) ipv6 = address.toString();
        }
    }
    QStringList targets;
    if (!ipv4.isEmpty()) targets << ipv4;
    if (!ipv6.isEmpty()) targets << ipv6;
    return targets;
}

QString WireguardConfigurator::serverIPv4CidrFromInterfaceConfig(const QString &configuration)
{
    const QRegularExpression interfaceAddress(QStringLiteral("(?:^|\\n)\\s*Address\\s*=\\s*([^\\r\\n]+)"));
    const auto addressMatch = interfaceAddress.match(configuration);
    if (addressMatch.hasMatch()) {
        for (const auto &entry : addressMatch.captured(1).split(',')) {
            QHostAddress address(entry.trimmed().section('/', 0, 0));
            const auto subnet = QHostAddress::parseSubnet(entry.trimmed());
            if (address.protocol() == QAbstractSocket::IPv4Protocol && !address.isNull()
                && address != QHostAddress::AnyIPv4 && !address.isLoopback() && !address.isMulticast()
                && subnet.second >= 0) {
                return address.toString() + "/" + QString::number(subnet.second);
            }
        }
    }

    return {};
}

QString WireguardConfigurator::clientIPv6FromInterfaceConfig(const QString &configuration, const QString &clientIPv4)
{
    const QHostAddress client(clientIPv4);
    if (client.protocol() != QAbstractSocket::IPv4Protocol || client.isNull()) return {};
    const QRegularExpression addressLine(QStringLiteral("(?:^|\\n)\\s*Address\\s*=\\s*([^\\r\\n]+)"));
    const auto match = addressLine.match(configuration);
    if (!match.hasMatch()) return {};
    for (const auto &entry : match.captured(1).split(',')) {
        const auto subnet = QHostAddress::parseSubnet(entry.trimmed());
        const QHostAddress server(entry.trimmed().section('/', 0, 0));
        if (subnet.first.protocol() != QAbstractSocket::IPv6Protocol || subnet.second != 64
            || server.isLoopback() || server.isMulticast() || server.isLinkLocal()
            || server == QHostAddress::AnyIPv6 || !server.scopeId().isEmpty()) continue;
        auto address = subnet.first.toIPv6Address();
        // The existing unique IPv4 allocation maps injectively into this /64.
        // Keep the server's usual ::1 and low host addresses separate.
        address[10] = 0; address[11] = 1;
        const auto ipv4 = client.toIPv4Address();
        for (int i = 0; i < 4; ++i) address[12 + i] = (ipv4 >> (24 - i * 8)) & 255;
        const QHostAddress result(address);
        if (result == server) continue;
        const QRegularExpression allowedLine(QStringLiteral("(?:^|\\n)\\s*AllowedIPs\\s*=\\s*([^\\r\\n]+)"));
        auto peers = allowedLine.globalMatch(configuration);
        bool occupied = false;
        while (peers.hasNext()) {
            for (const auto &entry : peers.next().captured(1).split(',')) {
                const auto existing = QHostAddress::parseSubnet(entry.trimmed());
                if (existing.first.protocol() == QAbstractSocket::IPv6Protocol && result.isInSubnet(existing)) occupied = true;
            }
        }
        if (!occupied) return result.toString();
    }
    return {};
}

QString WireguardConfigurator::serverIPv6CidrFromInterfaceConfig(const QString &configuration)
{
    const QRegularExpression addressLine(QStringLiteral("(?:^|\\n)\\s*Address\\s*=\\s*([^\\r\\n]+)"));
    const auto match = addressLine.match(configuration);
    if (!match.hasMatch()) return {};
    for (const auto &entry : match.captured(1).split(',')) {
        const QHostAddress address(entry.trimmed().section('/', 0, 0));
        const auto subnet = QHostAddress::parseSubnet(entry.trimmed());
        if (address.protocol() == QAbstractSocket::IPv6Protocol && subnet.second == 64
            && address != QHostAddress::AnyIPv6 && !address.isLoopback() && !address.isMulticast()
            && !address.isLinkLocal() && address.scopeId().isEmpty()) return address.toString() + "/64";
    }
    return {};
}

QString WireguardConfigurator::newServerIPv6Address()
{
    const auto random = QRandomGenerator::system()->generate64();
    return QStringLiteral("fd%1:%2:%3::1/64")
        .arg((random >> 32) & 0xff, 2, 16, QLatin1Char('0'))
        .arg((random >> 16) & 0xffff, 4, 16, QLatin1Char('0'))
        .arg(random & 0xffff, 4, 16, QLatin1Char('0'));
}

WireguardConfigurator::ConnectionData WireguardConfigurator::prepareWireguardConfig(const ServerCredentials &credentials,
                                                                                    DockerContainer container,
                                                                                    const WireGuardServerConfig* serverConfig,
                                                                                    const AwgServerConfig* awgServerConfig,
                                                                                    const DnsSettings &dnsSettings,
                                                                                    ErrorCode &errorCode)
{
    const auto serverSettings=serverConfig?serverConfig->toJson():awgServerConfig?awgServerConfig->toJson():QJsonObject{};
    WireguardConfigurator::ConnectionData connData;
    if (!m_pendingPeerExport.isEmpty()) {
        const auto &state=m_pendingPeerExport;
        connData={state.value("clientPrivKey").toString(),state.value("clientPubKey").toString(),
            state.value("clientIP").toString(),state.value("pathMtuProbe").toString(),state.value("clientIPv6").toString(),
            state.value("serverPubKey").toString(),state.value("pskKey").toString(),state.value("host").toString(),state.value("port").toString()};
        const auto original=state.value("expected").toString(), candidate=state.value("candidate").toString();
        connData.pathMtuProbes = pathMtuProbesFromInterfaceConfig(original);
        const auto port=serverConfig && !serverConfig->port.isEmpty()?serverConfig->port:
            awgServerConfig && !awgServerConfig->port.isEmpty()?awgServerConfig->port:m_defaultPort;
        if (state.size()!=16 || state.value("version")!=1
            || state.value("serverSettings")!=serverSettings
            || state.value("container")!=ContainerUtils::containerToString(container)
            || state.value("sshPort")!=credentials.port || state.value("sshUser")!=credentials.userName || original.isEmpty() || original.toUtf8().size()>4*1024*1024
            || candidate.toUtf8().size()>4*1024*1024 || !pendingPeerKeyPair(connData.clientPrivKey,connData.clientPubKey)
            || QHostAddress(connData.clientIP).protocol()!=QAbstractSocket::IPv4Protocol
            || connData.pathMtuProbe!=pathMtuProbeFromInterfaceConfig(original)
            || connData.clientIPv6!=clientIPv6FromInterfaceConfig(original,connData.clientIP)
            || QByteArray::fromBase64(connData.pskKey.toLatin1()).size()!=32
            || QByteArray::fromBase64(connData.serverPubKey.toLatin1()).size()!=32
            || connData.host!=credentials.hostName || connData.port!=port
            || candidate!=pendingPeerCandidate(original,connData)
            || !m_persistPendingPeerExport || !m_persistPendingPeerExport(state)) {
            errorCode=ErrorCode::InternalError; return connData;
        }
        bool handled=false;
        errorCode=m_sshSession->replaceLiveProtocolConfig(container,credentials,original,candidate,handled,true);
        if (errorCode==ErrorCode::NoError && !handled) errorCode=ErrorCode::InternalError;
        return connData;
    }
    connData = WireguardConfigurator::genClientKeys();
    connData.host = credentials.hostName;
    
    QString portStr = m_defaultPort;
    if (serverConfig && !serverConfig->port.isEmpty()) {
        portStr = serverConfig->port;
    } else if (awgServerConfig && !awgServerConfig->port.isEmpty()) {
        portStr = awgServerConfig->port;
    }
    connData.port = portStr;

    if (connData.clientPrivKey.isEmpty() || connData.clientPubKey.isEmpty()) {
        errorCode = ErrorCode::InternalError;
        return connData;
    }

    QString configPath = m_serverConfigPath;
    if (container == DockerContainer::Awg) {
        configPath = amnezia::protocols::awg::serverLegacyConfigPath;
    }
    const auto originalConfig = QString::fromUtf8(m_sshSession->getTextFileFromContainer(container, credentials, configPath, errorCode));
    if (errorCode != ErrorCode::NoError) return connData;
    const auto &stdOut = originalConfig;
    auto ips = getIpsFromConf(stdOut);
    connData.pathMtuProbe = pathMtuProbeFromInterfaceConfig(stdOut);
    connData.pathMtuProbes = pathMtuProbesFromInterfaceConfig(stdOut);

    QHostAddress nextIp = [&] {
        QHostAddress result;
        QHostAddress lastIp;
        QString subnetAddress = protocols::wireguard::defaultSubnetAddress;
        if (serverConfig && !serverConfig->subnetAddress.isEmpty()) {
            subnetAddress = serverConfig->subnetAddress;
        } else if (awgServerConfig && !awgServerConfig->subnetAddress.isEmpty()) {
            subnetAddress = awgServerConfig->subnetAddress;
        }
        if (ips.empty()) {
            lastIp.setAddress(subnetAddress);
        } else {
            lastIp = ips.last();
        }
        quint8 lastOctet = static_cast<quint8>(lastIp.toIPv4Address());
        switch (lastOctet) {
        case 254: result.setAddress(lastIp.toIPv4Address() + 3); break;
        case 255: result.setAddress(lastIp.toIPv4Address() + 2); break;
        default: result.setAddress(lastIp.toIPv4Address() + 1); break;
        }

        return result;
    }();

    connData.clientIP = nextIp.toString();
    connData.clientIPv6 = clientIPv6FromInterfaceConfig(stdOut, connData.clientIP);

    // Get keys
    connData.serverPubKey =
            m_sshSession->getTextFileFromContainer(container, credentials, m_serverPublicKeyPath, errorCode);
    connData.serverPubKey.replace("\n", "");
    if (errorCode != ErrorCode::NoError) {
        return connData;
    }

    connData.pskKey = m_sshSession->getTextFileFromContainer(container, credentials, m_serverPskKeyPath, errorCode);
    connData.pskKey.replace("\n", "");

    if (errorCode != ErrorCode::NoError) {
        return connData;
    }

    // Add client to config
    QString peerAddresses = connData.clientIP + "/32";
    if (!connData.clientIPv6.isEmpty()) peerAddresses += ", " + connData.clientIPv6 + "/128";
    QString configPart = QString("[Peer]\n"
                                 "PublicKey = %1\n"
                                 "PresharedKey = %2\n"
                                 "AllowedIPs = %3\n\n")
                                 .arg(connData.clientPubKey, connData.pskKey, peerAddresses);

    auto candidate = originalConfig;
    if (!candidate.endsWith('\n')) candidate += '\n';
    candidate += configPart;
    if (m_persistPendingPeerExport) {
        const QJsonObject state{{"version",1},{"serverSettings",serverSettings},{"container",ContainerUtils::containerToString(container)},
            {"sshPort",credentials.port},{"sshUser",credentials.userName},{"expected",originalConfig},{"candidate",candidate},
            {"clientPrivKey",connData.clientPrivKey},{"clientPubKey",connData.clientPubKey},{"clientIP",connData.clientIP},
            {"pathMtuProbe",connData.pathMtuProbe},{"clientIPv6",connData.clientIPv6},{"serverPubKey",connData.serverPubKey},
            {"pskKey",connData.pskKey},{"host",connData.host},{"port",connData.port}};
        if (!m_persistPendingPeerExport(state)) { errorCode=ErrorCode::InternalError; return connData; }
        m_pendingPeerExport=state;
    }
    bool transactional = false;
    errorCode = m_sshSession->replaceLiveProtocolConfig(container, credentials, originalConfig, candidate, transactional);
    if (errorCode != ErrorCode::NoError || transactional) return connData;

    errorCode = m_sshSession->uploadTextFileToContainer(container, credentials, configPart, configPath,
                                                              libssh::ScpOverwriteMode::ScpAppendToExisting);

    if (errorCode != ErrorCode::NoError) {
        return connData;
    }

    bool isAwg = (container == DockerContainer::Awg2);
    QString bin = isAwg ? QStringLiteral("awg") : QStringLiteral("wg");
    QString iface = isAwg ? QStringLiteral("awg0") : QStringLiteral("wg0");
    QString script = QString(
        "sudo docker exec -i $CONTAINER_NAME bash -c '%1 syncconf %2 <(%1-quick strip %3)'").arg(bin, iface, configPath);

    errorCode = m_sshSession->runScript(
            credentials,
            m_sshSession->replaceVars(script, amnezia::genBaseVars(credentials, container, dnsSettings.primaryDns, dnsSettings.secondaryDns)));

    return connData;
}

ProtocolConfig WireguardConfigurator::createConfig(const ServerCredentials &credentials, DockerContainer container,
                                                    const ContainerConfig &containerConfig,
                                                    const DnsSettings &dnsSettings,
                                                    ErrorCode &errorCode)
{
    const WireGuardServerConfig* wireguardServerConfig = nullptr;
    const WireGuardClientConfig* wireguardClientConfig = nullptr;
    const AwgServerConfig* awgServerConfig = nullptr;
    const AwgClientConfig* awgClientConfig = nullptr;
    
    if (auto* wireGuardProtocolConfig = containerConfig.getWireGuardProtocolConfig()) {
        wireguardServerConfig = &wireGuardProtocolConfig->serverConfig;
        if (wireGuardProtocolConfig->clientConfig.has_value()) {
            wireguardClientConfig = &wireGuardProtocolConfig->clientConfig.value();
        }
    } else if (auto* awgProtocolConfig = containerConfig.getAwgProtocolConfig()) {
        awgServerConfig = &awgProtocolConfig->serverConfig;
        if (awgProtocolConfig->clientConfig.has_value()) {
            awgClientConfig = &awgProtocolConfig->clientConfig.value();
        }
    }
    
    amnezia::ScriptVars vars = amnezia::genBaseVars(credentials, container, dnsSettings.primaryDns, dnsSettings.secondaryDns);
    vars.append(amnezia::genProtocolVarsForContainer(container, containerConfig));
    QString scriptData = amnezia::scriptData(m_configTemplate, container);
    QString config = m_sshSession->replaceVars(scriptData, vars);

    // The template lists every possible key, but each parameter is optional -
    // drop the lines whose value came out empty
    static const QRegularExpression emptyValueLine(R"(^\s*\S+\s*=\s*$)");
    auto configTemplateLines = config.split("\n");
    configTemplateLines.removeIf([](const QString &line) { return emptyValueLine.match(line).hasMatch(); });
    config = configTemplateLines.join("\n");

    ConnectionData connData = prepareWireguardConfig(credentials, container, wireguardServerConfig, awgServerConfig, dnsSettings, errorCode);
    if (errorCode != ErrorCode::NoError) {
        return WireGuardProtocolConfig{};
    }

    config.replace("$WIREGUARD_CLIENT_PRIVATE_KEY", connData.clientPrivKey);
    if (!connData.clientIPv6.isEmpty())
        config.replace("$WIREGUARD_CLIENT_IP/32", connData.clientIP + "/32, " + connData.clientIPv6 + "/128");
    else config.replace("$WIREGUARD_CLIENT_IP", connData.clientIP);
    config.replace("$WIREGUARD_SERVER_PUBLIC_KEY", connData.serverPubKey);
    config.replace("$WIREGUARD_PSK", connData.pskKey);

    QString mtu = protocols::wireguard::defaultMtu;
    if (wireguardClientConfig && !wireguardClientConfig->mtu.isEmpty()) {
        mtu = wireguardClientConfig->mtu;
    } else if (awgClientConfig && !awgClientConfig->mtu.isEmpty()) {
        mtu = awgClientConfig->mtu;
    }
    
    WireGuardProtocolConfig protocolConfig;
    if (wireguardServerConfig) {
        protocolConfig.serverConfig = *wireguardServerConfig;
    }
    
    WireGuardClientConfig clientConfig;
    clientConfig.nativeConfig = config;
    clientConfig.hostName = connData.host;
    clientConfig.port = connData.port.toInt();
    clientConfig.clientIp = connData.clientIP;
    if (!connData.clientIPv6.isEmpty()) clientConfig.clientIp += "/32, " + connData.clientIPv6 + "/128";
    clientConfig.clientPrivateKey = connData.clientPrivKey;
    clientConfig.clientPublicKey = connData.clientPubKey;
    clientConfig.serverPublicKey = connData.serverPubKey;
    clientConfig.presharedKey = connData.pskKey;
    clientConfig.clientId = connData.clientPubKey;
    clientConfig.allowedIps = QStringList { "0.0.0.0/0", "::/0" };
    const bool useKeepAliveRange = awgServerConfig && awgServerConfig->hasAwg3Params();
    clientConfig.persistentKeepAlive = useKeepAliveRange ? protocols::awg::defaultPersistentKeepAlive
                                                         : protocols::wireguard::defaultPersistentKeepAlive;
    clientConfig.mtu = mtu;
    clientConfig.isObfuscationEnabled = false;
    
    if (connectionUpdates::usablePathProbe(connData.pathMtuProbe, clientConfig.toJson()))
        clientConfig.pathMtuProbe = connData.pathMtuProbe;
    for (const auto &target : connData.pathMtuProbes) {
        if (connectionUpdates::usablePathProbe(target, clientConfig.toJson())) clientConfig.pathMtuProbes.append(target);
    }
    protocolConfig.setClientConfig(clientConfig);
    
    return protocolConfig;
}

ProtocolConfig WireguardConfigurator::processConfigWithLocalSettings(const ConnectionSettings &settings,
                                                                     ProtocolConfig protocolConfig)
{
    return ConfiguratorBase::processConfigWithLocalSettings(settings, protocolConfig);
}

ProtocolConfig WireguardConfigurator::processConfigWithExportSettings(const ExportSettings &settings,
                                                                      ProtocolConfig protocolConfig)
{
    return ConfiguratorBase::processConfigWithExportSettings(settings, protocolConfig);
}
