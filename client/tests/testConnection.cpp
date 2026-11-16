#include <QJsonDocument>
#include <QJsonObject>
#include <QDebug>
#include <QUuid>
#include <QSignalSpy>
#include <QTest>
#include <QHostAddress>
#include <QFile>

#include "utils/testCoreController.h"
#include "utils/testUtils.h"
#include "vpnConnection.h"
#include "secureQSettings.h"
#include "core/utils/utilities.h"
#include "version.h"
#include "core/utils/networkUtilities.h"
#include "core/configurators/openVpnConfigurator.h"
#include "core/utils/selfhosted/scriptsRegistry.h"
#include "core/protocols/openVpnProtocol.h"
#include "core/utils/openVpnIpv6.h"

using namespace amnezia;
using namespace amnezia::test;

class OpenVpnCapabilityReader : public OpenVpnConfigurator {
public:
    OpenVpnCapabilityReader() : OpenVpnConfigurator(nullptr) {}
    int addressReads = 0;
    bool neverReady = false;
    bool failRead = false;
protected:
    QByteArray readCapabilityFile(const ServerCredentials &, DockerContainer, const QString &path, ErrorCode &error) override
    {
        error = failRead ? ErrorCode::SshScpFailureError : ErrorCode::NoError;
        if (failRead) return {};
        if (path.endsWith("server.conf")) return "server-ipv6 fd6e:a81b:704f:1101::/64\n";
        ++addressReads;
        if (neverReady || addressReads < 3) return {}; // Interface has not appeared yet.
        return "fd6ea81b704f11010000000000000001 00000003 40 00 80 tun0\n";
    }
};

#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
class RefreshProtocol : public VpnProtocol {
public:
    RefreshProtocol() : VpnProtocol({}) {}
    bool isConnected() const override { return true; }
    bool periodic = true;
    bool supportsIpv6HostUpdates() const override { return periodic; }
    ErrorCode start() override { return ErrorCode::NoError; }
    void stop() override {}
    int requests = 0;
    QStringList requested;
    std::function<void(bool)> completion;
    void addResolvedIpv6Hosts(const QStringList &hosts, bool, std::function<void(bool)> done) override
    { ++requests; requested = hosts; completion = std::move(done); }
};
class RefreshConnection : public VpnConnection {
public:
    using VpnConnection::VpnConnection;
    using VpnConnection::refreshIpv6Sites;
    using VpnConnection::rememberOpenVpnIpv6Capability;
    void attach(const QSharedPointer<VpnProtocol> &protocol) { m_vpnProtocol = protocol; }
    QList<std::function<void(const QHostInfo &)>> lookups;
    int lookupSiteAddresses(const QString &, std::function<void(const QHostInfo &)> done) override
    { lookups.append(std::move(done)); return -1; }
};
#endif

class TestConnection : public QObject
{
    Q_OBJECT

private:
    TestCoreController* m_coreController;
    SecureQSettings* m_settings;

private slots:
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
    void openVpnIpv6RefreshWaitsForRouteAck()
    {
        SecureQSettings settings("IPv6-Refresh-" + QUuid::createUuid().toString(), "test", nullptr, false);
        SecureServersRepository servers(&settings);
        SecureAppSettingsRepository app(&settings);
        app.setRouteMode(RouteMode::VpnOnlyForwardSites);
        app.setSitesSplitTunnelingEnabled(true);
        app.addVpnSite(RouteMode::VpnOnlyForwardSites, "rotation.test", {"2001:db8::10"});
        const auto protocol = QSharedPointer<RefreshProtocol>::create();
        RefreshConnection connection(&servers, &app);
        connection.attach(protocol);
        connection.setConnectionState(Vpn::ConnectionState::Connected);
        auto *timer = connection.findChild<QTimer *>("ipv6SiteRefresh");
        QVERIFY(timer); QCOMPARE(timer->interval(), 30000); QVERIFY(timer->isActive());
        timer->setInterval(1);
        QTRY_COMPARE(connection.lookups.size(), 1);
        timer->stop();
        connection.refreshIpv6Sites();
        QCOMPARE(connection.lookups.size(), 1); // One in-flight batch.
        QHostInfo answer;
        answer.setAddresses({QHostAddress("2001:db8::20"), QHostAddress("192.0.2.20")});
        connection.lookups.takeFirst()(answer);
        QCOMPARE(protocol->requested, QStringList{"2001:db8::20"});
        const auto cached = [&] { return SecureAppSettingsRepository::siteIpList(app.vpnSites(RouteMode::VpnOnlyForwardSites).value("rotation.test")); };
        QVERIFY(!cached().contains("2001:db8::20"));
        protocol->completion(false);
        QVERIFY(!cached().contains("2001:db8::20"));
        connection.refreshIpv6Sites();
        QCOMPARE(connection.lookups.size(), 1);
        connection.lookups.takeFirst()(answer);
        protocol->completion(true);
        QVERIFY(cached().contains("2001:db8::20"));
        QVERIFY(!cached().contains("192.0.2.20")); // IPv6 refresh never changes IPv4 routing/cache.
        connection.refreshIpv6Sites();
        answer.setAddresses({QHostAddress("2001:db8::30")});
        connection.lookups.takeFirst()(answer);
        connection.setConnectionState(Vpn::ConnectionState::Disconnected);
        QVERIFY(!timer->isActive());
        protocol->completion(true);
        QVERIFY(!cached().contains("2001:db8::30")); // Ignore an ACK from the stopped session.
        connection.refreshIpv6Sites();
        QVERIFY(connection.lookups.isEmpty());
        // Connected must not cancel the initial lookup of a backend without polling.
        protocol->periodic = false;
        connection.addSitesRoutes({}, RouteMode::VpnOnlyForwardSites, true);
        QCOMPARE(connection.lookups.size(), 1);
        const int before = protocol->requests;
        connection.setConnectionState(Vpn::ConnectionState::Connected);
        QVERIFY(!timer->isActive());
        connection.lookups.takeFirst()(answer);
        QCOMPARE(protocol->requests, before + 1);
        protocol->completion(false);
        settings.clearSettings();
    }
#endif
    void openVpnDualStackPushPreservesIpv4Gateway()
    {
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
        OpenVpnProtocol protocol({});
        protocol.updateVpnGateway("PUSH: Received control message: 'PUSH_REPLY,ifconfig 10.8.0.6 10.8.0.5,ifconfig-ipv6 fd00::2/64 fd00::1,peer-id 0'");
        QCOMPARE(protocol.vpnLocalAddress(), QString("10.8.0.6"));
        QCOMPARE(protocol.vpnGateway(), QString("10.8.0.5"));
        QVERIFY(protocol.serverAssignedIpv6());
        protocol.updateVpnGateway("PUSH: Received control message: 'PUSH_REPLY,ifconfig-ipv6 fd00::3/64 fd00::1'");
        QCOMPARE(protocol.vpnLocalAddress(), QString("10.8.0.6"));
        QCOMPARE(protocol.vpnGateway(), QString("10.8.0.5"));
        protocol.updateVpnGateway("PUSH: Received control message: 'PUSH_REPLY,ifconfig 10.8.0.8 255.255.255.0'");
        QCOMPARE(protocol.vpnLocalAddress(), QString("10.8.0.8"));
        QCOMPARE(protocol.vpnGateway(), QString("255.255.255.0"));
        protocol.updateVpnGateway("PUSH: Received control message: 'PUSH_REPLY,ifconfig-ipv6 not-a-subnet fd00::1'");
        QVERIFY(!protocol.serverAssignedIpv6());
        protocol.updateVpnGateway("PUSH: Received control message: 'PUSH_REPLY,ifconfig not-an-address 10.8.0.1'");
        QCOMPARE(protocol.vpnLocalAddress(), QString("10.8.0.8"));
        QCOMPARE(protocol.vpnGateway(), QString("255.255.255.0"));
#else
        QSKIP("Desktop management parser; Linux avoids native driver setup in this fixture");
#endif
    }
    void openVpnLearnsCapabilityWithoutReplacingImportedIdentity()
    {
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
        SecureQSettings settings("OpenVPN-Capability-" + QUuid::createUuid().toString(), "test", nullptr, false);
        SecureServersRepository servers(&settings);
        SecureAppSettingsRepository app(&settings);
        RefreshConnection connection(&servers, &app);
        OpenVpnProtocolConfig profile;
        OpenVpnClientConfig client;
        client.clientId = "existing-client";
        client.nativeConfig = "client\n<key>\nKEEP-PRIVATE-KEY\n</key>\n";
        const auto pushLog = qEnvironmentVariable("AMNEZIA_OPENVPN_PUSH_LOG");
        if (!pushLog.isEmpty()) {
            QFile log(pushLog);
            QVERIFY(log.open(QIODevice::ReadOnly));
            QVERIFY(log.size() < 4 * 1024 * 1024);
            OpenVpnProtocol observed({});
            for (const auto &line : QString::fromUtf8(log.readAll()).split('\n'))
                if (line.contains("PUSH: Received control message:")) observed.updateVpnGateway(line);
            QVERIFY(observed.serverAssignedIpv6());
            QVERIFY(QHostAddress(observed.vpnLocalAddress()).protocol() == QAbstractSocket::IPv4Protocol);
            QFile native(qEnvironmentVariable("AMNEZIA_OPENVPN_CLIENT_PROFILE"));
            QVERIFY(native.open(QIODevice::ReadOnly));
            client.nativeConfig = QString::fromUtf8(native.readAll());
        }
        profile.setClientConfig(client);
        ContainerConfig container;
        container.container = DockerContainer::OpenVpn;
        container.protocolConfig = profile;
        for (auto kind : {serverConfigUtils::ConfigType::Native, serverConfigUtils::ConfigType::SelfHostedUser,
                          serverConfigUtils::ConfigType::SelfHostedAdmin, serverConfigUtils::ConfigType::AmneziaPremiumV2,
                          serverConfigUtils::ConfigType::AmneziaFreeV3, serverConfigUtils::ConfigType::ExternalPremium}) {
            NativeServerConfig base;
            base.hostName = "unchanged.test";
            base.defaultContainer = DockerContainer::OpenVpn;
            base.containers[DockerContainer::OpenVpn] = container;
            base.containers[DockerContainer::OpenVpn].protocolConfig.as<OpenVpnProtocolConfig>()->serverConfig.isThirdPartyConfig = kind == serverConfigUtils::ConfigType::Native;
            QJsonObject initial = base.toJson();
            if (kind == serverConfigUtils::ConfigType::SelfHostedUser) initial = SelfHostedUserServerConfig::fromJson(initial).toJson();
            if (kind == serverConfigUtils::ConfigType::SelfHostedAdmin) {
                auto admin = SelfHostedAdminServerConfig::fromJson(initial);
                admin.userName = "fixture"; admin.password = "fixture-only"; admin.port = 22;
                initial = admin.toJson();
            }
            const bool apiKind = kind == serverConfigUtils::ConfigType::AmneziaPremiumV2
                || kind == serverConfigUtils::ConfigType::AmneziaFreeV3 || kind == serverConfigUtils::ConfigType::ExternalPremium;
            if (apiKind) {
                auto api = ApiV2ServerConfig::fromJson(initial);
                api.configVersion = serverConfigUtils::ConfigSource::AmneziaGateway;
                api.crc = 42;
                api.apiConfig.serviceType = kind == serverConfigUtils::ConfigType::AmneziaPremiumV2 ? "amnezia-premium"
                    : kind == serverConfigUtils::ConfigType::AmneziaFreeV3 ? "amnezia-free" : "external-premium";
                api.apiConfig.serviceProtocol = "openvpn";
                api.apiConfig.vpnKey = "KEEP-PROVIDER-KEY";
                api.authData.apiKey = "KEEP-PROVIDER-AUTH";
                initial = api.toJson();
            }
            initial["opaque_root_extension"] = "KEEP-ROOT";
            auto rawContainers = initial.value(configKey::containers).toArray();
            auto rawContainer = rawContainers[0].toObject();
            rawContainer["opaque_container_extension"] = "KEEP-CONTAINER";
            auto rawProtocol = rawContainer.value("openvpn").toObject();
            auto rawClient = QJsonDocument::fromJson(rawProtocol.value(configKey::lastConfig).toString().toUtf8()).object();
            rawClient.remove("ipv6Tunnel"); // Old profiles need not contain the field.
            rawClient["opaque_client_extension"] = "KEEP-CLIENT";
            rawProtocol[configKey::lastConfig] = QString::fromUtf8(QJsonDocument(rawClient).toJson());
            rawContainer["openvpn"] = rawProtocol;
            rawContainers[0] = rawContainer;
            initial[configKey::containers] = rawContainers;
            const auto id = servers.addServer(QUuid::createUuid().toString(), initial, kind);
            QVERIFY(servers.serverJsonById(id).has_value());
            const auto before = *servers.serverJsonById(id);
            QSignalSpy edits(&servers, &SecureServersRepository::serverCapabilityObserved);
            QSignalSpy runtimeEdits(&servers, &SecureServersRepository::serverEdited);
            connection.rememberOpenVpnIpv6Capability(id, before);
            QCOMPARE(edits.count(), 1);
            QCOMPARE(runtimeEdits.count(), 0); // Must not restart the owner's local Xray proxy.
            auto verify = [&](auto config) {
                QVERIFY(config.has_value());
                const auto learned = config->containerConfig(DockerContainer::OpenVpn).protocolConfig;
                const auto *openvpn = learned.template as<OpenVpnProtocolConfig>();
                QVERIFY(openvpn && openvpn->clientConfig);
                QVERIFY(openvpn->clientConfig->ipv6Tunnel);
                QCOMPARE(openvpn->clientConfig->nativeConfig, client.nativeConfig);
                QCOMPARE(openvpn->clientConfig->clientId, client.clientId);
            };
            if (kind == serverConfigUtils::ConfigType::Native) verify(servers.nativeConfig(id));
            if (kind == serverConfigUtils::ConfigType::SelfHostedUser) verify(servers.selfHostedUserConfig(id));
            if (kind == serverConfigUtils::ConfigType::SelfHostedAdmin) verify(servers.selfHostedAdminConfig(id));
            if (apiKind) {
                verify(servers.apiV2Config(id));
                auto original = ApiV2ServerConfig::fromJson(before);
                const auto learned = servers.apiV2Config(id);
                QVERIFY(learned.has_value());
                original.containers = learned->containers;
                QCOMPARE(original.toJson(), learned->toJson()); // Provider metadata/auth/CRC unchanged.
            }
            const auto after = *servers.serverJsonById(id);
            QCOMPARE(after.value("opaque_root_extension").toString(), QString("KEEP-ROOT"));
            const auto savedContainer = after.value(configKey::containers).toArray()[0].toObject();
            QCOMPARE(savedContainer.value("opaque_container_extension").toString(), QString("KEEP-CONTAINER"));
            const auto savedClient = QJsonDocument::fromJson(savedContainer.value("openvpn").toObject()
                .value(configKey::lastConfig).toString().toUtf8()).object();
            QCOMPARE(savedClient.value("opaque_client_extension").toString(), QString("KEEP-CLIENT"));
            connection.rememberOpenVpnIpv6Capability(id, before); // Stale generation.
            connection.rememberOpenVpnIpv6Capability(id, after); // Already recorded.
            QCOMPARE(edits.count(), 1);
            QCOMPARE(*servers.serverJsonById(id), after);
            QCOMPARE(runtimeEdits.count(), 0);
        }
        settings.clearSettings();
#else
        QSKIP("Desktop cached-profile capability learning");
#endif
    }
    void ipsecServerResourcesArePackaged()
    {
        QFile image(":/server_scripts/ipsec/Dockerfile");
        QVERIFY(image.open(QIODevice::ReadOnly));
        const auto dockerfile = image.readAll();
        QVERIFY(dockerfile.contains("FROM hwdsl2/ipsec-vpn-server@sha256:"));
        QVERIFY(dockerfile.contains("\"dumb-init\", \"/opt/amnezia/start.sh\""));
        QVERIFY(dockerfile.contains("CMD []")); // Never inherit the identity-generating installer.
        QFile helper(":/server_scripts/ipsec/enable_ipv6.sh");
        QVERIFY(helper.open(QIODevice::ReadOnly));
        QVERIFY(!helper.readAll().isEmpty());
        QFile updater(":/server_scripts/update_ipsec.sh");
        QVERIFY(updater.open(QIODevice::ReadOnly));
        QVERIFY(updater.readAll().contains("amnezia_update="));
        for (const auto type : {ProtocolScriptType::configure_container, ProtocolScriptType::container_startup,
                                ProtocolScriptType::run_container}) {
            const auto script = scriptData(type, DockerContainer::Ipsec);
            QVERIFY(!script.isEmpty());
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
            QProcess syntax;
            syntax.start("bash", {"-n"});
            QVERIFY(syntax.waitForStarted(3000));
            syntax.write(script.toUtf8());
            syntax.closeWriteChannel();
            QVERIFY(syntax.waitForFinished(3000));
            QVERIFY2(syntax.exitCode() == 0, syntax.readAllStandardError().constData());
#endif
        }
    }
    void openVpnCapabilityWaitsForTunnel()
    {
        OpenVpnProtocolConfig original;
        OpenVpnClientConfig client;
        client.clientId = "existing-client";
        client.nativeConfig = "client\n<key>\nKEEP-THIS-KEY\n</key>\n";
        original.setClientConfig(client);
        ProtocolConfig cached = original;
        OpenVpnCapabilityReader reader;
        QCOMPARE(reader.refreshIpv6Capability({}, DockerContainer::OpenVpn, cached, true), ErrorCode::NoError);
        QCOMPARE(reader.addressReads, 3);
        original.clientConfig->ipv6Tunnel = true;
        QCOMPARE(cached.toJson(), ProtocolConfig(original).toJson());
        const auto before = cached.toJson();
        reader.neverReady = true;
        reader.addressReads = 0;
        QCOMPARE(reader.refreshIpv6Capability({}, DockerContainer::OpenVpn, cached, true), ErrorCode::ProtocolUpdateOutcomeUnknown);
        QVERIFY(reader.addressReads > 1 && reader.addressReads <= 22);
        QCOMPARE(cached.toJson(), before);
        reader.failRead = true;
        QCOMPARE(reader.refreshIpv6Capability({}, DockerContainer::OpenVpn, cached, true), ErrorCode::SshScpFailureError);
        QCOMPARE(cached.toJson(), before);
    }
    void openVpnIpv6ProfileAndExport()
    {
        const auto startup = scriptData(ProtocolScriptType::container_startup, DockerContainer::OpenVpn);
        QVERIFY(startup.contains("amnezia_prepare_openvpn_ipv6()"));
        QVERIFY(startup.contains("amnezia_prepare_openvpn_ipv6 /opt/amnezia/openvpn/server.conf"));
        QVERIFY(NetworkUtilities::checkIpSubnetFormat("fd00::/8"));
        QVERIFY(NetworkUtilities::checkIpSubnetFormat("64:ff9b::/96"));
        QVERIFY(NetworkUtilities::checkIpSubnetFormat("2001:db8::1"));
        QVERIFY(!NetworkUtilities::checkIpSubnetFormat("::/129"));
        QVERIFY(!NetworkUtilities::checkIpSubnetFormat("fe80::1%eth0/64"));
        OpenVpnProtocolConfig profile;
        OpenVpnClientConfig client;
        client.nativeConfig = "client\nremote 198.51.100.1 1194\n";
        client.ipv6Tunnel = true;
        profile.setClientConfig(client);
        profile = OpenVpnProtocolConfig::fromJson(profile.toJson());
        QVERIFY(profile.clientConfig->ipv6Tunnel);
        OpenVpnConfigurator configurator(nullptr);
        auto legacy = profile;
        legacy.clientConfig->ipv6Tunnel = false;
        legacy.clientConfig->clientId = "existing-client";
        legacy.clientConfig->nativeConfig += "<key>\nUNCHANGED-PRIVATE-KEY\n</key>\n";
        ProtocolConfig cached = legacy;
        auto refreshed = legacy;
        refreshed.clientConfig->ipv6Tunnel = true;
        OpenVpnConfigurator::applyObservedIpv6Capability(cached,
            "server-ipv6 fd6e:a81b:704f:1101::/64\n",
            "fd6ea81b704f11010000000000000001 00000003 40 00 80 tun0\n");
        QCOMPARE(cached.toJson(), ProtocolConfig(refreshed).toJson());
        QVERIFY(!OpenVpnConfigurator::applyObservedIpv6Capability(cached,
            "server-ipv6 fd6e:a81b:704f:1101::/64\n", ""));
        QCOMPARE(cached.toJson(), ProtocolConfig(refreshed).toJson());
        OpenVpnConfigurator::applyObservedIpv6Capability(cached, "server 10.66.0.0 255.255.255.0\n", "");
        QCOMPARE(cached.toJson(), ProtocolConfig(legacy).toJson());
        QVERIFY(configurator.refreshIpv6Capability({}, DockerContainer::OpenVpn, cached) != ErrorCode::NoError);
        QCOMPARE(cached.toJson(), ProtocolConfig(legacy).toJson());
        ConnectionSettings settings{{"1.1.1.1", "8.8.8.8"}, false, {false, RouteMode::VpnAllSites, {}}};
        const auto captured = [](const QString &config, const QString &ip) {
            for (const auto &line : config.split('\n')) {
                const auto fields = line.simplified().split(' ');
                if (fields.size() >= 2 && fields[0] == "route-ipv6"
                    && QHostAddress(ip).isInSubnet(QHostAddress::parseSubnet(fields[1]))) return true;
            }
            return false;
        };
        auto config = configurator.processConfigWithLocalSettings(settings, profile).nativeConfig();
        QVERIFY(!config.contains("block-ipv6"));
        QVERIFY(captured(config, "fd12::1"));
        QVERIFY(captured(config, "64:ff9b::c000:201"));
        const auto storedProfile = profile.toJson();
        for (const auto mode : {RouteMode::VpnAllSites, RouteMode::VpnOnlyForwardSites, RouteMode::VpnAllExceptSites}) {
            auto disabled = settings;
            disabled.ipv6Enabled = false;
            disabled.splitTunneling = {true, mode, {"fd99::/16"}};
            for (bool api : {false, true}) {
                disabled.isApiConfig = api;
                const auto blocked = configurator.processConfigWithLocalSettings(disabled, profile).nativeConfig();
                QVERIFY(blocked.contains("block-ipv6"));
                QVERIFY(captured(blocked, "fd99::4"));
                QVERIFY(captured(blocked, "2001:db8::4"));
                QCOMPARE(profile.toJson(), storedProfile); // OFF is local, not a server-capability rewrite.
            }
        }
        config = configurator.processConfigWithExportSettings({settings.dns}, profile).nativeConfig();
        QVERIFY(!config.contains("block-ipv6"));
        QVERIFY(captured(config, "2001:db8::1"));
        QVERIFY(captured(config, "fd12::1"));
        QJsonObject policies{{"full", config}};
        const auto exportedClient = OpenVpnClientConfig::fromJson({{configKey::config, config}});
        QVERIFY(exportedClient.ipv6Tunnel);
        profile.setClientConfig(exportedClient);
        settings.splitTunneling = {true, RouteMode::VpnOnlyForwardSites, {"fd00::/8", "192.0.2.0/24"}};
        config = configurator.processConfigWithLocalSettings(settings, profile).nativeConfig();
        QVERIFY(captured(config, "fd12::1"));
        QVERIFY(!captured(config, "2001:db8::1"));
        policies["include"] = config;
        settings.splitTunneling.routeMode = RouteMode::VpnAllExceptSites;
        settings.splitTunneling.siteRoutes = {"fd99::4/128", "192.0.2.0/24"};
        config = configurator.processConfigWithLocalSettings(settings, profile).nativeConfig();
        QVERIFY(!captured(config, "fd99::4"));
        QVERIFY(captured(config, "fd99::5"));
        QVERIFY(captured(config, "2001:db8::1"));
        QVERIFY(!config.contains("redirect-gateway ipv6"));
        policies["exclude"] = config;
        client.ipv6Tunnel = false;
        profile.setClientConfig(client);
        settings.splitTunneling.isSitesSplitTunnelingEnabled = false;
        config = configurator.processConfigWithLocalSettings(settings, profile).nativeConfig();
        QVERIFY(config.contains("block-ipv6"));
        QVERIFY(config.contains("ifconfig-ipv6 "));
        QVERIFY(config.contains("setenv opt disable-dco"));
        QVERIFY(captured(config, "fd88::1"));
        QVERIFY(captured(config, "64:ff9b::c000:201"));
        policies["legacy-full"] = config;
        config = configurator.processConfigWithExportSettings({settings.dns}, profile).nativeConfig();
        QVERIFY(config.contains("block-ipv6"));
        policies["legacy-export"] = config;
        auto apiClient = client;
        apiClient.nativeConfig += "redirect-gateway def1 bypass-dhcp\nroute 192.0.2.0 255.255.255.0\n";
        profile.setClientConfig(apiClient);
        auto apiSettings = settings;
        apiSettings.isApiConfig = true;
        const auto apiConfig = configurator.processConfigWithLocalSettings(apiSettings, profile).nativeConfig();
        QVERIFY(apiConfig.contains("redirect-gateway def1 bypass-dhcp"));
        QVERIFY(apiConfig.contains("route 192.0.2.0 255.255.255.0"));
        QVERIFY(apiConfig.contains("block-ipv6"));
        QVERIFY(apiConfig.contains("ifconfig-ipv6 "));
        QVERIFY(captured(apiConfig, "fd88::1"));
        QVERIFY(captured(apiConfig, "64:ff9b::c000:201"));
        policies["legacy-api"] = apiConfig;
        apiClient.ipv6Tunnel = true;
        profile.setClientConfig(apiClient);
        const auto apiIpv6Config = configurator.processConfigWithLocalSettings(apiSettings, profile).nativeConfig();
        QVERIFY(!apiIpv6Config.contains("block-ipv6"));
        QVERIFY(!apiIpv6Config.contains("fd15:53b6:dead"));
        QVERIFY(apiIpv6Config.contains("redirect-gateway def1 bypass-dhcp"));
        QVERIFY(captured(apiIpv6Config, "fd88::1"));
        QVERIFY(captured(apiIpv6Config, "64:ff9b::c000:201"));
        policies["api-full"] = apiIpv6Config;
        const auto blockedImport = OpenVpnClientConfig::fromJson({{configKey::config, config}});
        QVERIFY(!blockedImport.ipv6Tunnel);
        auto upgraded = blockedImport;
        upgraded.ipv6Tunnel = true;
        profile.setClientConfig(upgraded);
        const auto upgradedConfig = configurator.processConfigWithLocalSettings(settings, profile).nativeConfig();
        QVERIFY(!upgradedConfig.contains("fd15:53b6:dead"));
        QVERIFY(!upgradedConfig.contains("block-ipv6"));
        QVERIFY(!upgradedConfig.contains("disable-dco"));
        QVERIFY(captured(upgradedConfig, "fd88::1"));
        profile.setClientConfig(blockedImport);
        config = configurator.processConfigWithLocalSettings(settings, profile).nativeConfig();
        QCOMPARE(config.count("ifconfig-ipv6 "), 1);
        QCOMPARE(config.count("# amnezia-ipv6-block-begin"), 1);
        settings.splitTunneling = {true, RouteMode::VpnOnlyForwardSites, {"fd00::/8", "192.0.2.0/24"}};
        config = configurator.processConfigWithLocalSettings(settings, profile).nativeConfig();
        QVERIFY(captured(config, "fd88::1"));
        QVERIFY(!captured(config, "2001:db8:88::1"));
        policies["legacy-include"] = config;
        settings.splitTunneling.routeMode = RouteMode::VpnAllExceptSites;
        settings.splitTunneling.siteRoutes = {"fd99::4/128", "192.0.2.0/24"};
        config = configurator.processConfigWithLocalSettings(settings, profile).nativeConfig();
        QVERIFY(!captured(config, "fd99::4"));
        QVERIFY(captured(config, "fd99::5"));
        QVERIFY(captured(config, "2001:db8:88::1"));
        QVERIFY(!config.contains("redirect-gateway ipv6"));
        policies["legacy-exclude"] = config;
        auto explicitConfig = client;
        explicitConfig.nativeConfig += "ifconfig-ipv6 fd77::2/64 fd77::1\nblock-ipv6\n<key>\nUNCHANGED-KEY\n</key>\n";
        profile.setClientConfig(explicitConfig);
        config = configurator.processConfigWithLocalSettings(settings, profile).nativeConfig();
        QVERIFY(!config.contains("fd15:53b6:dead"));
        QVERIFY(config.contains("ifconfig-ipv6 fd77::2/64 fd77::1"));
        QVERIFY(config.contains("UNCHANGED-KEY"));
        explicitConfig = OpenVpnClientConfig::fromJson({{configKey::config, config}});
        explicitConfig.ipv6Tunnel = true;
        profile.setClientConfig(explicitConfig);
        config = configurator.processConfigWithLocalSettings(settings, profile).nativeConfig();
        QVERIFY(config.contains("block-ipv6")); // Explicit administrator policy survives.
        QVERIFY(config.contains("ifconfig-ipv6 fd77::2/64 fd77::1"));
        const auto fixturePath = qEnvironmentVariable("AMNEZIA_OPENVPN_POLICY_FIXTURE");
        if (!fixturePath.isEmpty()) {
            QFile file(fixturePath);
            QVERIFY(file.open(QIODevice::WriteOnly));
            const auto bytes = QJsonDocument(policies).toJson();
            QCOMPARE(file.write(bytes), qint64(bytes.size()));
        }
        const auto builderFixturePath = qEnvironmentVariable("AMNEZIA_OPENVPN_TUN_BUILDER_FIXTURE");
        QJsonObject builderPolicies;
        for (auto it = policies.constBegin(); it != policies.constEnd(); ++it) {
            QStringList lines;
            for (const auto &line : openVpnIpv6::forTunBuilder(it.value().toString()).split('\n')) {
                const auto trimmed = line.trimmed();
                if (trimmed.isEmpty() || trimmed.startsWith("up ") || trimmed.startsWith("down ")
                    || trimmed.startsWith("script-security ")) continue; // Desktop-only hooks.
                lines.append(trimmed);
            }
            builderPolicies[it.key()] = lines.join('\n') + '\n';
        }
        QFile builderGolden(QFINDTESTDATA("data/openvpn-tun-builder-policies.json"));
        QVERIFY(builderGolden.open(QIODevice::ReadOnly));
        const auto expectedBuilderPolicies = QJsonDocument::fromJson(builderGolden.readAll()).object();
        if (!builderFixturePath.isEmpty()) {
            QFile file(builderFixturePath);
            QVERIFY(file.open(QIODevice::WriteOnly));
            const auto bytes = QJsonDocument(builderPolicies).toJson();
            QCOMPARE(file.write(bytes), qint64(bytes.size()));
        }
        QCOMPARE(builderPolicies, expectedBuilderPolicies);
        QVERIFY(!OpenVpnClientConfig::fromJson({}).ipv6Tunnel);
    }
    void openVpnTunBuilderIpv6Compatibility()
    {
        const QString credentials = "<key>\nUNCHANGED-PRIVATE-KEY\n</key>\n";
        const QString explicitConfig = "client\nifconfig-ipv6 fd77::2/64 fd77::1\n" + credentials;
        QCOMPARE(openVpnIpv6::forTunBuilder(explicitConfig), explicitConfig);
        const QString base = "client\n" + credentials;
        for (const auto mode : {RouteMode::VpnAllSites, RouteMode::VpnOnlyForwardSites, RouteMode::VpnAllExceptSites}) {
            const auto fallback = openVpnIpv6::blockingDirectives(base, mode, {"fd00::/8"}, {"fd55::53"});
            const QString address = "ifconfig-ipv6 fd15:53b6:dead::2/64 fd15:53b6:dead::1\n";
            QVERIFY(fallback.contains(address));
            const auto result = openVpnIpv6::forTunBuilder(base + fallback);
            auto expected = base + fallback;
            expected.remove(address);
            QCOMPARE(result, expected); // Only the owned address may change.
            QCOMPARE(openVpnIpv6::forTunBuilder(result), result);
            QVERIFY(result.contains("block-ipv6\n"));
            QVERIFY(!OpenVpnClientConfig::fromJson({{configKey::config, result}}).ipv6Tunnel);
            // Explicit administrator configuration outside the owned block is retained.
            QCOMPARE(openVpnIpv6::forTunBuilder(explicitConfig + fallback), explicitConfig + expected.mid(base.size()));
        }
    }
    void initTestCase() {
        QString testOrg = "AmneziaVPN-Test-" + QUuid::createUuid().toString();
        m_settings = new SecureQSettings(testOrg, "amnezia-client", nullptr, false);

        auto vpnConnection = QSharedPointer<VpnConnection>::create(nullptr, nullptr);

        m_coreController = new TestCoreController(vpnConnection, m_settings, nullptr, this);
    }

    void cleanupTestCase() {
        m_settings->clearSettings();
        delete m_coreController;
        delete m_settings;
    }

    void init() {
        m_settings->clearSettings();
        m_coreController->m_serversRepository->invalidateCache();
        if (m_coreController->m_serversModel) {
            m_coreController->m_serversModel->updateModel(QVector<ServerDescription>(), "");
        }
    }

    void testConnect() {
        QString awgKey = getEnvValue("THIRD_PARTY_AWG_VPN_KEY");
        QString xrayKey = getEnvValue("THIRD_PARTY_XRAY_VPN_KEY");
        QString wgKey = getEnvValue("THIRD_PARTY_WIRE_GUARD_VPN_KEY");
        QString ovpnKey = getEnvValue("THIRD_PARTY_OPEN_VPN_KEY");
        QString ikevKey = getEnvValue("THIRD_PARTY_IKEV_VPN_KEY");

        logEnvValueState("THIRD_PARTY_AWG_VPN_KEY");
        logEnvValueState("THIRD_PARTY_XRAY_VPN_KEY");
        logEnvValueState("THIRD_PARTY_WIRE_GUARD_VPN_KEY");
        logEnvValueState("THIRD_PARTY_OPEN_VPN_KEY");
        logEnvValueState("THIRD_PARTY_IKEV_VPN_KEY");

        // toggleConnection() silently refuses to emit prepareConfig when the
        // AmneziaVPN service process is not running (isConnectionSupported returns
        // AmneziaServiceNotRunning), so this test needs an installed client.
        if (!Utils::processIsRunning(Utils::executable(SERVICE_NAME, false), true)) {
            QSKIP("AmneziaVPN service is not running - connection flow cannot be tested");
        }

        QSignalSpy prepareConfigSpy(m_coreController->m_connectionUiController, &ConnectionUiController::prepareConfig);

        auto importResult0 = m_coreController->m_importCoreController->extractConfigFromData(awgKey);
        if (importResult0.errorCode == ErrorCode::NoError) {
            m_coreController->m_importCoreController->importConfig(importResult0.config);

            m_coreController->m_connectionUiController->toggleConnection();
            QVERIFY2(prepareConfigSpy.count() == 1, "prepareConfig signal should be emitted once");

            m_coreController->m_connectionUiController->toggleConnection();
            QVERIFY2(m_coreController->m_connectionUiController->isConnected() == false, "Connection should NOT be active");
        } else {
            qWarning() << "Error on AWG key import";
        }

        auto importResult1 = m_coreController->m_importCoreController->extractConfigFromData(xrayKey);
        if (importResult1.errorCode == ErrorCode::NoError) {
            m_coreController->m_importCoreController->importConfig(importResult1.config);

            m_coreController->m_connectionUiController->toggleConnection();
            QVERIFY2(prepareConfigSpy.count() == 3, "prepareConfig signal should be emitted three times");

            m_coreController->m_connectionUiController->toggleConnection();
            QVERIFY2(m_coreController->m_connectionUiController->isConnected() == false, "Connection should NOT be active");
        } else {
            qWarning() << "Error on XRay key import";
        }

        auto importResult2 = m_coreController->m_importCoreController->extractConfigFromData(wgKey);
        if (importResult2.errorCode == ErrorCode::NoError) {
            m_coreController->m_importCoreController->importConfig(importResult2.config);

            m_coreController->m_connectionUiController->toggleConnection();
            QVERIFY2(prepareConfigSpy.count() == 5, "prepareConfig signal should be emitted five times");

            m_coreController->m_connectionUiController->toggleConnection();
            QVERIFY2(m_coreController->m_connectionUiController->isConnected() == false, "Connection should NOT be active");
        } else {
            qWarning() << "Error on WG key import";
        }

        auto importResult3 = m_coreController->m_importCoreController->extractConfigFromData(ovpnKey);
        if (importResult3.errorCode == ErrorCode::NoError) {
            m_coreController->m_importCoreController->importConfig(importResult3.config);

            m_coreController->m_connectionUiController->toggleConnection();
            QVERIFY2(prepareConfigSpy.count() == 7, "prepareConfig signal should be emitted seven times");

            m_coreController->m_connectionUiController->toggleConnection();
            QVERIFY2(m_coreController->m_connectionUiController->isConnected() == false, "Connection should NOT be active");
        } else {
            qWarning() << "Error on OpenVPN key import";
        }

        auto importResult4 = m_coreController->m_importCoreController->extractConfigFromData(ikevKey);
        if (importResult4.errorCode == ErrorCode::NoError) {
            m_coreController->m_importCoreController->importConfig(importResult4.config);

            m_coreController->m_connectionUiController->toggleConnection();
            QVERIFY2(prepareConfigSpy.count() == 9, "prepareConfig signal should be emitted nine times");

            m_coreController->m_connectionUiController->toggleConnection();
            QVERIFY2(m_coreController->m_connectionUiController->isConnected() == false, "Connection should NOT be active");
        }
        else {
            qWarning() << "Error on IKEV key import";
        }
    }
};

QTEST_MAIN(TestConnection)
#include "testConnection.moc"
