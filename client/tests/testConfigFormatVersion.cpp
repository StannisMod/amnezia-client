#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSignalSpy>
#include <QSet>
#include <QTest>
#include <QUuid>

#include "utils/testCoreController.h"
#include "core/models/api/apiV2ServerConfig.h"
#include "core/models/selfhosted/nativeServerConfig.h"
#include "core/models/selfhosted/selfHostedAdminServerConfig.h"
#include "core/models/selfhosted/selfHostedUserServerConfig.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/serverConfigUtils.h"
#include "secureQSettings.h"
#include "vpnConnection.h"
#include "core/configurators/wireguardConfigurator.h"
#include "core/models/protocols/wireGuardProtocolConfig.h"
#include "core/models/protocols/awgProtocolConfig.h"
#include "core/utils/selfhosted/scriptsRegistry.h"

using namespace amnezia;

namespace
{
    QJsonObject adminConfigJson(const QString &hostName, int formatVersion = -1)
    {
        QJsonObject json;
        json[configKey::hostName] = hostName;
        json[configKey::userName] = QStringLiteral("root");
        json[configKey::password] = QStringLiteral("secret");
        json[configKey::port] = 22;
        json[configKey::description] = QStringLiteral("Server ") + hostName;
        if (formatVersion >= 0) {
            json[configKey::formatVersion] = formatVersion;
        }
        return json;
    }

    QByteArray serversListBytes(const QList<QJsonObject> &configs)
    {
        QJsonArray array;
        for (const QJsonObject &config : configs) {
            array.append(config);
        }
        return QJsonDocument(array).toJson();
    }
} // namespace

class TestConfigFormatVersion : public QObject
{
    Q_OBJECT

private:
    TestCoreController *m_coreController = nullptr;
    SecureQSettings *m_settings = nullptr;

private slots:
    void testServerIPv6PrefixPersistsWithoutInventingLegacyAddresses()
    {
        QSet<QString> prefixes;
        for (int i = 0; i < 32; ++i) {
            const auto address = WireguardConfigurator::newServerIPv6Address();
            const auto subnet = QHostAddress::parseSubnet(address);
            QCOMPARE(subnet.second, 64);
            QVERIFY((subnet.first.toIPv6Address()[0] & 0xfe) == 0xfc);
            QVERIFY(!prefixes.contains(address)); prefixes.insert(address);
        }
        const auto address = *prefixes.begin();
        WireGuardServerConfig wg; wg.ipv6Address = address;
        const auto restoredWg = WireGuardServerConfig::fromJson(wg.toJson());
        QCOMPARE(restoredWg.ipv6Address, address); QVERIFY(wg.hasEqualServerSettings(restoredWg));
        auto changedWg = restoredWg; changedWg.ipv6Address.clear(); QVERIFY(!wg.hasEqualServerSettings(changedWg));
        AwgServerConfig awg; awg.ipv6Address = address;
        const auto restoredAwg = AwgServerConfig::fromJson(awg.toJson());
        QCOMPARE(restoredAwg.ipv6Address, address); QVERIFY(awg.hasEqualServerSettings(restoredAwg));
        QVERIFY(WireGuardServerConfig::fromJson({}).ipv6Address.isEmpty());
        QVERIFY(AwgServerConfig::fromJson({}).ipv6Address.isEmpty());
        QCOMPARE(WireguardConfigurator::serverIPv6CidrFromInterfaceConfig("Address = 10.77.0.1/24, fd77::1/64\n"), QString("fd77::1/64"));
        QVERIFY(WireguardConfigurator::serverIPv6CidrFromInterfaceConfig("Address = 10.77.0.1/24\n").isEmpty());
    }
    void testIPv6PreparationIsPackagedForAWGAndWG()
    {
        for (const auto container : {DockerContainer::Awg, DockerContainer::Awg2, DockerContainer::WireGuard}) {
            const auto script = scriptData(ProtocolScriptType::run_container, container);
            QVERIFY(script.contains("AMNEZIA_IPV6_NETWORK_STATUS"));
            QVERIFY(script.contains("--ipv4=false"));
            QVERIFY(script.contains("sudo docker network connect \"$AMNEZIA_IPV6_NETWORK\""));
            const auto startup = scriptData(ProtocolScriptType::container_startup, container);
            QVERIFY(startup.startsWith("#!/bin/bash\n"));
            QVERIFY(startup.contains("amnezia_enable_ipv6()"));
            QVERIFY(startup.contains("AMNEZIA_IPV6_FORWARDING_STATUS"));
        }
        QVERIFY(!scriptData(ProtocolScriptType::run_container, DockerContainer::OpenVpn).contains("AMNEZIA_IPV6_NETWORK_STATUS"));
    }
    void testIPv6ScriptAddressIsCanonical()
    {
        WireGuardProtocolConfig protocol;
        protocol.serverConfig.ipv6Address = "fd77::1/64";
        ContainerConfig container; container.protocolConfig = protocol;
        auto variables = genWireGuardVars(container);
        QVERIFY(variables.contains(qMakePair(QString("$WIREGUARD_IPV6_ADDRESS"), QString("fd77::1/64"))));
        protocol.serverConfig.ipv6Address = "fd77::1/64\";$(untrusted)";
        container.protocolConfig = protocol;
        variables = genWireGuardVars(container);
        QVERIFY(variables.contains(qMakePair(QString("$WIREGUARD_IPV6_ADDRESS"), QString())));
    }
    void testClientIPv6AllocationUsesExplicitServerPrefix()
    {
        const auto configuration = QString("Address = 10.8.1.0/24, fd77:1234:5678:9::1/64\n");
        const auto first = WireguardConfigurator::clientIPv6FromInterfaceConfig(configuration, "10.8.1.2");
        const auto second = WireguardConfigurator::clientIPv6FromInterfaceConfig(configuration, "10.8.1.3");
        QCOMPARE(QHostAddress(first), QHostAddress("fd77:1234:5678:9:0:1:a08:102"));
        QVERIFY(first != second);
        QVERIFY(WireguardConfigurator::clientIPv6FromInterfaceConfig(configuration + "AllowedIPs = " + first + "/128\n", "10.8.1.2").isEmpty());
        QCOMPARE(first, WireguardConfigurator::clientIPv6FromInterfaceConfig(configuration, "10.8.1.2"));
        QVERIFY(WireguardConfigurator::clientIPv6FromInterfaceConfig("Address = 10.8.1.0/24", "10.8.1.2").isEmpty());
        QVERIFY(WireguardConfigurator::clientIPv6FromInterfaceConfig("Address = fd77::1/128", "10.8.1.2").isEmpty());
        QVERIFY(WireguardConfigurator::clientIPv6FromInterfaceConfig("Address = fe80::1/64", "10.8.1.2").isEmpty());
        QVERIFY(WireguardConfigurator::clientIPv6FromInterfaceConfig(configuration, "fd77::2").isEmpty());
    }
    void testPathMtuProbeUsesExplicitServerAddress()
    {
        QCOMPARE(WireguardConfigurator::pathMtuProbeFromInterfaceConfig("Address = 10.8.1.0/24\nAllowedIPs = 10.8.1.2/32"), QString("10.8.1.0"));
        QCOMPARE(WireguardConfigurator::pathMtuProbeFromInterfaceConfig("Address = fd77::1/64, 10.77.0.9/24\n"), QString("10.77.0.9"));
        QVERIFY(WireguardConfigurator::pathMtuProbeFromInterfaceConfig("AllowedIPs = 10.77.0.2/32\n").isEmpty());
        QVERIFY(WireguardConfigurator::pathMtuProbeFromInterfaceConfig("Address = fd77::1/64\n").isEmpty());
        QVERIFY(WireguardConfigurator::pathMtuProbeFromInterfaceConfig("Address = 127.0.0.1/8\n").isEmpty());
        WireGuardClientConfig wg; wg.pathMtuProbe = "10.77.0.9";
        QCOMPARE(WireGuardClientConfig::fromJson(wg.toJson()).pathMtuProbe, wg.pathMtuProbe);
        AwgClientConfig awg; awg.pathMtuProbe = wg.pathMtuProbe;
        QCOMPARE(AwgClientConfig::fromJson(awg.toJson()).pathMtuProbe, awg.pathMtuProbe);
        QVERIFY(WireGuardClientConfig::fromJson({}).pathMtuProbe.isEmpty());
        QVERIFY(AwgClientConfig::fromJson({}).pathMtuProbe.isEmpty());
    }
    void testDualStackServerAddressKeepsIPv4HostAndMask()
    {
        QCOMPARE(WireguardConfigurator::serverIPv4CidrFromInterfaceConfig("Address = fd77::1/64, 10.77.0.9/20\n"), QString("10.77.0.9/20"));
        QCOMPARE(WireguardConfigurator::serverIPv4CidrFromInterfaceConfig("Address = 10.77.0.9/32, fd77::1/64\n"), QString("10.77.0.9/32"));
        QVERIFY(WireguardConfigurator::serverIPv4CidrFromInterfaceConfig("Address = 0.0.0.0/24\n").isEmpty());
        QVERIFY(WireguardConfigurator::serverIPv4CidrFromInterfaceConfig("Address = fd77::1/64\n").isEmpty());
        QVERIFY(WireguardConfigurator::serverIPv4CidrFromInterfaceConfig("Address = 10.77.0.9/99\n").isEmpty());
    }
    void initTestCase()
    {
        const QString testOrg = "AmneziaVPN-Test-" + QUuid::createUuid().toString();
        m_settings = new SecureQSettings(testOrg, "amnezia-client", nullptr, false);
        auto vpnConnection = QSharedPointer<VpnConnection>::create(nullptr, nullptr);
        m_coreController = new TestCoreController(vpnConnection, m_settings, nullptr, this);
    }

    void cleanupTestCase()
    {
        m_settings->clearSettings();
        delete m_coreController;
        delete m_settings;
    }

    void init()
    {
        m_settings->clearSettings();
        m_coreController->m_serversRepository->invalidateCache();
    }

    void testVersionCheckHelpers()
    {
        QCOMPARE(serverConfigUtils::configFormatVersion(QJsonObject()), 0);
        QVERIFY(serverConfigUtils::isConfigFormatVersionSupported(QJsonObject()));
        QVERIFY(serverConfigUtils::isConfigFormatVersionSupported(
                adminConfigJson("1.1.1.1", serverConfigUtils::currentConfigFormatVersion)));
        QVERIFY(!serverConfigUtils::isConfigFormatVersionSupported(
                adminConfigJson("1.1.1.1", serverConfigUtils::currentConfigFormatVersion + 1)));
    }

    void testToJsonWritesCurrentFormatVersion()
    {
        SelfHostedAdminServerConfig admin;
        admin.hostName = "1.1.1.1";
        QCOMPARE(admin.toJson().value(configKey::formatVersion).toInt(-1), serverConfigUtils::currentConfigFormatVersion);

        SelfHostedUserServerConfig user;
        user.hostName = "1.1.1.1";
        QCOMPARE(user.toJson().value(configKey::formatVersion).toInt(-1), serverConfigUtils::currentConfigFormatVersion);

        NativeServerConfig native;
        native.hostName = "1.1.1.1";
        QCOMPARE(native.toJson().value(configKey::formatVersion).toInt(-1), serverConfigUtils::currentConfigFormatVersion);

        ApiV2ServerConfig api;
        api.hostName = "1.1.1.1";
        QCOMPARE(api.toJson().value(configKey::formatVersion).toInt(-1), serverConfigUtils::currentConfigFormatVersion);
    }

    void testImportAcceptsMissingAndCurrentVersion()
    {
        auto *importController = m_coreController->m_importCoreController;
        QSignalSpy importFinishedSpy(importController, &ImportController::importFinished);

        const QString withoutVersion = QJsonDocument(adminConfigJson("1.1.1.1")).toJson();
        auto result = importController->extractConfigFromData(withoutVersion);
        QCOMPARE(result.errorCode, ErrorCode::NoError);
        importController->importConfig(result.config);

        const QString currentVersion =
                QJsonDocument(adminConfigJson("2.2.2.2", serverConfigUtils::currentConfigFormatVersion)).toJson();
        result = importController->extractConfigFromData(currentVersion);
        QCOMPARE(result.errorCode, ErrorCode::NoError);
        importController->importConfig(result.config);

        QCOMPARE(importFinishedSpy.count(), 2);
        QCOMPARE(m_coreController->m_serversRepository->serversCount(), 2);

        const auto stored = m_coreController->m_serversRepository->selfHostedAdminConfig(
                m_coreController->m_serversRepository->serverIdAt(0));
        QVERIFY(stored.has_value());
        QCOMPARE(stored->toJson().value(configKey::formatVersion).toInt(-1), serverConfigUtils::currentConfigFormatVersion);
    }

    void testImportRejectsNewerVersion()
    {
        auto *importController = m_coreController->m_importCoreController;
        QSignalSpy importFinishedSpy(importController, &ImportController::importFinished);
        QSignalSpy importErrorSpy(importController, &ImportController::importErrorOccurred);

        const QJsonObject newer = adminConfigJson("3.3.3.3", serverConfigUtils::currentConfigFormatVersion + 1);
        const QByteArray newerBytes = QJsonDocument(newer).toJson();

        auto result = importController->extractConfigFromData(QString::fromUtf8(newerBytes));
        QCOMPARE(result.errorCode, ErrorCode::ConfigFormatVersionNotSupportedError);
        QVERIFY(result.config.isEmpty());

        const QString vpnUrl = "vpn://"
                + QString::fromUtf8(qCompress(newerBytes, 8).toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
        result = importController->extractConfigFromData(vpnUrl);
        QCOMPARE(result.errorCode, ErrorCode::ConfigFormatVersionNotSupportedError);
        QVERIFY(result.config.isEmpty());

        result = importController->extractConfigFromQr(newerBytes);
        QCOMPARE(result.errorCode, ErrorCode::ConfigFormatVersionNotSupportedError);
        QVERIFY(result.config.isEmpty());

        importController->importConfig(newer);
        QCOMPARE(importErrorSpy.count(), 1);
        QCOMPARE(importErrorSpy.first().at(0).value<ErrorCode>(), ErrorCode::ConfigFormatVersionNotSupportedError);
        QCOMPARE(importFinishedSpy.count(), 0);
        QCOMPARE(m_coreController->m_serversRepository->serversCount(), 0);
    }

    void testRepositorySkipsNewerVersionOnLoad()
    {
        m_settings->setValue("Servers/serversList",
                             serversListBytes({ adminConfigJson("1.1.1.1"),
                                                adminConfigJson("2.2.2.2", serverConfigUtils::currentConfigFormatVersion + 1),
                                                adminConfigJson("3.3.3.3", serverConfigUtils::currentConfigFormatVersion) }));
        m_coreController->m_serversRepository->invalidateCache();

        QCOMPARE(m_coreController->m_serversRepository->serversCount(), 2);
        QCOMPARE(m_coreController->m_serversRepository->unsupportedFormatConfigsCount(), 1);

        const auto rejected = m_coreController->m_serversRepository->addServer(
                QString(), adminConfigJson("4.4.4.4", serverConfigUtils::currentConfigFormatVersion + 1),
                serverConfigUtils::ConfigType::SelfHostedAdmin);
        QVERIFY(!rejected.isEmpty());
        QCOMPARE(m_coreController->m_serversRepository->serversCount(), 2);
    }

    void testRestoreBackupReportsSkippedConfigs()
    {
        QJsonObject backup;
        backup["Servers/serversList"] = QString::fromUtf8(serversListBytes(
                { adminConfigJson("1.1.1.1"),
                  adminConfigJson("2.2.2.2", serverConfigUtils::currentConfigFormatVersion + 1) }));

        QSignalSpy errorSpy(m_coreController->m_settingsUiController, &SettingsUiController::errorOccurred);
        QSignalSpy restoredSpy(m_coreController->m_settingsUiController, &SettingsUiController::restoreBackupFinished);

        m_coreController->m_settingsUiController->restoreAppConfigFromData(QJsonDocument(backup).toJson());

        QCOMPARE(restoredSpy.count(), 1);
        QCOMPARE(errorSpy.count(), 1);
        QCOMPARE(errorSpy.first().at(0).value<ErrorCode>(), ErrorCode::RestoreBackupUnsupportedConfigsSkipped);
        QCOMPARE(m_coreController->m_serversRepository->serversCount(), 1);

        errorSpy.clear();
        restoredSpy.clear();
        QJsonObject cleanBackup;
        cleanBackup["Servers/serversList"] = QString::fromUtf8(serversListBytes({ adminConfigJson("5.5.5.5") }));
        m_coreController->m_settingsUiController->restoreAppConfigFromData(QJsonDocument(cleanBackup).toJson());
        QCOMPARE(restoredSpy.count(), 1);
        QCOMPARE(errorSpy.count(), 0);
    }
};

QTEST_MAIN(TestConfigFormatVersion)
#include "testConfigFormatVersion.moc"
