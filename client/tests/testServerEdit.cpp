#include <QJsonDocument>
#include <QJsonObject>
#include <QUuid>
#include <QSignalSpy>
#include <QTest>
#include <QTcpServer>
#include <QTcpSocket>
#include <QThreadPool>

#include "utils/testCoreController.h"
#include "core/models/serverDescription.h"
#include "ui/models/serversModel.h"
#include "utils/testUtils.h"
#include "vpnConnection.h"
#include "secureQSettings.h"
#include "core/controllers/connectionController.h"

using namespace amnezia;
using namespace amnezia::test;

class TestServerEdit : public QObject
{
    Q_OBJECT

private:
    TestCoreController* m_coreController;
    SecureQSettings* m_settings;

private slots:
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
            m_coreController->m_serversModel->updateModel(QVector<ServerDescription>(), QString{});
        }
    }

    void testVpnDomainPreservesSshAndRoundTrips() {
        SelfHostedAdminServerConfig config = SelfHostedAdminServerConfig::fromJson({
            {configKey::hostName, "192.0.2.10"}, {configKey::userName, "root"},
            {configKey::password, "test-secret"}, {configKey::port, 22}
        });
        config.defaultContainer = DockerContainer::Awg2;
        AwgProtocolConfig awg;
        AwgClientConfig client{};
        client.hostName = config.hostName;
        client.port = 51820;
        client.clientPrivateKey = "PRIVATE";
        client.serverPublicKey = "PUBLIC";
        client.presharedKey = "PSK";
        client.nativeConfig = "[Interface]\nPrivateKey = PRIVATE\n[Peer]\nPublicKey = PUBLIC\nEndpoint = 192.0.2.10:51820\n";
        awg.setClientConfig(client);
        ContainerConfig container;
        container.container = config.defaultContainer;
        container.protocolConfig = awg;
        config.containers[config.defaultContainer] = container;
        auto *repository = m_coreController->m_serversRepository;
        const QString id = repository->addServer("domain-test", config.toJson(), serverConfigUtils::ConfigType::SelfHostedAdmin);
        auto *servers = m_coreController->m_serversController;
        QVERIFY(servers->setVpnHostName(id, " VPN.Example.org "));
        const auto saved = repository->selfHostedAdminConfig(id);
        QVERIFY(saved.has_value());
        QCOMPARE(saved->credentials().hostName, "192.0.2.10");
        QCOMPARE(saved->vpnHostName, "vpn.example.org");
        // Endpoint edits must not replace keys or mutate cached client profiles.
        QCOMPARE(saved->containerConfig(config.defaultContainer).protocolConfig.getClientConfigJson().value(configKey::hostName).toString(), "192.0.2.10");

        VpnConnection vpn(repository, m_coreController->m_appSettingsRepository);
        ConnectionController connections(repository, m_coreController->m_appSettingsRepository, &vpn);
        QJsonObject prepared;
        DockerContainer selected = DockerContainer::None;
        QCOMPARE(connections.prepareConnection(id, prepared, selected), ErrorCode::NoError);
        QCOMPARE(prepared.value(configKey::hostName).toString(), "vpn.example.org");
        const auto data = prepared.value(ProtocolUtils::key_proto_config_data(Proto::Awg)).toObject();
        QCOMPARE(data.value(configKey::hostName).toString(), "vpn.example.org");
        QCOMPARE(data.value(configKey::clientPrivKey).toString(), "PRIVATE");
        QVERIFY(data.value(configKey::config).toString().contains("Endpoint = vpn.example.org:51820"));

        const auto exported = m_coreController->m_exportController->generateFullAccessConfig(id);
        QCOMPARE(exported.errorCode, ErrorCode::NoError);
        const auto imported = m_coreController->m_importCoreController->extractConfigFromData(exported.config);
        QCOMPARE(imported.errorCode, ErrorCode::NoError);
        const auto restored = SelfHostedAdminServerConfig::fromJson(imported.config);
        QCOMPARE(restored.hostName, "192.0.2.10");
        QCOMPARE(restored.vpnHostName, "vpn.example.org");

        QVERIFY(!servers->setVpnHostName(id, "https://wrong.example.org/path"));
        QCOMPARE(servers->vpnHostName(id), "vpn.example.org");
        QVERIFY(servers->setVpnHostName(id, ""));
        QCOMPARE(connections.prepareConnection(id, prepared, selected), ErrorCode::NoError);
        QCOMPARE(prepared.value(configKey::hostName).toString(), "192.0.2.10");
    }

    void testSoftwareUpdateWithSingleGlobalWorker() {
        QTcpServer endpoint;
        QVERIFY(endpoint.listen(QHostAddress::LocalHost));
        bool reachedSsh = false;
        connect(&endpoint, &QTcpServer::newConnection, &endpoint, [&]() {
            reachedSsh = true;
            while (endpoint.hasPendingConnections()) {
                auto *socket = endpoint.nextPendingConnection();
                socket->abort(); // Fail SSH before authentication or commands.
                socket->deleteLater();
            }
        });
        SelfHostedAdminServerConfig config = SelfHostedAdminServerConfig::fromJson({
            {configKey::hostName, "127.0.0.1"}, {configKey::userName, "test"},
            {configKey::password, "test-only"}, {configKey::port, endpoint.serverPort()}
        });
        config.defaultContainer = DockerContainer::WireGuard;
        ContainerConfig container;
        container.container = config.defaultContainer;
        container.protocolConfig = WireGuardProtocolConfig{};
        config.containers[config.defaultContainer] = container;
        const QString id = m_coreController->m_serversRepository->addServer(
                "software-update-pool-test", config.toJson(), serverConfigUtils::ConfigType::SelfHostedAdmin);
        auto *controller = m_coreController->m_installUiController;
        qRegisterMetaType<ErrorCode>();
        QSignalSpy error(controller, &InstallUiController::installationErrorOccurred);
        QSignalSpy busy(controller, &InstallUiController::serverIsBusy);
        QVERIFY(error.isValid());
        QVERIFY(busy.isValid());
        auto *globalPool = QThreadPool::globalInstance();
        const int originalLimit = globalPool->maxThreadCount();
        globalPool->setMaxThreadCount(1);
        controller->updateProtocolSoftware(id, static_cast<int>(config.defaultContainer));
        const bool completed = !error.isEmpty() || error.wait(3000);
        // Drain a regressed implementation before asserting, so a blocked
        // global worker cannot hang cleanup or the remaining test cases.
        globalPool->setMaxThreadCount(qMax(2, originalLimit));
        if (!completed) {
            error.wait(3000);
        }
        globalPool->setMaxThreadCount(originalLimit);
        QVERIFY2(completed, "Software update deadlocked Qt's single-worker global pool");
        QVERIFY(reachedSsh);
        QCOMPARE(error.count(), 1);
        QVERIFY(error.at(0).at(0).toInt() != static_cast<int>(ErrorCode::NoError));
        QCOMPARE(busy.count(), 2);
        QCOMPARE(busy.at(0).at(0).toBool(), true);
        QCOMPARE(busy.at(1).at(0).toBool(), false);
    }

    void testServerEditTriggersHandlers() {
        QString awgKey = getEnvValue("THIRD_PARTY_AWG_VPN_KEY");

        if (!isEnvValueConfigured(awgKey)) {
            QSKIP("Set THIRD_PARTY_AWG_VPN_KEY");
        }

        QSignalSpy importFinishedSpy(m_coreController->m_importCoreController, &ImportController::importFinished);
        auto importResult = m_coreController->m_importCoreController->extractConfigFromData(awgKey);
        m_coreController->m_importCoreController->importConfig(importResult.config);
        QVERIFY2(importFinishedSpy.count() == 1, "Import should succeed");

        QSignalSpy serverEditedSpy(m_coreController->m_serversRepository, &SecureServersRepository::serverEdited);

        QVERIFY(m_coreController->m_serversController->renameServer(
            m_coreController->m_serversController->getServerId(0), QStringLiteral("Edited AWG Server")));

        QVERIFY2(serverEditedSpy.count() == 1, "serverEdited signal should be emitted");
        QVERIFY2(serverEditedSpy.at(0).at(0).toString() == m_coreController->m_serversRepository->serverIdAt(0),
                 "serverEdited should emit edited server id");

        const auto editedDescription = serverDescription(m_coreController->m_serversRepository,
                                                         m_coreController->m_serversRepository->serverIdAt(0));
        QVERIFY2(editedDescription.has_value(), "Server config should exist");
        QVERIFY2(*editedDescription == "Edited AWG Server", "Server description should be updated");

        if (m_coreController->m_serversModel) {
            QString modelDesc = m_coreController->m_serversModel->data(m_coreController->m_serversModel->index(0, 0), ServersModel::NameRole).toString();
            QVERIFY2(modelDesc == "Edited AWG Server", "Server description in model should be updated");
        }
    }

    void testServerEditPreservesDefault() {
        QString awgKey = getEnvValue("THIRD_PARTY_AWG_VPN_KEY");
        QString xrayKey = getEnvValue("THIRD_PARTY_XRAY_VPN_KEY");

        if (!isEnvValueConfigured(awgKey) || !isEnvValueConfigured(xrayKey)) {
            QSKIP("Set THIRD_PARTY_AWG_VPN_KEY and THIRD_PARTY_XRAY_VPN_KEY");
        }

        auto importResult1 = m_coreController->m_importCoreController->extractConfigFromData(awgKey);
        m_coreController->m_importCoreController->importConfig(importResult1.config);
        auto importResult2 = m_coreController->m_importCoreController->extractConfigFromData(xrayKey);
        m_coreController->m_importCoreController->importConfig(importResult2.config);

        QVERIFY2(m_coreController->m_serversRepository->defaultServerIndex() == 1, "Default server should be index 1");

        QSignalSpy defaultServerChangedSpy(m_coreController->m_serversRepository, &SecureServersRepository::defaultServerChanged);

        QVERIFY(m_coreController->m_serversController->renameServer(
            m_coreController->m_serversController->getServerId(1), QStringLiteral("Edited Default Server")));

        QVERIFY2(defaultServerChangedSpy.count() == 0, "defaultServerChanged should NOT be emitted when editing default server");
        QVERIFY2(m_coreController->m_serversRepository->defaultServerIndex() == 1, "Default server index should remain 1");

        QVERIFY(m_coreController->m_serversController->renameServer(
            m_coreController->m_serversController->getServerId(0), QStringLiteral("Edited Non-Default Server")));

        QVERIFY2(defaultServerChangedSpy.count() == 0, "defaultServerChanged should NOT be emitted when editing non-default server");
        QVERIFY2(m_coreController->m_serversRepository->defaultServerIndex() == 1, "Default server index should remain 1");
    }
};

QTEST_MAIN(TestServerEdit)
#include "testServerEdit.moc"

