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

using namespace amnezia;
using namespace amnezia::test;

#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
class RefreshProtocol : public VpnProtocol {
public:
    RefreshProtocol() : VpnProtocol({}) {}
    bool isConnected() const override { return true; }
    bool supportsIpv6HostUpdates() const override { return true; }
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
        settings.clearSettings();
    }
#endif
    void openVpnIpv6ProfileAndExport()
    {
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
        config = configurator.processConfigWithLocalSettings(settings, profile).nativeConfig();
        QVERIFY(!captured(config, "fd12::1"));
        QVERIFY(captured(config, "2001:db8::1"));
        QVERIFY(!config.contains("redirect-gateway ipv6"));
        policies["exclude"] = config;
        const auto fixturePath = qEnvironmentVariable("AMNEZIA_OPENVPN_POLICY_FIXTURE");
        if (!fixturePath.isEmpty()) {
            QFile file(fixturePath);
            QVERIFY(file.open(QIODevice::WriteOnly));
            const auto bytes = QJsonDocument(policies).toJson();
            QCOMPARE(file.write(bytes), qint64(bytes.size()));
        }
        client.ipv6Tunnel = false;
        profile.setClientConfig(client);
        settings.splitTunneling.isSitesSplitTunnelingEnabled = false;
        QVERIFY(configurator.processConfigWithLocalSettings(settings, profile).nativeConfig().contains("block-ipv6"));
        QVERIFY(configurator.processConfigWithExportSettings({settings.dns}, profile).nativeConfig().contains("block-ipv6"));
        QVERIFY(!OpenVpnClientConfig::fromJson({}).ipv6Tunnel);
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
