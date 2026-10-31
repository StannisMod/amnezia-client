#include <QCoreApplication>
#include <QDebug>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcessEnvironment>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QUuid>
#include <QTest>

#include "utils/testCoreController.h"
#include "core/models/serverDescription.h"
#include "secureQSettings.h"
#include "vpnConnection.h"

using namespace amnezia;

class TestUiAppSTModelAndController : public QObject
{
    Q_OBJECT

private:
    TestCoreController *m_coreController;
    SecureQSettings *m_settings;

private slots:
    void initTestCase()
    {
        QString testOrg = "AmneziaVPN-Test-" + QUuid::createUuid().toString();
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
        if (m_coreController->m_serversModel) {
            m_coreController->m_serversModel->updateModel(QVector<ServerDescription>(), QString{});
        }
    }

    void testApplicationModesKeepSeparateLists()
    {
        auto ui = m_coreController->m_appSplitTunnelingUiController;
        auto model = m_coreController->m_appSplitTunnelingModel;
        auto repo = m_coreController->m_appSettingsRepository;
        auto core = m_coreController->m_appSplitTunnelingController;
        core->setRouteMode(AppsRouteMode::VpnAllExceptApps);
        core->clearAppsList();
        core->setRouteMode(AppsRouteMode::VpnOnlyForwardApps);
        core->clearAppsList();
        const auto executable = QCoreApplication::applicationFilePath();
        ui->addApp(executable);
        QCOMPARE(model->rowCount(), 1);
        ui->setRouteMode(static_cast<int>(AppsRouteMode::VpnAllExceptApps));
        QCOMPARE(model->rowCount(), 0);
        ui->setRouteMode(static_cast<int>(AppsRouteMode::VpnOnlyForwardApps));
        QCOMPARE(model->rowCount(), 1);
        QCOMPARE(repo->vpnApps(AppsRouteMode::VpnOnlyForwardApps).first().appPath, executable);
        QVERIFY(repo->vpnApps(AppsRouteMode::VpnAllExceptApps).isEmpty());
        core->clearAppsList();
    }

    void testRestoreApplicationScope()
    {
#if defined(Q_OS_WIN) || (defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID))
        auto repo = m_coreController->m_appSettingsRepository;
        auto ui = m_coreController->m_appSplitTunnelingUiController;
        repo->setSingBoxRoutingEnabled(true);
        ui->setRouteMode(static_cast<int>(AppsRouteMode::VpnOnlyForwardApps));
        m_coreController->m_appSplitTunnelingController->clearAppsList();
        ui->addApp(QCoreApplication::applicationFilePath());
        ui->toggleSplitTunneling(true);
        const auto backup = m_coreController->m_settingsController->backupAppConfig();
        ui->setRouteMode(static_cast<int>(AppsRouteMode::VpnAllExceptApps));
        ui->toggleSplitTunneling(false);
        QSignalSpy modeSpy(ui, &AppSplitTunnelingUiController::routeModeChanged);
        QCOMPARE(m_coreController->m_settingsController->restoreAppConfigFromData(backup), ErrorCode::NoError);
        QVERIFY(!modeSpy.isEmpty());
        QCOMPARE(ui->getRouteMode(), static_cast<int>(AppsRouteMode::VpnOnlyForwardApps));
        QVERIFY(ui->isSplitTunnelingEnabled());
        QCOMPARE(m_coreController->m_appSplitTunnelingModel->rowCount(), 1);
        m_coreController->m_appSplitTunnelingController->clearAppsList();
#endif
    }

    void testUnsupportedLegacyScopeRejectedBeforeConnect()
    {
#if defined(Q_OS_WIN) || (defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID))
        auto repo = m_coreController->m_appSettingsRepository;
        repo->setAppsSplitTunnelingEnabled(true);
        repo->setAppsRouteMode(AppsRouteMode::VpnOnlyForwardApps);
        repo->setVpnApps(AppsRouteMode::VpnOnlyForwardApps,
            {InstalledAppInfo{ "test", "", QCoreApplication::applicationFilePath() }});
        auto connection = QSharedPointer<VpnConnection>::create(nullptr, nullptr);
        connection->setRepositories(m_coreController->m_serversRepository, repo);
        QSignalSpy errorSpy(connection.data(), &VpnConnection::vpnProtocolError);
        connection->connectToVpn("test", DockerContainer::OpenVpn, {});
        QCOMPARE(errorSpy.count(), 1);
        QCOMPARE(errorSpy.first().first().value<ErrorCode>(), ErrorCode::NotSupportedOnThisPlatform);
        QCOMPARE(connection->connectionState(), Vpn::ConnectionState::Error);
#endif
    }

    void testRolesAndSignals()
    {
        QSignalSpy finishedSpy(m_coreController->m_appSplitTunnelingUiController, &AppSplitTunnelingUiController::finished);
        QSignalSpy errorOccurredSpy(m_coreController->m_appSplitTunnelingUiController, &AppSplitTunnelingUiController::errorOccurred);
        QSignalSpy isSplitTunnelingChangedSpy(m_coreController->m_appSplitTunnelingUiController, &AppSplitTunnelingUiController::isSplitTunnelingEnabledChanged);

        m_coreController->m_appSplitTunnelingUiController->toggleSplitTunneling(true);
        QVERIFY2(isSplitTunnelingChangedSpy.count() == 1, "isSplitTunnelingChangedSpy signal should be emitted");
        QVERIFY2(m_coreController->m_appSplitTunnelingUiController->isSplitTunnelingEnabled() == true, "AppSplitTunneling should be enabled");

        m_coreController->m_appSplitTunnelingUiController->toggleSplitTunneling(false);
        QVERIFY2(isSplitTunnelingChangedSpy.count() == 2, "isSplitTunnelingChangedSpy signal should be emitted 2nd time");
        QVERIFY2(m_coreController->m_appSplitTunnelingUiController->isSplitTunnelingEnabled() == false, "AppSplitTunneling should be disabled");

        const QString app = QCoreApplication::applicationFilePath();

        m_coreController->m_appSplitTunnelingUiController->addApp(app);
        m_coreController->m_appSplitTunnelingUiController->updateModel();
        QVERIFY2(finishedSpy.count() == 1, "finished signal should be emitted");
        QVERIFY2(m_coreController->m_appSplitTunnelingModel->rowCount() == 1, "AppSplitTunnelingModel should have 1 row");

        QModelIndex appSTModelIndex = m_coreController->m_appSplitTunnelingModel->index(0, 0);
        QVERIFY2(appSTModelIndex.isValid(), "Site model index should be valid");

        auto appPath = m_coreController->m_appSplitTunnelingModel->data(appSTModelIndex, AppSplitTunnelingModel::AppPathRole);
        QString msg = QString("app path should be %1, got %2").arg(app, appPath.toString());
        QVERIFY2(app.contains(appPath.toString()) == true, msg.toLocal8Bit().constData());

        auto pkgAppName = m_coreController->m_appSplitTunnelingModel->data(appSTModelIndex, AppSplitTunnelingModel::PackageAppNameRole);
        QVERIFY2(pkgAppName == true, "app name should be set");

        auto pkgAppIcon = m_coreController->m_appSplitTunnelingModel->data(appSTModelIndex, AppSplitTunnelingModel::PackageAppIconRole);
        QVERIFY2(pkgAppIcon == true, "app image should be set");

        m_coreController->m_appSplitTunnelingUiController->addApp(app);
        m_coreController->m_appSplitTunnelingUiController->updateModel();
        QVERIFY2(errorOccurredSpy.count() == 1, "errorOccurred signal should be emitted");
        QVERIFY2(m_coreController->m_appSplitTunnelingModel->rowCount() == 1, "AppSplitTunnelingModel should have 3 rows (same app should not be added)");

        m_coreController->m_appSplitTunnelingUiController->removeApp(0);
        m_coreController->m_appSplitTunnelingUiController->updateModel();
        QVERIFY2(finishedSpy.count() == 2, "finished signal should be emitted");
        QVERIFY2(m_coreController->m_appSplitTunnelingModel->rowCount() == 0, "AppSplitTunnelingModel should have 0 rows");
    }
};

QTEST_MAIN(TestUiAppSTModelAndController)
#include "testUiAppSTModelAndController.moc"
