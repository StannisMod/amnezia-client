#include <QJsonDocument>
#include <QQmlComponent>
#include <QQmlContext>
#include <QQmlEngine>
#include <QScopedPointer>
#include <QTest>
#include <QUuid>
#include "utils/testCoreController.h"
#include "core/controllers/selfhosted/serverMigrationController.h"
#include "secureQSettings.h"
#include "vpnConnection.h"

class TestServerMigrationUi : public QObject {
    Q_OBJECT
private slots:
    void loadsWizardAndRestoresPendingOperation_data() {
        QTest::addColumn<QString>("phase");
        for (const auto &phase : {"target-fingerprint", "fingerprints", "copying", "switching", "active"})
            QTest::newRow(phase) << QString::fromLatin1(phase);
    }
    void loadsWizardAndRestoresPendingOperation() {
        QFETCH(QString, phase);
        SecureQSettings settings("AmneziaMigrationUi-"+QUuid::createUuid().toString(), "test", nullptr, false);
        QJsonObject saved{{"phase", phase}, {"domain", "vpn.example.test"}, {"serverId", "synthetic-server"},
                          {"targetIdentity", QJsonObject{{"address", "192.0.2.17"}}}};
        settings.setValue("Conf/serverMigration", QJsonDocument(saved).toJson());
        auto vpn = QSharedPointer<VpnConnection>::create(nullptr, nullptr);
        TestCoreController core(vpn, &settings, nullptr, nullptr);
        auto *controller = core.findChild<ServerMigrationController *>();
        QVERIFY(controller);
        QCOMPARE(controller->phase(), phase);
        QCOMPARE(controller->domain(), QString("vpn.example.test"));
        QCOMPARE(controller->targetAddress(), QString("192.0.2.17"));
        QVERIFY(!controller->busy());
        QQmlEngine engine;
        engine.rootContext()->setContextProperty("ServerMigrationController", controller);
        QQmlComponent component(&engine);
        component.setData(R"(
            import QtQuick
            import QtQuick.Controls
            import "qrc:/migration-test"
            ApplicationWindow {
                width: 640; height: 720
                ServerMigrationDialog { parent: Overlay.overlay; selectedServerId: "synthetic-server" }
            }
        )", QUrl("qrc:/migration-test/Host.qml"));
        QVERIFY2(component.isReady(), qPrintable(component.errorString()));
        QScopedPointer<QObject> window(component.create());
        QVERIFY2(window, qPrintable(component.errorString()));
        settings.clearSettings();
    }
};
QTEST_MAIN(TestServerMigrationUi)
#include "testServerMigrationUi.moc"
