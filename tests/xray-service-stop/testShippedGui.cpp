#include <QtTest>
#include <QQuickWindow>
#include <QQuickItem>
#include <QScopeGuard>
#include <QNetworkInterface>
#include <QDirIterator>
#include <QJsonArray>
#include "amneziaApplication.h"
#include "core/utils/ipcClient.h"
#include "linuxdnsrecovery.h"
#include "version.h"

class ShippedGuiXrayStop : public QObject {
    Q_OBJECT
private slots:
    void installedLayoutDisconnectRetry()
    {
        auto app = qobject_cast<AmneziaApplication *>(qApp);
        QVERIFY(app);
        app->init(); // Real repository/controllers and shipped APP_QML_ENTRYPOINT.
        auto engine = app->qmlEngine();
        QTRY_VERIFY(!engine->rootObjects().isEmpty());
        auto window = qobject_cast<QQuickWindow *>(engine->rootObjects().first());
        QVERIFY(window);
        auto settings = engine->rootContext()->contextProperty("SettingsController").value<QObject *>();
        auto connection = engine->rootContext()->contextProperty("ConnectionController").value<QObject *>();
        QVERIFY(settings && connection);
        QVERIFY(settings->setProperty("ipv6Enabled", false));
        QVERIFY(settings->setProperty("primaryDns", "2001:db8::53"));
        QVERIFY(settings->setProperty("secondaryDns", "2001:db8::53"));
        QVERIFY(settings->setProperty("isKillSwitchEnabled", false));
        QTRY_VERIFY(window->findChild<QQuickItem *>("connectButton"));
        auto button = window->findChild<QQuickItem *>("connectButton");
        QVERIFY(QTest::qWaitForWindowExposed(window, 5000));
        QTRY_VERIFY(button->isVisible() && button->isEnabled());
        const auto click = [&] {
            const auto point = button->mapToScene(QPointF(button->width()/2, button->height()/2)).toPoint();
            QTest::mouseClick(window, Qt::LeftButton, Qt::NoModifier, point);
        };
        const auto backend = LinuxDnsRecovery::systemBackend();
        int index = 0;
        QJsonObject published;
        auto restoreEdit = qScopeGuard([&] {
            if (index && !published.isEmpty() && QNetworkInterface::interfaceFromIndex(index).isValid())
                backend.write(index, "dns", published["dns"]);
        });
        click(); // Actual shipped ConnectButton -> UI/core controllers -> VPN thread.
        QTRY_VERIFY_WITH_TIMEOUT(connection->property("isConnected").toBool(), 15000);
        index = QNetworkInterface::interfaceFromName("tun2").index();
        QVERIFY(index > 0);
        published = backend.read(index);
        QVERIFY(!published["dns"].toArray().isEmpty());
        QDirIterator journals(qEnvironmentVariable("XDG_CONFIG_HOME"), {"owned-*.json"},
                             QDir::Files, QDirIterator::Subdirectories);
        QVERIFY(journals.hasNext());
        const auto journal = journals.next();
        QFile journalFile(journal);
        QVERIFY(journalFile.open(QIODevice::ReadOnly));
        const auto owner = QJsonDocument::fromJson(journalFile.readAll()).object().value("owner");
        journalFile.close();
        auto iface = IpcClient::Interface();
        QVERIFY(iface);
        auto engineToken = iface->xrayCurrentToken();
        QVERIFY(engineToken.waitForFinished());
        const auto token = engineToken.returnValue();
        QVERIFY(token > 0);
        const QJsonArray external{QString("192.0.2.77")};
        QVERIFY(backend.write(index, "dns", external));
        click(); // Shipped disconnect, not a direct protocol/controller call.
        QTest::qWait(800);
        QVERIFY(QNetworkInterface::interfaceFromName("tun2").index() == index);
        QVERIFY(QFile::exists(journal));
        QVERIFY(journalFile.open(QIODevice::ReadOnly));
        QCOMPARE(QJsonDocument::fromJson(journalFile.readAll()).object()["owner"], owner);
        journalFile.close();
        auto stillRunning = iface->xrayCurrentToken();
        QVERIFY(stillRunning.waitForFinished());
        QCOMPARE(stillRunning.returnValue(), token);
        QCOMPARE(backend.read(index)["dns"].toArray(), external);
        QVERIFY(backend.write(index, "dns", published["dns"]));
        QTRY_VERIFY_WITH_TIMEOUT(!QNetworkInterface::interfaceFromName("tun2").isValid(), 10000);
        QVERIFY(!QFile::exists(journal));
        auto stopped = iface->xrayCurrentToken();
        QVERIFY(stopped.waitForFinished());
        QCOMPARE(stopped.returnValue(), qint64(0));
        QTRY_VERIFY(!connection->property("isConnected").toBool()
                    && !connection->property("isConnectionInProgress").toBool());
        qInfo("PASS: shipped GUI import/connect/disconnect; refused DNS restore retains TUN/journal; automatic retry confirms teardown");
    }
};
int main(int argc, char **argv)
{
    if (qEnvironmentVariable("AMNEZIA_NATIVE_DNS_SERVICE_TEST") != "isolated-namespace") {
        qInfo("SKIP: shipped GUI acceptance requires isolated service/resolved namespace");
        return 77;
    }
    QByteArray config = R"({"inbounds":[{"listen":"127.0.0.1","port":10808,"protocol":"socks","settings":{"auth":"noauth","udp":true}}],"outbounds":[{"protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":10809}]}}]})";
    QByteArray import = "--import";
    char *applicationArgs[] = {argv[0], import.data(), config.data(), nullptr};
    int applicationArgc = 3;
    AmneziaApplication app(applicationArgc, applicationArgs);
    app.registerTypes();
    app.setApplicationName(APPLICATION_NAME);
    app.setOrganizationName(ORGANIZATION_NAME);
    app.loadFonts();
    app.parseCommands();
    ShippedGuiXrayStop test;
    return QTest::qExec(&test, argc, argv);
}
#include "testShippedGui.moc"
