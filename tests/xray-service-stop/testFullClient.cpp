#include <QtTest>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickWindow>
#include <QScopeGuard>
#include <QDirIterator>
#include <QJsonDocument>
#include <QJsonArray>
#include <QNetworkInterface>
#include "vpnConnection.h"
#include "core/protocols/xrayProtocol.h"
#include "core/protocols/protocolUtils.h"
#include "core/utils/constants/configKeys.h"
#include "linuxdnsrecovery.h"

QByteArray captureState()
{
    QByteArray result;
    for (const auto &arguments : {QStringList{"-6", "route", "show", "table", "all"},
                                  QStringList{"-6", "rule", "show"}}) {
        QProcess process;
        process.start("ip", arguments);
        if (!process.waitForFinished(5000) || process.exitCode() != 0) return {};
        result += process.readAllStandardOutput();
    }
    return result;
}
QStringList workerPids()
{
    const auto service = qEnvironmentVariable("AMNEZIA_SERVICE_PID");
    QFile children(QString("/proc/%1/task/%1/children").arg(service));
    if (!children.open(QIODevice::ReadOnly)) return {};
    QStringList result;
    for (const auto &pid : QString::fromUtf8(children.readAll()).simplified().split(' ')) {
        if (QFileInfo("/proc/" + pid + "/exe").symLinkTarget().endsWith("/tun2socks"))
            result.append(pid);
    }
    return result;
}
class LiveConnection : public VpnConnection {
public:
    LiveConnection() : VpnConnection(nullptr, nullptr) {}
    void install(const QSharedPointer<VpnProtocol> &protocol) {
        m_vpnProtocol = protocol;
        connect(protocol.data(), &VpnProtocol::connectionStateChanged, this, &VpnConnection::setConnectionState);
    }
};
class FullClientXrayStop : public QObject {
    Q_OBJECT
private slots:
    void guiDisconnectRetainsThenAutomaticallyRetries()
    {
        using namespace amnezia;
        if (qEnvironmentVariable("AMNEZIA_NATIVE_DNS_SERVICE_TEST") != "isolated-namespace")
            QSKIP("requires real service in an isolated resolved/network namespace");
        auto iface = IpcClient::Interface();
        QVERIFY(iface && iface->isReplicaValid());
        const auto baselineCapture = captureState();
        QVERIFY(!baselineCapture.isEmpty());
        const QJsonObject engine{
            {"inbounds", QJsonArray{QJsonObject{{"listen", "127.0.0.1"}, {"port", 10808},
                {"protocol", "socks"}, {"settings", QJsonObject{{"auth", "noauth"}, {"udp", true}}}}}},
            {"outbounds", QJsonArray{QJsonObject{{"protocol", "freedom"}, {"settings", QJsonObject{}}}}}};
        const QJsonObject config{
            {"ipv6_enabled", false}, {configKey::hostName, "127.0.0.1"},
            {configKey::dns1, "2001:db8::53"}, {configKey::dns2, "2001:db8::53"},
            {configKey::splitTunnelType, int(RouteMode::VpnOnlyForwardSites)},
            {configKey::killSwitchOption, false},
            {ProtocolUtils::key_proto_config_data(Proto::Xray),
                QJsonObject{{configKey::config, QString::fromUtf8(QJsonDocument(engine).toJson())}}}};
        LiveConnection connection;
        auto protocol = QSharedPointer<XrayProtocol>::create(config);
        connection.install(protocol);
        const auto backend = LinuxDnsRecovery::systemBackend();
        QJsonObject published;
        int index = 0;
        auto resolveFixtureEdit = qScopeGuard([&] {
            if (index && !published.isEmpty() && QNetworkInterface::interfaceFromIndex(index).isValid())
                backend.write(index, "dns", published["dns"]);
        });
        QCOMPARE(protocol->start(), ErrorCode::NoError);
        QTRY_COMPARE_WITH_TIMEOUT(protocol->connectionState(), Vpn::Connected, 10000);
        QTRY_COMPARE(workerPids().size(), 1);
        const auto workers = workerPids();
        const auto ownedCapture = captureState();
        QVERIFY(ownedCapture.contains("tun2"));
        index = QNetworkInterface::interfaceFromName("tun2").index();
        QVERIFY(index > 0);
        published = backend.read(index);
        QCOMPARE(published["dns"].toArray().size(), 2);
        auto tokenReply = iface->xrayCurrentToken();
        QVERIFY(tokenReply.waitForFinished());
        const auto token = tokenReply.returnValue();
        QVERIFY(token > 0);
        QString journalPath;
        QDirIterator journals(qEnvironmentVariable("XDG_CONFIG_HOME"), {"owned-*.json"},
                             QDir::Files, QDirIterator::Subdirectories);
        QVERIFY(journals.hasNext());
        journalPath = journals.next();
        QFile file(journalPath);
        QVERIFY(file.open(QIODevice::ReadOnly));
        const auto journal = QJsonDocument::fromJson(file.readAll()).object();
        file.close();
        const QJsonArray external{QString("192.0.2.77")};
        QVERIFY(backend.write(index, "dns", external));
        QQmlApplicationEngine gui;
        gui.rootContext()->setContextProperty("backend", &connection);
        gui.loadData(R"(
            import QtQuick
            import QtQuick.Window
            Window {
                id: window
                property int disconnectRequests: 0
                visible: true; width: 240; height: 100
                Rectangle {
                    anchors.fill: parent
                    MouseArea {
                        anchors.fill: parent
                        onClicked: {
                            window.disconnectRequests++
                            backend.disconnectFromVpn()
                        }
                    }
                }
            }
        )");
        QCOMPARE(gui.rootObjects().size(), 1);
        auto window = qobject_cast<QQuickWindow *>(gui.rootObjects().first());
        QVERIFY(window);
        QTRY_VERIFY(window->isVisible());
        QVERIFY(QTest::qWaitForWindowExposed(window, 5000));
        QTest::qWait(100); // Deliver the first scene-graph/polish cycle before mouse input.
        QTest::mouseClick(window, Qt::LeftButton, Qt::NoModifier, QPoint(120, 50));
        QTRY_COMPARE(window->property("disconnectRequests").toInt(), 1);
        QCOMPARE(connection.connectionState(), Vpn::Disconnecting);
        QTest::qWait(800); // Exercise multiple real 250ms automatic retry deadlines.
        QCOMPARE(connection.vpnProtocol().data(), protocol.data());
        QVERIFY(connection.connectionState() != Vpn::Disconnected);
        QCOMPARE(QNetworkInterface::interfaceFromName("tun2").index(), index);
        QCOMPARE(backend.read(index)["dns"].toArray(), external);
        QVERIFY(QFile::exists(journalPath));
        QVERIFY(file.open(QIODevice::ReadOnly));
        QCOMPARE(QJsonDocument::fromJson(file.readAll()).object()["owner"], journal["owner"]);
        file.close();
        QCOMPARE(workerPids(), workers);
        QCOMPARE(captureState(), ownedCapture);
        auto current = iface->xrayCurrentToken();
        QVERIFY(current.waitForFinished());
        QCOMPARE(current.returnValue(), token);
        qInfo("PASS: actual XrayProtocol/QML disconnect retains protocol/TUN/engine/DNS journal across failed automatic retries");
        QVERIFY(backend.write(index, "dns", published["dns"]));
        // No second stop() call: only the production retry timer may finish.
        QTRY_COMPARE_WITH_TIMEOUT(connection.connectionState(), Vpn::Disconnected, 10000);
        QTRY_VERIFY(connection.vpnProtocol().isNull());
        QVERIFY(!QNetworkInterface::interfaceFromName("tun2").isValid());
        QVERIFY(!QFile::exists(journalPath));
        QTRY_VERIFY(workerPids().isEmpty());
        QCOMPARE(captureState(), baselineCapture);
        auto stopped = iface->xrayCurrentToken();
        QVERIFY(stopped.waitForFinished());
        QCOMPARE(stopped.returnValue(), qint64(0));
        qInfo("PASS: actual XrayProtocol automatic retry confirms teardown and VpnConnection release after QML disconnect");
    }
};
QTEST_MAIN(FullClientXrayStop)
#include "testFullClient.moc"
