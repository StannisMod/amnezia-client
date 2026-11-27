#include "../../client/core/utils/managementServer.h"
#include "../../client/core/protocols/openVpnManagementEnvironment.h"
#include <QTcpServer>
#include <QTcpSocket>
#include <QSignalSpy>
#include <QtTest>

class TestManagementStream : public QObject {
    Q_OBJECT
private slots:
    void fragmentedEnvironment()
    {
        QTcpServer reservation;
        QVERIFY(reservation.listen(QHostAddress::LocalHost, 0));
        const auto port = reservation.serverPort();
        reservation.close();
        ManagementServer management;
        QVERIFY(management.start("127.0.0.1", port));
        QTcpSocket peer;
        peer.connectToHost(QHostAddress::LocalHost, port);
        QVERIFY(peer.waitForConnected(1000));
        QTRY_VERIFY_WITH_TIMEOUT(management.isOpen(), 1000);
        QSignalSpy readable(&management, &ManagementServer::readyRead);
        OpenVpnManagementEnvironment environment;
        using Result = OpenVpnManagementEnvironment::Result;

        peer.write(">UPDOWN:U");
        peer.flush();
        QTRY_VERIFY_WITH_TIMEOUT(!readable.isEmpty(), 1000);
        QVERIFY(management.readLine().isEmpty());
        readable.clear();
        peer.write("P\r\n>UPDOWN:ENV,dns_server_1_sni=resolver.");
        peer.flush();
        QTRY_VERIFY_WITH_TIMEOUT(!readable.isEmpty(), 1000);
        QCOMPARE(environment.consume(management.readLine().trimmed().toStdString()), Result::Pending);
        QVERIFY(management.readLine().isEmpty());
        readable.clear();
        peer.write("example\r\n>UPDOWN:ENV,foreign_option_1=dhcp-option DNS 2001:db8::53\r\n"
                   ">UPDOWN:ENV,amnezia_native_routes=success\r\n"
                   ">UPDOWN:ENV,END\r\n");
        peer.flush();
        QTRY_VERIFY_WITH_TIMEOUT(!readable.isEmpty(), 1000);
        for (int i = 0; i < 3; ++i) {
            auto line = management.readLine();
            QVERIFY(!line.isEmpty());
            while (line.endsWith('\r') || line.endsWith('\n')) line.chop(1);
            QCOMPARE(environment.consume(line.toStdString()), Result::Pending);
            QVERIFY(!environment.nativeRoutesSucceeded());
        }
        QCOMPARE(environment.consume(management.readLine().trimmed().toStdString()), Result::Complete);
        QVERIFY(environment.nativeRoutesSucceeded());
        QCOMPARE(environment.values().at("dns_server_1_sni"), std::string("resolver.example"));
        QCOMPARE(environment.values().at("foreign_option_1"),
                 std::string("dhcp-option DNS 2001:db8::53"));
        QVERIFY(management.readLine().isEmpty());
    }
};

QTEST_GUILESS_MAIN(TestManagementStream)
#include "testManagementStream.moc"
