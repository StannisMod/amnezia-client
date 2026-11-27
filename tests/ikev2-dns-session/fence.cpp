#include <winsock2.h>
#include <windows.h>
#include <fwpmu.h>
#include <QtTest>
#include <QScopeGuard>
#include <QTcpServer>
#include <QTcpSocket>
#include <QUdpSocket>
#include "platforms/windows/daemon/nativednsfirewall.h"

class NativeFenceTest : public QObject
{
    Q_OBJECT
private slots:
    void initTestCase()
    {
        QCOMPARE(qEnvironmentVariable("AMNEZIA_IKEV2_DNS_NATIVE_TEST"), QString("isolated-fixture"));
        HANDLE token = nullptr;
        QVERIFY(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token));
        auto release = qScopeGuard([&] { CloseHandle(token); });
        TOKEN_ELEVATION elevation{};
        DWORD size = 0;
        QVERIFY(GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size));
        QVERIFY(elevation.TokenIsElevated);
    }
    void udpTcpFencedUntilExplicitRetirement()
    {
        QTcpServer tcp;
        QUdpSocket udp;
        QVERIFY2(tcp.listen(QHostAddress::LocalHost, 53), qPrintable(tcp.errorString()));
        QVERIFY2(udp.bind(QHostAddress::LocalHost, 53), qPrintable(udp.errorString()));
        QTcpSocket before;
        before.connectToHost(QHostAddress::LocalHost, 53);
        QVERIFY(before.waitForConnected(1000));
        QUdpSocket beforeUdp;
        QCOMPARE(beforeUdp.writeDatagram("before", QHostAddress::LocalHost, 53), qint64(6));
        QVERIFY(udp.waitForReadyRead(1000));
        char data[32]{};
        QCOMPARE(udp.readDatagram(data, sizeof(data)), qint64(6));
        HANDLE lease = NativeDnsFirewall::openSetupFence();
        QVERIFY(lease);
        auto cleanup = qScopeGuard([&] { if (lease) FwpmEngineClose0(lease); });
        QTcpSocket blocked;
        blocked.connectToHost(QHostAddress::LocalHost, 53);
        QVERIFY(!blocked.waitForConnected(1000));
        QVERIFY(blocked.state() != QAbstractSocket::ConnectedState);
        QUdpSocket blockedUdp;
        blockedUdp.writeDatagram("blocked", QHostAddress::LocalHost, 53);
        QVERIFY(!udp.waitForReadyRead(300));
        QVERIFY(!udp.hasPendingDatagrams());
        const auto closed = FwpmEngineClose0(lease);
        if (closed == ERROR_SUCCESS) lease = nullptr;
        QCOMPARE(closed, DWORD(ERROR_SUCCESS));
        QTcpSocket after;
        after.connectToHost(QHostAddress::LocalHost, 53);
        QVERIFY(after.waitForConnected(1000));
        QUdpSocket afterUdp;
        QCOMPARE(afterUdp.writeDatagram("after", QHostAddress::LocalHost, 53), qint64(5));
        QVERIFY(udp.waitForReadyRead(1000));
        QCOMPARE(udp.readDatagram(data, sizeof(data)), qint64(5));
        QCOMPARE(QByteArray(data, 5), QByteArray("after"));
    }
};

QTEST_GUILESS_MAIN(NativeFenceTest)
#include "fence.moc"
