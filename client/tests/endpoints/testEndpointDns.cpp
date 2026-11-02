#include <QTest>
#include "daemon/endpointdnslookup.h"

class TestEndpointDns : public QObject {
    Q_OBJECT
private:
    static QByteArray reply(QByteArray query, const QByteArray &ip = QByteArray::fromHex("c0000209")) {
        query[2] = char(0x81); query[3] = char(0x80);
        const bool ipv4 = quint8(query[query.size() - 3]) == 1;
        query[7] = ipv4 ? 1 : 0;
        if (ipv4) query += QByteArray::fromHex("c00c00010001000000000004") + ip;
        return query;
    }
private slots:
    void resolvesViaOwnedSocketAndClosesExceptionBeforeCompletion() {
        QUdpSocket dns;
        QVERIFY(dns.bind(QHostAddress(QHostAddress::LocalHost), quint16(0)));
        EndpointDnsLookup lookup;
        bool allowed = false, completed = false, validFirewall = true;
        quint16 source = 0;
        connect(&dns, &QUdpSocket::readyRead, this, [&] {
            while (dns.hasPendingDatagrams()) {
                QHostAddress sender; quint16 port;
                QByteArray packet(4096, 0);
                packet.resize(int(dns.readDatagram(packet.data(), packet.size(), &sender, &port)));
                QVERIFY(allowed); QCOMPARE(port, source);
                dns.writeDatagram(reply(packet), sender, port);
            }
        });
        lookup.start("vpn.example.org", QHostAddress::LocalHost,
            [&](quint16 port, const QHostAddress &address, bool enabled) {
                validFirewall &= address == QHostAddress(QHostAddress::LocalHost);
                if (enabled) { validFirewall &= port != 0; source = port; }
                else { validFirewall &= port == source; }
                allowed = enabled; return true;
            }, [&](const QList<QHostAddress> &addresses) {
                QVERIFY(!allowed); QCOMPARE(addresses, QList<QHostAddress>{QHostAddress("192.0.2.9")}); completed = true;
            }, dns.localPort(), 200);
        QTRY_VERIFY(completed);
        QVERIFY(validFirewall);
    }
    void malformedAndUnrelatedRepliesCannotSupplyAnAddress() {
        QUdpSocket dns;
        QVERIFY(dns.bind(QHostAddress(QHostAddress::LocalHost), quint16(0)));
        EndpointDnsLookup lookup;
        bool completed = false, allowed = false;
        connect(&dns, &QUdpSocket::readyRead, this, [&] {
            while (dns.hasPendingDatagrams()) {
                QHostAddress sender; quint16 port;
                QByteArray packet(4096, 0);
                packet.resize(int(dns.readDatagram(packet.data(), packet.size(), &sender, &port)));
                auto wrongId = reply(packet); wrongId[0] = char(quint8(wrongId[0]) ^ 1);
                dns.writeDatagram(wrongId, sender, port);
                auto loop = reply(packet); loop[12] = char(0xc0); loop[13] = 12;
                dns.writeDatagram(loop, sender, port);
                auto truncated = reply(packet); truncated.chop(3);
                dns.writeDatagram(truncated, sender, port);
                auto otherQuestion = reply(packet); otherQuestion[13] = 'x';
                dns.writeDatagram(otherQuestion, sender, port);
            }
        });
        lookup.start("vpn.example.org", QHostAddress::LocalHost,
            [&](quint16, const QHostAddress &, bool enabled) { allowed = enabled; return true; },
            [&](const QList<QHostAddress> &addresses) { QVERIFY(!allowed); QVERIFY(addresses.isEmpty()); completed = true; }, dns.localPort(), 30);
        QTRY_VERIFY(completed);
    }
    void cancelAndTimeoutRevokeTheException() {
        QUdpSocket dns;
        QVERIFY(dns.bind(QHostAddress(QHostAddress::LocalHost), quint16(0)));
        EndpointDnsLookup lookup;
        bool allowed = false; int callbacks = 0;
        const auto firewall = [&](quint16, const QHostAddress &, bool enabled) { allowed = enabled; return true; };
        lookup.start("vpn.example.org", QHostAddress::LocalHost, firewall, [&](auto) { ++callbacks; }, dns.localPort(), 10);
        QVERIFY(allowed); lookup.cancel(); QVERIFY(!allowed);
        QTest::qWait(30); QCOMPARE(callbacks, 0);
        lookup.start("vpn.example.org", QHostAddress::LocalHost, firewall, [&](auto addresses) { QVERIFY(addresses.isEmpty()); ++callbacks; }, dns.localPort(), 10);
        QTRY_COMPARE(callbacks, 1); QVERIFY(!allowed);
    }
};
QTEST_GUILESS_MAIN(TestEndpointDns)
#include "testEndpointDns.moc"
