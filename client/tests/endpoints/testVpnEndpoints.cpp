#include <QTest>
#include "core/utils/vpnEndpoint.h"

using namespace amnezia::vpnEndpoint;

class TestVpnEndpoints : public QObject
{
    Q_OBJECT
private slots:
    void hosts_data()
    {
        QTest::addColumn<QString>("input");
        QTest::addColumn<QString>("expected");
        QTest::newRow("domain") << " VPN.Example.org. " << "vpn.example.org";
        QTest::newRow("idn") << QString::fromUtf8("пример.рф") << "xn--e1afmkfd.xn--p1ai";
        QTest::newRow("ipv4") << "192.0.2.1" << "192.0.2.1";
        QTest::newRow("ipv6") << "[2001:db8::1]" << "2001:db8::1";
        for (const auto &invalid : {"https://vpn.example.org", "vpn.example.org:443", "vpn.example.org/path",
                                  "user@vpn.example.org", "a..example.org", "-a.example.org", "a_.example.org",
                                  "vpn.example.org\nEndpoint = evil", "999.999.999.999", "fe80::1%eth0"}) {
            QTest::newRow(invalid) << QString(invalid) << QString();
        }
    }
    void hosts()
    {
        QFETCH(QString, input);
        QFETCH(QString, expected);
        QCOMPARE(normalizeHost(input), expected);
    }
    void preservesKeysAndPort()
    {
        const QString original = "[Interface]\nPrivateKey = SECRET\n# Endpoint = untouched:1\n[Peer]\nPublicKey = PUBLIC\nEndpoint = 192.0.2.1:51820 # note\nPresharedKey = PSK\n";
        auto expected = original;
        expected.replace("192.0.2.1:51820", "vpn.example.org:51820");
        QCOMPARE(replacePeerHost(original, "vpn.example.org"), expected);
        QCOMPARE(replacePeerHost(expected, "vpn.example.org"), expected);
        auto ipv6 = original;
        ipv6.replace("192.0.2.1:51820", "[2001:db8::2]:51820");
        QCOMPARE(replacePeerHost(expected, "2001:db8::2"), ipv6);
        QCOMPARE(replacePeerHost(ipv6, "vpn.example.org"), expected);
    }
    void crlfAndInterfaceRemainIntact()
    {
        const QString original = "[Interface]\r\nEndpoint = outside:1\r\n[Peer]\r\n Endpoint = [2001:db8::1]:443\r\n";
        auto expected = original;
        expected.replace("[2001:db8::1]:443", "vpn.example.org:443");
        QCOMPARE(replacePeerHost(original, "vpn.example.org"), expected);
    }
    void addressFamilies()
    {
        const QList<QHostAddress> dual{QHostAddress("2001:db8::1"), QHostAddress("192.0.2.1")};
        QCOMPARE(preferredAddress(dual, false), "192.0.2.1");
        QCOMPARE(preferredAddress(dual, true), "192.0.2.1");
        QCOMPARE(preferredAddress({dual.first()}, true), "2001:db8::1");
        QVERIFY(preferredAddress({dual.first()}, false).isEmpty());
        QVERIFY(preferredAddress({}, true).isEmpty());
    }
    void reconnectKeepsDomain()
    {
        const QJsonObject profile{{"protocol", "awg"}, {"hostName", "vpn.example.org"},
            {"awg_config_data", QJsonObject{{"hostName", "vpn.example.org"}, {"port", 51820}, {"client_priv_key", "SECRET"}}}};
        const auto first = activationConfig(profile, "192.0.2.1");
        const auto second = activationConfig(profile, "192.0.2.2");
        QCOMPARE(first.value("hostName").toString(), "192.0.2.1");
        QCOMPARE(second.value("awg_config_data").toObject().value("hostName").toString(), "192.0.2.2");
        QCOMPARE(second.value("awg_config_data").toObject().value("client_priv_key").toString(), "SECRET");
        QCOMPARE(second.value("awg_config_data").toObject().value("port").toInt(), 51820);
        QCOMPARE(profile.value("hostName").toString(), "vpn.example.org");
        QCOMPARE(profile.value("awg_config_data").toObject().value("hostName").toString(), "vpn.example.org");
    }
};
QTEST_GUILESS_MAIN(TestVpnEndpoints)
#include "testVpnEndpoints.moc"
