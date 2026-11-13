#include <QtTest>
#include "../../client/platforms/linux/daemon/linuxdefaultgateway.h"

class TestLinuxDefaultGateway : public QObject {
    Q_OBJECT
    static void ip(const QStringList &args) {
        QProcess p; p.start("ip", args);
        QVERIFY(p.waitForFinished(5000));
        QVERIFY2(p.exitCode()==0,p.readAllStandardError().constData());
    }
private slots:
    void selectDefaultAndFamily() {
        QVERIFY(qEnvironmentVariable("AMNEZIA_PROXY_ROUTE_TEST")=="isolated-netns");
        auto selected=amnezia::linuxNetwork::defaultGateway();
        QCOMPARE(selected.first,QString("192.0.2.1"));
        QCOMPARE(selected.second.name(),QString("uplink0"));
        ip({"route","add","default","via","10.20.0.1","dev","lan0","metric","100"});
        ip({"route","del","default","via","192.0.2.1","dev","uplink0"});
        ip({"route","add","default","via","192.0.2.1","dev","uplink0","metric","4294967295"});
        QCOMPARE(amnezia::linuxNetwork::defaultGateway().first,QString("10.20.0.1"));
        ip({"route","del","default","via","10.20.0.1","dev","lan0","metric","100"});
        ip({"route","del","default","via","192.0.2.1","dev","uplink0","metric","4294967295"});
        // The pre-existing IPv4 host/policy routes must not replace an IPv6 default.
        selected=amnezia::linuxNetwork::defaultGateway();
        QCOMPARE(selected.first,QString("2001:db8:1::1"));
        QCOMPARE(selected.second.name(),QString("uplink0"));
        ip({"-6","route","add","default","via","2001:db8:2::1","dev","lan0","metric","10"});
        QCOMPARE(amnezia::linuxNetwork::defaultGateway().first,QString("2001:db8:2::1"));
        ip({"link","set","lan0","down"});
        QCOMPARE(amnezia::linuxNetwork::defaultGateway().first,QString("2001:db8:1::1"));
        ip({"-6","route","flush","default"});
        QVERIFY(!amnezia::linuxNetwork::defaultGateway().second.isValid());
        ip({"route","add","default","dev","uplink0"});
        selected=amnezia::linuxNetwork::defaultGateway();
        QVERIFY(selected.first.isEmpty());
        QCOMPARE(selected.second.name(),QString("uplink0"));
    }
};
QTEST_GUILESS_MAIN(TestLinuxDefaultGateway)
#include "testLinuxDefaultGateway.moc"
