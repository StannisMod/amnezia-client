#include <QtTest>
#include "../../client/platforms/linux/daemon/linuxproxyipv6.h"

class TestLinuxProxyIpv6 : public QObject {
    Q_OBJECT
    QByteArray ip(const QStringList &args) {
        QProcess p; p.start("ip", args);
        if (!p.waitForFinished(5000) || p.exitCode() != 0) return {};
        return p.readAllStandardOutput();
    }
    QByteArray device(const QString &target) { return ip({"-6", "route", "get", target}); }
private slots:
    void kernelRoutingAndCleanup() {
        QVERIFY(qEnvironmentVariable("AMNEZIA_PROXY_ROUTE_TEST") == "isolated-netns");
        QVERIFY(!ip({"link", "show", "tun2"}).isEmpty());
        const auto rules = ip({"-6", "rule", "show"});
        const auto routes = ip({"-6", "route", "show", "table", "all"});
        const auto routes4 = ip({"-4", "route", "show", "table", "all"});
        const auto rules4 = ip({"-4", "rule", "show"});
        QVERIFY(device("2606:4700::1").contains("dev uplink0"));
        {
            LinuxProxyIpv6 policy;
            QVERIFY(policy.configure({"::/0"}, {"2001:db8:2::/64", "2001:db8:1::42/128"}));
            for (const auto &target : {"2606:4700::1", "fd42::2", "64:ff9b::c000:201"})
                QVERIFY2(device(target).contains("dev tun2"), target);
            QVERIFY(device("2001:db8:2::42").contains("dev lan0"));
            QVERIFY(device("2001:db8:1::42").contains("dev uplink0"));
            QVERIFY(ip({"-6", "route", "get", "2606:4700::1", "from", "2001:db8:2::2"}).contains("dev uplink0"));
            QVERIFY(!policy.configure({"::/0"}, {}));
        }
        QCOMPARE(ip({"-6", "rule", "show"}), rules);
        QCOMPARE(ip({"-6", "route", "show", "table", "all"}), routes);
        QCOMPARE(ip({"-4", "route", "show", "table", "all"}), routes4);
        QCOMPARE(ip({"-4", "rule", "show"}), rules4);
        {
            LinuxProxyIpv6 policy;
            QVERIFY(policy.configure({"2001:db8:42::/64"}, {}));
            QVERIFY(device("2001:db8:42::5").contains("dev tun2"));
            QVERIFY(device("fd42::2").contains("dev uplink0"));
        }
        {
            LinuxProxyIpv6 invalid;
            QVERIFY(!invalid.configure({"::/0"}, {"::/129"}));
        }
        QCOMPARE(ip({"-6", "rule", "show"}), rules);
        QCOMPARE(ip({"-6", "route", "show", "table", "all"}), routes);
    }
};
QTEST_GUILESS_MAIN(TestLinuxProxyIpv6)
#include "testLinuxProxyIpv6.moc"
