#include <QtTest>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include "linuxroutemonitor.h"

class LinuxExclusionRoutesTests : public QObject {
    Q_OBJECT
    static QByteArray ip(const QStringList &args)
    {
        QProcess process;
        process.start("ip", args);
        if (!process.waitForStarted() || !process.waitForFinished() || process.exitCode() != 0)
            qFatal("ip failed: %s", qPrintable(QString::fromUtf8(process.readAllStandardError())));
        return process.readAllStandardOutput();
    }
    static QString device(const QString &address)
    {
        const auto result = QJsonDocument::fromJson(ip({"-j", "route", "get", address})).array();
        return result.first().toObject().value("dev").toString();
    }
private slots:
    void preserveOriginalRouting()
    {
        const auto rules4 = ip({"-4", "-N", "-j", "rule", "show"});
        const auto rules6 = ip({"-6", "-N", "-j", "rule", "show"});
        const auto main4 = ip({"-4", "-N", "-j", "route", "show", "table", "main"});
        const auto main6 = ip({"-6", "-N", "-j", "route", "show", "table", "main"});
        const auto occupied = ip({"-4", "-N", "-j", "route", "show", "table", "51820"});
        const QStringList excluded = {"127.0.0.1", "127.0.0.53", "127.0.0.54", "::1",
            "10.20.0.8", "10.30.0.8", "198.51.100.42", "203.0.113.7", "213.148.1.80",
            "2001:db8:2::8", "2001:db8:3::8"};
        QMap<QString, QString> original;
        for (const auto &address : excluded) original[address] = device(address);
        {
            LinuxRouteMonitor monitor("amn0");
            for (const auto &prefix : {"127.0.0.0/8", "::1/128", "10.0.0.0/8",
                 "198.51.100.42/32", "203.0.113.0/24", "213.148.1.80/32", "2001:db8::/32"})
                QVERIFY(monitor.addExclusionRoute(IPAddress(QString::fromLatin1(prefix))));
            QVERIFY(monitor.insertRoute(IPAddress("0.0.0.0/1")));
            QVERIFY(monitor.insertRoute(IPAddress("128.0.0.0/1")));
            QVERIFY(monitor.insertRoute(IPAddress("::/1")));
            QVERIFY(monitor.insertRoute(IPAddress("8000::/1")));
            QTRY_COMPARE(device("1.1.1.1"), QString("amn0"));
            QTRY_COMPARE(device("2606:4700:4700::1111"), QString("amn0"));
            for (const auto &address : excluded)
                QTRY_COMPARE(device(address), original.value(address));
            QCOMPARE(original.value("10.20.0.8"), QString("lan0"));
            QCOMPARE(original.value("10.30.0.8"), QString("uplink0"));
            QCOMPARE(original.value("198.51.100.42"), QString("lan0"));
            QCOMPARE(original.value("203.0.113.7"), QString("lan0"));
            QCOMPARE(original.value("127.0.0.53"), QString("lo"));
            QCOMPARE(ip({"-4", "-N", "-j", "route", "show", "table", "main"}), main4);
            QCOMPARE(ip({"-6", "-N", "-j", "route", "show", "table", "main"}), main6);
            QVERIFY(monitor.deleteExclusionRoute(IPAddress("10.0.0.0/8")));
            QTRY_COMPARE(device("10.30.0.8"), QString("amn0"));
            QVERIFY(monitor.addExclusionRoute(IPAddress("10.0.0.0/8")));
            QTRY_COMPARE(device("10.30.0.8"), QString("uplink0"));
            QVERIFY(monitor.deleteExclusionRoute(IPAddress("127.0.0.0/8")));
            QCOMPARE(device("127.0.0.53"), QString("lo"));
        }
        QCOMPARE(ip({"-4", "-N", "-j", "rule", "show"}), rules4);
        QCOMPARE(ip({"-6", "-N", "-j", "rule", "show"}), rules6);
        QCOMPARE(ip({"-4", "-N", "-j", "route", "show", "table", "main"}), main4);
        QCOMPARE(ip({"-6", "-N", "-j", "route", "show", "table", "main"}), main6);
        QCOMPARE(ip({"-4", "-N", "-j", "route", "show", "table", "51820"}), occupied);
        QCOMPARE(device("1.1.1.1"), QString("uplink0"));
    }
};
QTEST_GUILESS_MAIN(LinuxExclusionRoutesTests)
#include "testLinuxExclusionRoutes.moc"
