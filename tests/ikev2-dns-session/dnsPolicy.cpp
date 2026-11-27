#include <QtTest>
#include <QElapsedTimer>
#include <QJsonArray>
#include <QNetworkInterface>
#include "../../client/platforms/windows/daemon/windowsdnspolicy.h"

class NativeDnsPolicyTest : public QObject
{
    Q_OBJECT
private slots:
    void selectedNativePolicyRetainsOriginalTemplateBeforePublication()
    {
        QCOMPARE(qEnvironmentVariable("AMNEZIA_IKEV2_DNS_NATIVE_TEST"), QString("isolated-fixture"));
        const auto expected = qEnvironmentVariable("AMNEZIA_SELECTED_POLICY_EXPECT");
        if (expected.isEmpty()) QSKIP("selected-policy fixture not requested");
        QVERIFY(expected == "plain" || expected == "doh" || expected == "refuse");
        QNetworkInterface link;
        for (const auto &candidate : QNetworkInterface::allInterfaces())
            for (const auto &address : candidate.addressEntries())
                if (address.ip() == QHostAddress("10.0.2.15")) link = candidate;
        QVERIFY(link.isValid());
        const QList<QHostAddress> original{QHostAddress("10.0.2.3"), QHostAddress("2001:db8::53"),
                                          QHostAddress("10.0.2.3")};
        const auto selected = WindowsDnsPolicy::captureSelected(link.humanReadableName(), original);
        QCOMPARE(selected.has_value(), expected != "refuse");
        if (!selected) return;
        QCOMPARE(selected->snapshot["reader"], QJsonValue("windows-native-selected-dns-policy-v2"));
        QCOMPARE(selected->resolverPolicy.size(), 3);
        QCOMPARE(selected->resolverPolicy[0], selected->resolverPolicy[2]);
        QCOMPARE(selected->resolverPolicy[0].toObject()["transport"],
                 QJsonValue(expected == "doh" ? "https" : "plain"));
        QCOMPARE(selected->resolverPolicy[1].toObject()["server"], QJsonValue("2001:db8::53"));
        if (expected == "doh") {
            QCOMPARE(selected->resolverPolicy[0].toObject()["https_url"],
                QJsonValue(qEnvironmentVariable("AMNEZIA_SELECTED_POLICY_URI")));
            QCOMPARE(selected->resolverPolicy[0].toObject()["server_name"], QJsonValue("selected.invalid"));
            QCOMPARE(selected->resolverPolicy[0].toObject()["port"], QJsonValue(8443));
        }
    }
    void nativeSecurityPolicyIsNeverSilentlyDropped()
    {
        QCOMPARE(qEnvironmentVariable("AMNEZIA_IKEV2_DNS_NATIVE_TEST"), QString("isolated-fixture"));
        QNetworkInterface link;
        for (const auto &candidate : QNetworkInterface::allInterfaces())
            for (const auto &address : candidate.addressEntries())
                if (address.ip() == QHostAddress("10.0.2.15")) link = candidate;
        QVERIFY(link.isValid());
        const auto expected = qEnvironmentVariable("AMNEZIA_POLICY_EXPECT");
        QVERIFY(expected == "plain" || expected == "refuse");
        QElapsedTimer elapsed;
        elapsed.start();
        const auto policy = WindowsDnsPolicy::capturePlain(link.humanReadableName(), {QHostAddress("10.0.2.3")});
        qInfo() << "Native policy read milliseconds:" << elapsed.elapsed();
        QCOMPARE(policy.has_value(), expected == "plain");
        if (policy) {
            QCOMPARE(policy->value("reader").toString(), QString("windows-native-plain-dns-policy-v1"));
            QCOMPARE(policy->value("effective_nrpt").toArray().size(), 0);
            QCOMPARE(policy->value("interface").toArray().size(), 2);
        }
    }
};
QTEST_GUILESS_MAIN(NativeDnsPolicyTest)
#include "dnsPolicy.moc"
