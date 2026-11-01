#include <QtTest>
#include <QDir>
#include <QFileInfo>
#include "../../core/utils/domainRoutingConfig.h"

class DomainRoutingConfigTest : public QObject {
    Q_OBJECT
private slots:
    void portablePoliciesMatchEngineCorpus()
    {
        const auto path = QDir(QFileInfo(QString::fromUtf8(__FILE__)).absolutePath())
            .filePath("../../../native/routing/rules/testdata/portable-cases.json");
        QFile file(path);
        QVERIFY2(file.open(QIODevice::ReadOnly), qPrintable(path));
        const auto cases = QJsonDocument::fromJson(file.readAll()).array();
        QVERIFY(!cases.isEmpty());
        for (auto value : cases) {
            const auto row = value.toObject();
            const auto config = row.value("config").toObject();
            QJsonObject normalized;
            QString error;
            const bool valid = amnezia::routing::normalizeConfig(config, normalized, error);
            QCOMPARE(valid, !row.value("invalid").toBool());
            if (!valid) { QVERIFY(!error.isEmpty()); continue; }
            QCOMPARE(normalized.value("version").toInt(), 2);
            QJsonObject restored;
            const auto exported = QJsonDocument(normalized).toJson();
            QVERIFY(amnezia::routing::normalizeConfig(QJsonDocument::fromJson(exported).object(), restored, error));
            QCOMPARE(restored, normalized);
            // Includes disabled rules, overlapping conditions and source order.
            QCOMPARE(restored.value("rules").toArray().size(), config.value("rules").toArray().size());
            for (auto probe : row.value("probes").toArray()) {
                const auto q = probe.toObject();
                const auto result = amnezia::routing::inspectRule(restored, q.value("domain").toString(),
                    q.value("ip").toString(), QString::number(q.value("port").toInt()), q.value("network").toString());
                QVERIFY2(!result.contains("error"), qPrintable(result.value("error").toString()));
                QCOMPARE(result.value("action").toString(), q.value("action").toString());
                QCOMPARE(result.value("rule").toInt(), q.value("rule").toInt());
            }
        }
    }
    void portValidationAndInspectionErrors()
    {
        QString ports;
        QVERIFY(amnezia::routing::normalizePorts("443, 80-81, 81-82,0080", ports));
        QCOMPARE(ports, QString("80-82,443"));
        for (const auto &bad : {"0", "65536", "1-0", "1-2-3", "1,", ",1", "+1", "1.5", "-1", "80:90"})
            QVERIFY2(!amnezia::routing::normalizePorts(bad, ports), bad);
        const QJsonObject config{{"version", 2}, {"default", "block"}, {"rules", QJsonArray{}}};
        for (const auto &destination : {"*.ru", "https://example.org", "1.2.3.4/24", ""})
            QVERIFY(amnezia::routing::inspectRule(config, destination, "", "443", "tcp").contains("error"));
        QVERIFY(amnezia::routing::inspectRule(config, "example.org", "", "65536", "tcp").contains("error"));
        QVERIFY(amnezia::routing::inspectRule(config, "example.org", "bad", "443", "tcp").contains("error"));
        QCOMPARE(amnezia::routing::inspectRule(config, "example.org", "", "53", "udp").value("reason").toString(), QString("managed_dns"));
    }
    void normalizeEditableRules()
    {
        using amnezia::routing::destinationRule;
        const auto suffix = destinationRule("*.EXAMPLE.org.", "direct", false);
        QCOMPARE(suffix.value("kind").toString(), QString("suffix"));
        QCOMPARE(suffix.value("value").toString(), QString("example.org"));
        QVERIFY(suffix.value("disabled").toBool());
        QCOMPARE(destinationRule("192.168.1.97/24", "direct", true).value("value").toString(), QString("192.168.1.0/24"));
        QCOMPARE(destinationRule("2001:db8:abcd::1/32", "vpn", true).value("value").toString(), QString("2001:db8::/32"));
        QCOMPARE(destinationRule("2001:db8::1", "vpn", true).value("value").toString(), QString("2001:db8::1/128"));
        QCOMPARE(destinationRule(QString::fromUtf8("ПРИМЕР.рф"), "vpn", true).value("value").toString(), QString("xn--e1afmkfd.xn--p1ai"));
        for (const auto &bad : {"*ru", "a.*.ru", "a..ru", "https://example.org", "1.2.3.4/99", "fe80::1%eth0"})
            QVERIFY2(destinationRule(bad, "direct", true).isEmpty(), bad);
        QVERIFY(destinationRule("example.org", "fallback", true).isEmpty());
    }
    void migrationPreservesNames()
    {
        const QVariantMap sites{{"example.com", QStringList{"203.0.113.7"}},
                                {"*.ru", QStringList{}}, {"192.168.0.0/16", QStringList{}},
                                {"2001:db8::1", QStringList{}}};
        const auto config = amnezia::routing::fromLegacySites(true, amnezia::RouteMode::VpnAllExceptSites, sites);
        QCOMPARE(config.value("version").toInt(), 1);
        QCOMPARE(config.value("default").toString(), QString("vpn"));
        const auto rules = config.value("rules").toArray();
        QCOMPARE(rules.size(), 4);
        for (auto value : rules) {
            const auto rule = value.toObject();
            QCOMPARE(rule.value("action").toString(), QString("direct"));
            const auto destination = rule.value("value").toString();
            if (destination == "example.com") QCOMPARE(rule.value("kind").toString(), QString("domain"));
            else if (destination == "*.ru") QCOMPARE(rule.value("kind").toString(), QString("suffix"));
            else QCOMPARE(rule.value("kind").toString(), QString("cidr"));
        }
        QVERIFY(!QJsonDocument(config).toJson().contains("203.0.113.7"));
    }
    void inverseAndDisabled()
    {
        const QVariantMap sites{{"example.com", "203.0.113.7"}};
        const auto inverse = amnezia::routing::fromLegacySites(true, amnezia::RouteMode::VpnOnlyForwardSites, sites);
        QCOMPARE(inverse.value("default").toString(), QString("direct"));
        QCOMPARE(inverse.value("rules").toArray().first().toObject().value("action").toString(), QString("vpn"));
        const auto disabled = amnezia::routing::fromLegacySites(false, amnezia::RouteMode::VpnOnlyForwardSites, sites);
        QCOMPARE(disabled.value("default").toString(), QString("vpn"));
        QVERIFY(disabled.value("rules").toArray().isEmpty());
    }
};
QTEST_APPLESS_MAIN(DomainRoutingConfigTest)
#include "testDomainRoutingConfig.moc"
