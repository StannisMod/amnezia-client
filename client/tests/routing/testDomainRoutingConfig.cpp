#include <QtTest>
#include "../../core/utils/domainRoutingConfig.h"

class DomainRoutingConfigTest : public QObject {
    Q_OBJECT
private slots:
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
