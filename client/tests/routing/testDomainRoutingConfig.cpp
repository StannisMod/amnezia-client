#include <QtTest>
#include "../../core/utils/domainRoutingConfig.h"
#include "../../core/utils/splitDnsConfig.h"

class DomainRoutingConfigTest : public QObject {
    Q_OBJECT
private slots:
    void dnsAlwaysFollowsSiteRoutes()
    {
        const QJsonObject directRule{{"kind", "suffix"}, {"value", "corp.example"}, {"action", "direct"}};
        const QJsonObject routing{{"version", 1}, {"default", "vpn"}, {"rules", QJsonArray{directRule}}};
        const auto config = amnezia::dns::forSiteRoutes(routing, "10.77.0.2");
        QVERIFY(config.value("follow_routing").toBool());
        QVERIFY(config.value("rules").toArray().isEmpty());
        QVERIFY(!config.contains("preserve_network_domains"));
        const auto policies = config.value("policies").toObject();
        QCOMPARE(policies.size(), 2);
        const auto direct = policies.value("direct").toObject();
        QCOMPARE(direct.value("source").toString(), QString("network"));
        QCOMPARE(direct.value("path").toString(), QString("direct"));
        QVERIFY(direct.value("server").toString().isEmpty());
        const auto vpn = policies.value("vpn").toObject();
        QCOMPARE(vpn.value("server").toString(), QString("10.77.0.2"));
        QCOMPARE(vpn.value("path").toString(), QString("vpn"));
        // Reconnect reads the newly selected effective DNS, never a saved copy.
        const auto changed = amnezia::dns::forSiteRoutes(routing, "9.9.9.9");
        QCOMPARE(changed.value("policies").toObject().value("vpn").toObject().value("server").toString(), QString("9.9.9.9"));
        auto inverse = routing; inverse["default"] = "direct"; inverse["rules"] = QJsonArray{};
        QVERIFY(amnezia::dns::forSiteRoutes(inverse, "10.77.0.2").value("follow_routing").toBool());
    }
    void allVpnDnsDoesNotDependOnPhysicalDnsDiscovery()
    {
        for (const auto &rule : QJsonArray{QJsonObject{},
                 QJsonObject{{"kind", "cidr"}, {"value", "192.0.2.0/24"}, {"action", "direct"}},
                 QJsonObject{{"kind", "domain"}, {"value", "disabled.example"}, {"action", "direct"}, {"disabled", true}}}) {
            const QJsonObject routing{{"version", 1}, {"default", "vpn"}, {"rules", QJsonArray{rule}}};
            const auto config = amnezia::dns::forSiteRoutes(routing, "10.77.0.2");
            QCOMPARE(config.value("default").toString(), QString("vpn"));
            QVERIFY(!config.value("follow_routing").toBool());
            QCOMPARE(config.value("policies").toObject().size(), 1);
            QCOMPARE(config.value("policies").toObject().value("vpn").toObject().value("path").toString(), QString("vpn"));
        }
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
