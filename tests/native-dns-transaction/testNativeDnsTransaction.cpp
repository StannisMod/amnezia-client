#include <QtTest>
#include <QScopeGuard>
#include "daemon/dnsutils.h"
#include "daemon/interfaceconfig.h"
#include <QJsonObject>
#include "platforms/windows/daemon/windowsdnsselection.h"

struct State {
    QStringList events;
    int next = 0;
    bool publish = true, restore = true, retire = true, reuse = false, healthy = true;
    bool prepare = true;
    bool recordQuiesce = false, quiesce = true;
    bool resolverPolicySupported = false, recordPolicy = false;
    bool selectionAllowed = true;
    QJsonArray nativePolicy;
};

class Guard final : public NativeDnsGuard {
public:
    Guard(State &state) : s(state), id(++state.next) {}
    bool prepare(const QString &name, const QList<QHostAddress> &servers,
                 QList<QHostAddress> &endpoints) override {
        s.events << QString("prepare%1").arg(id);
        original = servers;
        ifname = name;
        for (int index = 0; index < servers.size(); ++index)
            endpoints << QHostAddress(QString("198.19.%1.%2").arg(id).arg(index + 1));
        return s.prepare;
    }
    bool matches(const QString &name, const QList<QHostAddress> &servers) const override {
        return s.reuse && ifname == name && original == servers;
    }
    bool retire() override {
        s.events << QString("retire%1").arg(id);
        return s.retire;
    }
    bool healthy() const override { return s.healthy; }
    bool quiesce() const override {
        if (s.recordQuiesce) s.events << QString("quiesce%1").arg(id);
        return s.quiesce;
    }
    bool setResolverPolicy(const QJsonArray &value) override {
        if (s.recordPolicy) s.events << QString("policy%1").arg(id);
        if (!value.isEmpty() && !s.resolverPolicySupported) return false;
        policy = value;
        return true;
    }
    bool matchesResolverPolicy(const QJsonArray &value) const override { return policy == value; }
private:
    State &s;
    int id;
    QString ifname;
    QList<QHostAddress> original;
    QJsonArray policy;
};

class Resolvers final : public DnsUtils {
public:
    explicit Resolvers(State &state) : DnsUtils(nullptr), s(state) {}
    QList<QHostAddress> last;
protected:
    bool selectResolverPolicy(const QString &, const QList<QHostAddress> &,
                              const QJsonArray &requested, QJsonArray &selected) override {
        selected = s.nativePolicy.isEmpty() ? requested : s.nativePolicy;
        return s.selectionAllowed;
    }
    bool updateResolversNative(const QString &, const QList<QHostAddress> &servers, bool strict) override {
        last = servers;
        s.events << (strict ? "publish-strict" : "publish-on");
        return s.publish;
    }
    bool restoreResolversNative(bool strict) override {
        s.events << (strict ? "restore-strict" : "restore-on");
        return s.restore;
    }
private:
    State &s;
};

class TestNativeDnsTransaction : public QObject {
    Q_OBJECT
private slots:
    void nativeSelectionPrecedesPreparationAndMetadataChangesReplaceForwarder()
    {
        State s;
        s.reuse = s.resolverPolicySupported = s.recordPolicy = true;
        s.selectionAllowed = false;
        s.nativePolicy = {QJsonObject{{"server", "192.0.2.53"}, {"port", 8443},
            {"transport", "https"}, {"server_name", "selected.example"},
            {"https_url", "https://selected.example:8443/original"}}};
        DnsUtils::setNativeDnsFactory([&] { return std::make_unique<Guard>(s); });
        Resolvers dns(s);
        const QList<QHostAddress> servers{QHostAddress("192.0.2.53")};
        QVERIFY(!dns.updateResolvers("native0", servers, false, "owner"));
        QCOMPARE(s.next, 0); // Refused native policy cannot even create a guard.
        QVERIFY(s.events.isEmpty());
        s.selectionAllowed = true;
        QVERIFY(dns.updateResolvers("native0", servers, false, "owner"));
        QCOMPARE(s.events, QStringList({"policy1", "prepare1", "publish-strict"}));
        s.events.clear();
        QVERIFY(dns.updateResolvers("native0", servers, false, "owner"));
        QCOMPARE(s.events, QStringList({"publish-strict"}));
        s.events.clear();
        auto changed = s.nativePolicy[0].toObject();
        changed["https_url"] = "https://selected.example:8443/changed";
        s.nativePolicy[0] = changed;
        QVERIFY(dns.updateResolvers("native0", servers, false, "owner"));
        QCOMPARE(s.events, QStringList({"policy2", "prepare2", "publish-strict", "retire1"}));
        s.events.clear();
        s.selectionAllowed = false;
        s.recordQuiesce = true;
        QSignalSpy failed(&dns, &DnsUtils::nativeDnsFailed);
        QVERIFY(!dns.updateResolvers("native0", servers, false, "owner"));
        QCOMPARE(s.events, QStringList({"quiesce2"})); // No stale-policy re-publication.
        QCOMPARE(failed.size(), 1);
        QVERIFY(!dns.nativeDnsHealthy("owner"));
        QVERIFY(dns.restoreResolvers("owner"));
    }
    void selectedWindowsDohKeepsOriginalUriIdentityOrderAndSecurity()
    {
        const QList<QHostAddress> servers{QHostAddress("192.0.2.53"), QHostAddress("2001:db8::53"),
                                          QHostAddress("192.0.2.53")};
        const QJsonObject mapping{{"server", "192.0.2.53"},
            {"template", "https://selected.example:8443/original-path{?dns}"},
            {"auto_upgrade", true}, {"allow_fallback", false}};
        const auto policy = WindowsDnsPolicy::selectedResolverPolicy(servers, {mapping}, false);
        QVERIFY(policy);
        QCOMPARE(policy->size(), 3);
        QCOMPARE((*policy)[0], (*policy)[2]);
        QCOMPARE((*policy)[0].toObject()["https_url"], mapping["template"]);
        QCOMPARE((*policy)[0].toObject()["server_name"], QJsonValue("selected.example"));
        QCOMPARE((*policy)[0].toObject()["port"], QJsonValue(8443));
        QCOMPARE((*policy)[1].toObject()["server"], QJsonValue("2001:db8::53"));
        QCOMPARE((*policy)[1].toObject()["transport"], QJsonValue("plain"));
        const auto prohibited = WindowsDnsPolicy::selectedResolverPolicy(servers, {mapping}, true);
        QVERIFY(prohibited);
        for (const auto &value : *prohibited)
            QCOMPARE(value.toObject()["transport"], QJsonValue("plain"));
        auto inactive = mapping;
        inactive["auto_upgrade"] = false;
        const auto plain = WindowsDnsPolicy::selectedResolverPolicy(servers, {inactive}, false);
        QVERIFY(plain);
        QCOMPARE((*plain)[0].toObject()["transport"], QJsonValue("plain"));
    }
    void selectedWindowsDohRefusesUnknownPolicyInsteadOfDowngrading()
    {
        const QList<QHostAddress> servers{QHostAddress("192.0.2.53")};
        const QJsonObject original{{"server", "192.0.2.53"},
            {"template", "https://selected.example/original"},
            {"auto_upgrade", true}, {"allow_fallback", false}};
        for (const auto &change : {
                QJsonObject{{"allow_fallback", true}}, QJsonObject{{"auto_upgrade", "true"}},
                QJsonObject{{"server", "192.0.2.54"}}, QJsonObject{{"unknown", true}},
                QJsonObject{{"template", "http://selected.example/original"}},
                QJsonObject{{"template", "https://user@selected.example/original"}},
                QJsonObject{{"template", "https://selected.example/original#fragment"}},
                QJsonObject{{"template", "https://selected.example/original?x=1{?dns}"}},
                QJsonObject{{"template", "https://selected.example/{other}"}},
                QJsonObject{{"template", "https://selected.example:0/original"}},
                QJsonObject{{"template", "https://192.0.2.54/original"}}}) {
            auto mapping = original;
            for (auto it = change.begin(); it != change.end(); ++it) mapping.insert(it.key(), it.value());
            QVERIFY(!WindowsDnsPolicy::selectedResolverPolicy(servers, {mapping}, false));
        }
        QVERIFY(!WindowsDnsPolicy::selectedResolverPolicy(servers, {original, original}, false));
    }
    void init() { DnsUtils::setNativeDnsFactory({}); }
    void cleanup() { DnsUtils::setNativeDnsFactory({}); }
    void resolverTransportPolicyPrecedesPreparationAndCannotReuseDifferentIdentity() {
        State s;
        s.reuse = s.resolverPolicySupported = s.recordPolicy = true;
        DnsUtils::setNativeDnsFactory([&] { return std::make_unique<Guard>(s); });
        Resolvers dns(s);
        const QList<QHostAddress> servers{QHostAddress("192.0.2.53")};
        QJsonArray policy{QJsonObject{{"server", "192.0.2.53"}, {"port", 853},
            {"transport", "tls"}, {"server_name", "selected.example"}}};
        QVERIFY(dns.updateResolvers("native0", servers, false, "owner", {}, {}, policy));
        QCOMPARE(s.events, QStringList({"policy1", "prepare1", "publish-strict"}));
        s.events.clear();
        QVERIFY(dns.updateResolvers("native0", servers, false, "owner", {}, {}, policy));
        QCOMPARE(s.events, QStringList({"publish-strict"}));
        s.events.clear();
        auto changed = policy[0].toObject();
        changed["server_name"] = "different.example";
        policy[0] = changed;
        QVERIFY(dns.updateResolvers("native0", servers, false, "owner", {}, {}, policy));
        QCOMPARE(s.events, QStringList({"policy2", "prepare2", "publish-strict", "retire1"}));
        QVERIFY(dns.restoreResolvers("owner"));
    }
    void unsupportedTransportPolicyCannotPrepareOrPublishPlaintext() {
        State s;
        s.recordPolicy = true;
        DnsUtils::setNativeDnsFactory([&] { return std::make_unique<Guard>(s); });
        Resolvers dns(s);
        const QJsonArray policy{QJsonObject{{"server", "192.0.2.53"}, {"port", 853}, {"transport", "tls"}}};
        QVERIFY(!dns.updateResolvers("native0", {QHostAddress("192.0.2.53")}, false, "owner", {}, {}, policy));
        QCOMPARE(s.events, QStringList({"policy1"}));
        s.events.clear();
        QVERIFY(!dns.updateResolvers("native0", {QHostAddress("192.0.2.53")}, true, "owner", {}, {}, policy));
        QVERIFY(s.events.isEmpty());
    }
    void quiescePrecedesUncertainRestoreAndBlocksOnFailure() {
        State s;
        s.recordQuiesce = true;
        DnsUtils::setNativeDnsFactory([&] { return std::make_unique<Guard>(s); });
        Resolvers dns(s);
        QVERIFY(dns.updateResolvers("native0", {QHostAddress("192.0.2.53")}, false, "owner"));
        s.events.clear();
        QVERIFY(!dns.restoreResolvers("foreign"));
        QVERIFY(s.events.isEmpty());
        s.quiesce = false;
        QVERIFY(!dns.restoreResolvers("owner"));
        QCOMPARE(s.events, QStringList({"quiesce1"}));
        s.events.clear();
        s.quiesce = true;
        s.restore = false;
        QVERIFY(!dns.restoreResolvers("owner"));
        QCOMPARE(s.events, QStringList({"quiesce1", "restore-strict"}));
        QVERIFY(!dns.nativeDnsHealthy("owner"));
        QVERIFY(!dns.updateResolvers("native0", {QHostAddress("192.0.2.54")}, false, "owner"));
        QCOMPARE(s.events, QStringList({"quiesce1", "restore-strict"}));
        s.events.clear();
        s.restore = true;
        QVERIFY(dns.restoreResolvers("owner"));
        QCOMPARE(s.events, QStringList({"quiesce1", "restore-strict", "retire1"}));
    }
    void uncertainReusedPublicationQuiescesImmediately() {
        State s;
        s.recordQuiesce = true;
        s.reuse = true;
        DnsUtils::setNativeDnsFactory([&] { return std::make_unique<Guard>(s); });
        Resolvers dns(s);
        const QList<QHostAddress> servers{QHostAddress("192.0.2.53")};
        QVERIFY(dns.updateResolvers("native0", servers, false, "owner"));
        s.events.clear();
        s.publish = false;
        QVERIFY(!dns.updateResolvers("native0", servers, false, "owner"));
        QCOMPARE(s.events, QStringList({"publish-strict", "quiesce1"}));
        s.restore = true;
        QVERIFY(dns.restoreResolvers("owner"));
    }
    void everyScopeCanQuiesceBeforeAnEarlierRestoreRefuses() {
        State first, second;
        first.recordQuiesce = second.recordQuiesce = true;
        Resolvers a(first), b(second);
        DnsUtils::setNativeDnsFactory([&] { return std::make_unique<Guard>(first); });
        QVERIFY(a.updateResolvers("native0", {QHostAddress("192.0.2.53")}, false, "owner"));
        DnsUtils::setNativeDnsFactory([&] { return std::make_unique<Guard>(second); });
        QVERIFY(b.updateResolvers("native1", {QHostAddress("192.0.2.54")}, false, "owner"));
        first.events.clear();
        second.events.clear();
        QVERIFY(a.quiesceResolvers("owner"));
        QVERIFY(b.quiesceResolvers("owner"));
        QCOMPARE(first.events, QStringList({"quiesce1"}));
        QCOMPARE(second.events, QStringList({"quiesce1"}));
        first.restore = false;
        QVERIFY(!a.restoreResolvers("owner"));
        QVERIFY(!a.nativeDnsHealthy("owner"));
        QVERIFY(!b.nativeDnsHealthy("owner"));
        QCOMPARE(second.events, QStringList({"quiesce1"}));
        first.restore = true;
        QVERIFY(a.restoreResolvers("owner"));
        QVERIFY(b.restoreResolvers("owner"));
    }
    void failedQuiesceStillAttemptsEveryOwnedGeneration() {
        State s;
        s.recordQuiesce = true;
        DnsUtils::setNativeDnsFactory([&] { return std::make_unique<Guard>(s); });
        Resolvers dns(s);
        QVERIFY(dns.updateResolvers("native0", {QHostAddress("192.0.2.53")}, false, "owner"));
        s.retire = false;
        QVERIFY(!dns.updateResolvers("native0", {QHostAddress("192.0.2.54")}, false, "owner"));
        s.events.clear();
        s.quiesce = false;
        QVERIFY(!dns.quiesceResolvers("owner"));
        QCOMPARE(s.events, QStringList({"quiesce2", "quiesce1"}));
        s.quiesce = s.retire = true;
        QVERIFY(dns.restoreResolvers("owner"));
    }
    void onPreservesNativePath() {
        State s;
        Resolvers dns(s);
        const QList<QHostAddress> servers = {QHostAddress("192.0.2.53")};
        QVERIFY(dns.updateResolvers("native0", servers));
        QCOMPARE(dns.last, servers);
        QVERIFY(dns.restoreResolvers());
        QCOMPARE(s.events, QStringList({"publish-on", "restore-on"}));
    }
    void missingOffAdapterCannotPublishFallback() {
        State s;
        Resolvers dns(s);
        QVERIFY(!dns.updateResolvers("native0", {QHostAddress("192.0.2.53")}, false));
        QVERIFY(s.events.isEmpty());
    }
    void noPublicationMustNotResetPlatformDns()
    {
        State s;
        s.restore = false; // Uninitialized platform reset would fail.
        Resolvers dns(s);
        QVERIFY(dns.restoreResolvers("unclaimed"));
        QVERIFY(s.events.isEmpty());
        QVERIFY(!dns.updateResolvers("native0", {QHostAddress("192.0.2.53")}, false, "unclaimed"));
        QVERIFY(dns.restoreResolvers("unclaimed"));
        QVERIFY(s.events.isEmpty());
        s.prepare = false;
        DnsUtils::setNativeDnsFactory([&] { return std::make_unique<Guard>(s); });
        QVERIFY(!dns.updateResolvers("native0", {QHostAddress("192.0.2.53")}, false, "prepared"));
        QVERIFY(dns.restoreResolvers("prepared"));
        QCOMPARE(s.events, QStringList({"prepare1", "retire1"}));
        s.prepare = true;
        QVERIFY(!dns.updateResolvers("native0", {QHostAddress("192.0.2.53")}, false, "metadata",
                                     QJsonObject{{"protocol", "openvpn"}}));
        QVERIFY(dns.restoreResolvers("metadata"));
        QCOMPARE(s.events, QStringList({"prepare1", "retire1", "prepare2", "retire2"}));
    }
    void legacyOnPublicationStillRejectsForeignOwner()
    {
        State s;
        Resolvers dns(s);
        QVERIFY(dns.updateResolvers("native0", {QHostAddress("192.0.2.53")}, true));
        QVERIFY(!dns.restoreResolvers("foreign"));
        QVERIFY(!dns.updateResolvers("other", {QHostAddress("192.0.2.54")}, false, "foreign"));
        QCOMPARE(s.events, QStringList({"publish-on"}));
        QVERIFY(dns.restoreResolvers());
        QCOMPARE(s.events, QStringList({"publish-on", "restore-on"}));
    }
    void failedPreparationRetainsOwnedCleanupForRetry() {
        State s;
        s.prepare = false;
        s.retire = false;
        DnsUtils::setNativeDnsFactory([&] { return std::make_unique<Guard>(s); });
        Resolvers dns(s);
        const QList<QHostAddress> servers{QHostAddress("192.0.2.53")};
        QVERIFY(!dns.updateResolvers("native0", servers, false, "current"));
        QCOMPARE(s.events, QStringList({"prepare1", "retire1"}));
        QVERIFY(!dns.restoreResolvers("stale"));
        QCOMPARE(s.events.size(), 2);
        QVERIFY(!dns.updateResolvers("native0", servers, false, "current"));
        QCOMPARE(s.next, 1);
        s.retire = true;
        QVERIFY(dns.restoreResolvers("current"));
        QCOMPARE(s.events.last(), QString("retire1"));
        s.prepare = true;
        QVERIFY(dns.updateResolvers("native0", servers, false, "next"));
        QVERIFY(dns.restoreResolvers("next"));
    }
    void replacementPreparesThenPublishesThenRetires() {
        State s;
        DnsUtils::setNativeDnsFactory([&] { return std::make_unique<Guard>(s); });
        Resolvers dns(s);
        const QList<QHostAddress> servers = {QHostAddress("192.0.2.53"), QHostAddress("2001:db8::53")};
        QVERIFY(dns.updateResolvers("native0", servers, false));
        QCOMPARE(dns.last.size(), servers.size());
        QVERIFY(dns.updateResolvers("native0", servers, false));
        QCOMPARE(s.events, QStringList({"prepare1", "publish-strict", "prepare2",
                                        "publish-strict", "retire1"}));
        s.restore = false;
        QVERIFY(!dns.restoreResolvers());
        QVERIFY(!s.events.contains("retire2"));
        s.restore = true;
        QVERIFY(dns.restoreResolvers());
        QCOMPARE(s.events.last(), QString("retire2"));
    }
    void uncertainPublicationRequiresConfirmedRestore() {
        State s;
        DnsUtils::setNativeDnsFactory([&] { return std::make_unique<Guard>(s); });
        Resolvers dns(s);
        s.publish = false;
        QVERIFY(!dns.updateResolvers("native0", {QHostAddress("192.0.2.53")}, false));
        QCOMPARE(s.events, QStringList({"prepare1", "publish-strict"}));
        s.publish = true;
        QVERIFY(!dns.updateResolvers("native0", {QHostAddress("192.0.2.53")}, false));
        QVERIFY(!dns.updateResolvers("native0", {QHostAddress("192.0.2.53")}, true));
        QCOMPARE(s.events.size(), 2);
        s.restore = false;
        QVERIFY(!dns.restoreResolvers());
        QVERIFY(!s.events.contains("retire1"));
        s.restore = true;
        QVERIFY(dns.restoreResolvers());
        QCOMPARE(s.events.last(), QString("retire1"));
    }
    void unchangedScopeRetainsDnsSessions() {
        State s;
        s.reuse = true;
        DnsUtils::setNativeDnsFactory([&] { return std::make_unique<Guard>(s); });
        Resolvers dns(s);
        const QList<QHostAddress> servers = {QHostAddress("192.0.2.53")};
        QVERIFY(dns.updateResolvers("native0", servers, false));
        const auto endpoints = dns.last;
        QVERIFY(dns.updateResolvers("native0", servers, false));
        QCOMPARE(dns.last, endpoints);
        QCOMPARE(s.events, QStringList({"prepare1", "publish-strict", "publish-strict"}));
        QVERIFY(dns.restoreResolvers());
    }
    void failedCleanupRemainsOwnedForRetry() {
        State s;
        DnsUtils::setNativeDnsFactory([&] { return std::make_unique<Guard>(s); });
        Resolvers dns(s);
        QVERIFY(dns.updateResolvers("native0", {QHostAddress("192.0.2.53")}, false));
        s.retire = false;
        QVERIFY(!dns.restoreResolvers());
        s.retire = true;
        QVERIFY(dns.restoreResolvers());
        QCOMPARE(s.events.count("retire1"), 2);
    }
    void nativeListenerFailureIsReportedOutsideGoCallbacks() {
        State s;
        DnsUtils::setNativeDnsFactory([&] { return std::make_unique<Guard>(s); });
        Resolvers dns(s);
        QSignalSpy failed(&dns, &DnsUtils::nativeDnsFailed);
        QVERIFY(dns.updateResolvers("native0", {QHostAddress("192.0.2.53")}, false));
        s.healthy = false;
        QTRY_COMPARE(failed.size(), 1);
        QVERIFY(dns.restoreResolvers());
        QCOMPARE(s.events.last(), QString("retire1"));
    }
    void userSwitchIsIndependentOfTunnelCapability() {
        InterfaceConfig config;
        config.m_hopType = InterfaceConfig::SingleHop;
        config.m_killSwitchEnabled = false;
        config.m_ipv6Enabled = false; // Server/native interface lacks IPv6.
        config.m_deviceIpv4Address = "192.0.2.10/32";
        config.m_primaryDnsServer = "192.0.2.53";
        QVERIFY(config.toJson().value("ipv6_enabled").toBool());
        QVERIFY(config.toWgConf().contains("\nDNS = 192.0.2.53"));
        config.m_ipv6PolicyEnabled = false; // Explicit user OFF.
        QVERIFY(!config.toJson().value("ipv6_enabled").toBool(true));
        const auto managed = config.toWgConf({{"Table", "off"}, {"AmneziaNativeDNS", "true"}});
        QVERIFY(!managed.contains("\nDNS =")); // Not the distinct AmneziaNativeDNS ownership key.
        QVERIFY(managed.contains("AmneziaNativeDNS = true"));
    }
    void staleOwnerCannotRestoreOrReplaceCurrentDns() {
        State s;
        DnsUtils::setNativeDnsFactory([&] { return std::make_unique<Guard>(s); });
        Resolvers dns(s);
        QVERIFY(dns.updateResolvers("native0", {QHostAddress("192.0.2.53")}, false, "current"));
        const auto before = s.events;
        QVERIFY(!dns.restoreResolvers("retired"));
        QVERIFY(!dns.restoreResolvers());
        QVERIFY(!dns.updateResolvers("native0", {QHostAddress("192.0.2.54")}, false, "retired"));
        QCOMPARE(s.events, before);
        QVERIFY(dns.restoreResolvers("current"));
    }
};

QTEST_GUILESS_MAIN(TestNativeDnsTransaction)
#include "testNativeDnsTransaction.moc"
