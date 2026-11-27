#include <QtTest>
#include "daemon/daemon.h"

struct LifecycleState {
    QStringList events;
    bool restore = true;
    bool down = true;
    bool deleted = true;
};

class LifecycleDns final : public DnsUtils {
public:
    explicit LifecycleDns(LifecycleState &state) : DnsUtils(nullptr), s(state) {}
protected:
    bool updateResolversNative(const QString &, const QList<QHostAddress> &, bool) override { return true; }
    bool restoreResolversNative(bool) override {
        s.events << "dns";
        return s.restore;
    }
private:
    LifecycleState &s;
};

class LifecycleWg final : public WireguardUtils {
public:
    explicit LifecycleWg(LifecycleState &state) : WireguardUtils(nullptr), s(state) {}
    bool interfaceExists() override { return true; }
    bool addInterface(const InterfaceConfig &) override { return true; }
    bool deleteInterface() override { s.events << "interface"; return s.deleted; }
    bool updatePeer(const InterfaceConfig &) override { return true; }
    bool deletePeer(const InterfaceConfig &) override { s.events << "peer"; return true; }
    QList<PeerStatus> getPeerStatus() override { return {}; }
    bool updateRoutePrefix(const IPAddress &) override { return true; }
    bool deleteRoutePrefix(const IPAddress &) override { s.events << "route"; return true; }
    bool addExclusionRoute(const IPAddress &) override { return true; }
    bool deleteExclusionRoute(const IPAddress &) override { return true; }
    bool excludeLocalNetworks(const QList<IPAddress> &) override { return true; }
private:
    LifecycleState &s;
};

class LifecycleDaemon final : public Daemon {
public:
    LifecycleDaemon(LifecycleState &state, LifecycleDns &dns, LifecycleWg &wg)
        : Daemon(nullptr), s(state), d(dns), w(wg) {
        InterfaceConfig config;
        config.m_hopType = InterfaceConfig::SingleHop;
        config.m_allowedIPAddressRanges << IPAddress(QHostAddress("192.0.2.0"), 24);
        m_connections.insert(InterfaceConfig::SingleHop, ConnectionState(config));
    }
    bool ownsConnection() const { return !m_connections.isEmpty(); }
protected:
    bool run(Op op, const InterfaceConfig &) override {
        if (op == Down) { s.events << "down"; return s.down; }
        return true;
    }
    WireguardUtils *wgutils() const override { return &w; }
    DnsUtils *dnsutils() override { return &d; }
private:
    LifecycleState &s;
    LifecycleDns &d;
    LifecycleWg &w;
};

class TestDaemonLifecycle : public QObject {
    Q_OBJECT
private slots:
    void failedDnsPreservesSplitPeersInterfaceAndAcknowledgment() {
        LifecycleState s;
        LifecycleDns dns(s);
        LifecycleWg wg(s);
        LifecycleDaemon daemon(s, dns, wg);
        QVERIFY(dns.updateResolvers("native0", {QHostAddress("192.0.2.53")}, true));
        QSignalSpy disconnected(&daemon, &Daemon::disconnected);
        s.restore = false;
        QVERIFY(!daemon.deactivate());
        QCOMPARE(s.events, QStringList({"dns"}));
        QVERIFY(daemon.ownsConnection());
        QCOMPARE(disconnected.count(), 0);
    }
    void failedInterfaceRetainsConnectionUntilSuccessfulRetry() {
        LifecycleState s;
        LifecycleDns dns(s);
        LifecycleWg wg(s);
        LifecycleDaemon daemon(s, dns, wg);
        QSignalSpy disconnected(&daemon, &Daemon::disconnected);
        s.deleted = false;
        QVERIFY(!daemon.deactivate());
        QVERIFY(daemon.ownsConnection());
        QCOMPARE(disconnected.count(), 0);
        s.deleted = true;
        QVERIFY(daemon.deactivate());
        QVERIFY(!daemon.ownsConnection());
        QCOMPARE(disconnected.count(), 1);
    }
    void failedPlatformDownPreservesNativeResourcesForRetry() {
        LifecycleState s;
        LifecycleDns dns(s);
        LifecycleWg wg(s);
        LifecycleDaemon daemon(s, dns, wg);
        QVERIFY(dns.updateResolvers("native0", {QHostAddress("192.0.2.53")}, true));
        QSignalSpy disconnected(&daemon, &Daemon::disconnected);
        s.down = false;
        QVERIFY(!daemon.deactivate());
        QCOMPARE(s.events, QStringList({"dns", "down"}));
        QVERIFY(daemon.ownsConnection());
        QCOMPARE(disconnected.count(), 0);
        s.down = true;
        QVERIFY(daemon.deactivate());
        QCOMPARE(disconnected.count(), 1);
    }
    void confirmedDnsPrecedesPlatformDownAndNativeRetirement() {
        LifecycleState s;
        LifecycleDns dns(s);
        LifecycleWg wg(s);
        LifecycleDaemon daemon(s, dns, wg);
        QVERIFY(dns.updateResolvers("native0", {QHostAddress("192.0.2.53")}, true));
        QVERIFY(daemon.deactivate());
        QCOMPARE(s.events, QStringList({"dns", "down", "route", "peer", "interface"}));
    }
};

QTEST_GUILESS_MAIN(TestDaemonLifecycle)
#include "testDaemonLifecycle.moc"
