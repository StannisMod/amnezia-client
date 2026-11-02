#include <QTest>
#include "core/utils/vpnEndpointSession.h"

using Session = amnezia::VpnEndpointSession;
using Phase = Session::Phase;
using Failure = Session::Failure;

class TestVpnEndpointSession : public QObject
{
    Q_OBJECT
private:
    static void fast(Session &session)
    {
        session.timing.retryMs = 1;
        session.timing.handshakeMs = 10000;
        session.timing.resolveMs = 10000;
        session.timing.cleanupMs = 1000;
    }
private slots:
    void rotatesOnlyAfterConfirmedCleanup()
    {
        Session session;
        fast(session);
        QStringList activated;
        int queries = 0, stops = 0;
        session.resolver = [&](const QString &host, Session::Completion done) {
            QCOMPARE(host, "vpn.example.org");
            ++queries;
            done({QHostAddress("2001:db8::1"), QHostAddress("192.0.2.1"), QHostAddress("192.0.2.2"), QHostAddress("192.0.2.1")});
        };
        session.activate = [&](const QString &address) { activated.append(address); };
        session.deactivate = [&] { ++stops; };
        session.start("vpn.example.org", false);
        QCOMPARE(activated, QStringList{"192.0.2.1"});
        session.recover();
        QCOMPARE(session.phase(), Phase::Stopping);
        QCOMPARE(stops, 1);
        session.connected(); // Late notification from the old tunnel.
        QCOMPARE(session.phase(), Phase::Stopping);
        QCOMPARE(activated.size(), 1);
        session.deactivated();
        QTRY_COMPARE(activated.size(), 2);
        QCOMPARE(activated.last(), "192.0.2.2");
        QCOMPARE(queries, 1);
        session.connected();
        QCOMPARE(session.phase(), Phase::Connected);
        session.recover();
        QCOMPARE(queries, 1); // DNS must not be queried through the old tunnel.
        session.deactivated();
        QTRY_COMPARE(queries, 2);
    }
    void dnsChangeAfterEstablishedOutage()
    {
        Session session;
        fast(session);
        int queries = 0;
        session.resolver = [&](const QString &, Session::Completion done) {
            done({QHostAddress(++queries == 1 ? "192.0.2.1" : "192.0.2.9")});
        };
        session.start("vpn.example.org", false);
        session.connected();
        session.recover();
        QCOMPARE(queries, 1);
        session.deactivated();
        QTRY_COMPARE(session.address(), "192.0.2.9");
    }
    void cancelIgnoresLateDnsAndCallbacksAfterDestruction()
    {
        Session::Completion late;
        int activated = 0;
        {
            Session session;
            fast(session);
            session.resolver = [&](const QString &, Session::Completion done) { late = done; };
            session.activate = [&](const QString &) { ++activated; };
            session.start("vpn.example.org", false);
            QCOMPARE(session.phase(), Phase::Resolving);
            session.stop();
            late({QHostAddress("192.0.2.1")});
            QCOMPARE(session.phase(), Phase::Idle);
            QCOMPARE(activated, 0);
        }
        late({QHostAddress("192.0.2.1")}); // Must be safe after destruction.
        QCOMPARE(activated, 0);
    }
    void newerLookupSupersedesOldOne()
    {
        Session session;
        fast(session);
        QList<Session::Completion> lookups;
        session.resolver = [&](const QString &, Session::Completion done) { lookups.append(done); };
        session.start("old.example.org", false);
        session.start("new.example.org", false);
        lookups.first()({QHostAddress("192.0.2.1")});
        QCOMPARE(session.phase(), Phase::Resolving);
        lookups.last()({QHostAddress("192.0.2.2")});
        QCOMPARE(session.address(), "192.0.2.2");
    }
    void retryBudgetIsFinite()
    {
        Session session;
        fast(session);
        session.timing.maxAttempts = 3;
        int activations = 0, failures = 0;
        session.resolver = [](const QString &, Session::Completion done) { done({QHostAddress("192.0.2.1")}); };
        session.activate = [&](const QString &) { ++activations; QTimer::singleShot(0, &session, [&] { session.recover(); }); };
        session.deactivate = [&] { session.deactivated(); };
        session.failed = [&](Failure error) { QCOMPARE(error, Failure::AttemptsExhausted); ++failures; };
        session.start("vpn.example.org", false);
        QTRY_COMPARE(failures, 1);
        QCOMPARE(activations, 3);
        QCOMPARE(session.phase(), Phase::Failed);
        QVERIFY(!session.wanted());
    }
    void missingAckNeverReactivates()
    {
        Session session;
        fast(session);
        session.timing.cleanupMs = 10;
        int activations = 0, failures = 0;
        session.resolver = [](const QString &, Session::Completion done) { done({QHostAddress("192.0.2.1")}); };
        session.activate = [&](const QString &) { ++activations; };
        session.failed = [&](Failure error) { QCOMPARE(error, Failure::Cleanup); ++failures; };
        session.start("vpn.example.org", false);
        session.recover();
        QTRY_COMPARE(failures, 1);
        session.deactivated(); // A late acknowledgement cannot restart a failed session.
        QCOMPARE(activations, 1);
    }
    void userStopCancelsRecoveryButWaitsForCleanup()
    {
        Session session;
        fast(session);
        int activations = 0;
        session.resolver = [](const QString &, Session::Completion done) { done({QHostAddress("192.0.2.1")}); };
        session.activate = [&](const QString &) { ++activations; };
        session.start("vpn.example.org", false);
        session.recover();
        session.stop();
        QCOMPARE(session.phase(), Phase::Stopping);
        session.deactivated();
        QCOMPARE(session.phase(), Phase::Idle);
        QVERIFY(!session.wanted());
        QCOMPARE(activations, 1);
    }
    void handshakeDeadlineTriggersTeardown()
    {
        Session session;
        fast(session);
        session.timing.handshakeMs = 10;
        int stops = 0;
        session.resolver = [](const QString &, Session::Completion done) { done({QHostAddress("192.0.2.1")}); };
        session.deactivate = [&] { ++stops; };
        session.start("vpn.example.org", false);
        QTRY_COMPARE(stops, 1);
        QCOMPARE(session.phase(), Phase::Stopping);
    }
    void resolutionTimeoutAndIpv6Policy()
    {
        Session session;
        fast(session);
        session.timing.maxAttempts = 1;
        session.timing.resolveMs = 10;
        int failures = 0;
        session.resolver = [](const QString &, Session::Completion) {};
        session.failed = [&](Failure error) { QCOMPARE(error, Failure::Resolution); ++failures; };
        session.start("vpn.example.org", false);
        QTRY_COMPARE(failures, 1);
        session.resolver = [](const QString &, Session::Completion done) { done({QHostAddress("2001:db8::1")}); };
        session.start("vpn.example.org", false);
        QCOMPARE(failures, 2);
        session.start("vpn.example.org", true);
        QCOMPARE(session.address(), "2001:db8::1");
    }
    void idleAndHealthyTrafficDoNotTriggerRecovery()
    {
        Session session;
        fast(session);
        session.timing.staleMs = 100;
        int stops = 0;
        session.resolver = [](const QString &, Session::Completion done) { done({QHostAddress("192.0.2.1")}); };
        session.deactivate = [&] { ++stops; };
        session.start("vpn.example.org", false);
        session.connected();
        session.observePeer(1000, 10, 10, 0);
        session.observePeer(1000, 10, 10, 1000); // Idle is healthy.
        QCOMPARE(stops, 0);
        session.observePeer(2000, 20, 10, 1001); // Rekey proves server reachability.
        session.observePeer(2000, 30, 20, 1100); // Incoming data resets the deadline.
        session.observePeer(2000, 40, 20, 1150);
        QCOMPARE(stops, 0);
        session.observePeer(2000, 50, 20, 1201); // Outbound-only, no handshake or receive progress.
        QCOMPARE(stops, 1);
        QCOMPARE(session.phase(), Phase::Stopping);
    }
};
QTEST_GUILESS_MAIN(TestVpnEndpointSession)
#include "testVpnEndpointSession.moc"
