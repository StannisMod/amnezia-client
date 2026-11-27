#include <QtTest>
#include "../../service/server/ikev2dnssession.h"

class Ikev2DnsSessionTest : public QObject
{
    Q_OBJECT
private slots:
    void restoreGatesNativeTeardown()
    {
        QStringList events;
        bool restore = false, join = false, release = false;
        Ikev2DnsSession session({
            [&](const QString &) { events << "begin"; return true; },
            [] { return Ikev2DnsSession::NativeState::Connected; },
            [&](const QString &) { events << "publish"; return true; },
            [](const QString &) { return true; },
            [&](const QString &) { events << "restore"; return restore; },
            [&] { events << "join"; return join; },
            [&] { events << "fence"; return true; },
            [&] { events << "protection"; return release; },
        });
        QVERIFY(session.begin("owner"));
        QVERIFY(!session.begin("replacement"));
        session.step();
        QCOMPARE(session.state("owner"), Ikev2DnsSession::State::Connected);
        QCOMPARE(events, QStringList({"begin", "publish", "fence"}));
        events.clear();
        QVERIFY(!session.stop("foreign"));
        QVERIFY(!session.stop("owner"));
        QCOMPARE(events, QStringList({"restore"}));
        restore = true;
        session.step();
        QCOMPARE(events, QStringList({"restore", "restore", "join"}));
        events.clear();
        join = true;
        session.step();
        QCOMPARE(events, QStringList({"join", "protection"}));
        events.clear();
        release = true;
        session.step();
        QCOMPARE(events, QStringList({"protection"}));
        QCOMPARE(session.state("owner"), Ikev2DnsSession::State::Stopped);
        QVERIFY(session.shutdown());
    }

    void failedPublicationAndNativeUncertainty_data()
    {
        QTest::addColumn<bool>("publicationFailure");
        QTest::newRow("failed-publication") << true;
        QTest::newRow("uncertain-native-status") << false;
    }
    void failedPublicationAndNativeUncertainty()
    {
        QFETCH(bool, publicationFailure);
        QStringList events;
        Ikev2DnsSession session({
            [](const QString &) { return true; },
            [&] { return publicationFailure ? Ikev2DnsSession::NativeState::Connected
                                           : Ikev2DnsSession::NativeState::Uncertain; },
            [&](const QString &) { events << "publish"; return false; },
            [](const QString &) { return true; },
            [&](const QString &) { events << "restore"; return false; },
            [&] { events << "join"; return true; },
            [&] { events << "fence"; return true; },
            [&] { events << "protection"; return true; },
        });
        QVERIFY(session.begin("owner"));
        session.step();
        QCOMPARE(session.state("owner"), Ikev2DnsSession::State::Stopping);
        QCOMPARE(events, publicationFailure ? QStringList({"publish", "restore"})
                                           : QStringList({"restore"}));
        QVERIFY(!session.shutdown());
        QVERIFY(!events.contains("join"));
        QVERIFY(!events.contains("fence"));
        QVERIFY(!events.contains("protection"));
    }

    void reentrantStopDuringPublication()
    {
        QStringList events;
        Ikev2DnsSession *current = nullptr;
        bool reentrantStopCompleted = true;
        Ikev2DnsSession session({
            [](const QString &) { return true; },
            [] { return Ikev2DnsSession::NativeState::Connected; },
            [&](const QString &) {
                events << "publish-enter";
                reentrantStopCompleted = current->stop("owner");
                events << "publish-return";
                return true;
            },
            [](const QString &) { return true; },
            [&](const QString &) { events << "restore"; return false; },
            [&] { events << "join"; return true; },
            [&] { events << "fence"; return true; },
            [&] { events << "protection"; return true; },
        });
        current = &session;
        QVERIFY(session.begin("owner"));
        session.step();
        QVERIFY(!reentrantStopCompleted);
        QCOMPARE(events, QStringList({"publish-enter", "publish-return", "restore"}));
        QCOMPARE(session.state("owner"), Ikev2DnsSession::State::Stopping);
    }

    void partiallyFailedBeginRetainsOwnership()
    {
        bool restored = false;
        QStringList events;
        Ikev2DnsSession session({
            [](const QString &) { return false; },
            [] { return Ikev2DnsSession::NativeState::Gone; },
            [](const QString &) { return true; },
            [](const QString &) { return true; },
            [&](const QString &) { events << "restore"; return restored; },
            [&] { events << "join"; return true; },
            [&] { events << "fence"; return true; },
            [&] { events << "protection"; return true; },
        });
        QVERIFY(!session.begin("owner"));
        QVERIFY(!session.begin("replacement"));
        QCOMPARE(events, QStringList({"restore"}));
        restored = true;
        QVERIFY(session.stop("owner"));
        QCOMPARE(events, QStringList({"restore", "restore", "join", "fence", "protection"}));
    }
};

QTEST_GUILESS_MAIN(Ikev2DnsSessionTest)
#include "main.moc"
