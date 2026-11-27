#include <QtTest>
#include <QTcpSocket>
#include <QSignalSpy>
#include <memory>
#include "openvpndnssession.h"
#include "openvpndnsselection.h"
#include "core/utils/openVpnDnsScripts.h"

namespace {
void send(QTcpSocket &peer, const QString &text)
{
    const auto bytes = text.toUtf8();
    QCOMPARE(peer.write(bytes), bytes.size());
    peer.flush();
}
void frame(QTcpSocket &peer, const QString &routes = "success", const QString &dev = "owned-tun")
{
    send(peer, ">UPDOWN:UP\r\n>UPDOWN:ENV,dev=" + dev + "\r\n"
        ">UPDOWN:ENV,amnezia_native_dns=external\r\n"
        ">UPDOWN:ENV,amnezia_native_routes=" + routes + "\r\n"
        ">UPDOWN:ENV,foreign_option_1=dhcp-option DNS 2001:db8::53\r\n"
        ">UPDOWN:ENV,dns_server_1_sni=preserve  spaces=x\r\n"
        ">UPDOWN:ENV,password=never-store-or-forward\r\n"
        ">UPDOWN:ENV,END\r\n");
}
void request(QTcpSocket &peer, const QString &phase, int serial)
{
    send(peer, ">NEED-OK:Need 'AMNEZIA-DNS-" + phase + ":" + QString::number(serial)
        + "' confirmation MSG:Confirm service-owned native DNS transaction\r\n");
}
}

class TestOpenVpnDnsSession : public QObject {
    Q_OBJECT
private slots:
    void bundledWriterOmissionIsExact()
    {
        const QString script = "/owned (test)/update-resolv-conf.sh";
        const auto input = "script-security 2\r\nup \"" + script + "\"\r\ndown " + script
            + "\r\nup /provider/route-hook\r\ndown \"" + script + "\" --argument\r\n"
              "up \"/owned (test)/update-resolv-conf.sh\r\nroute 192.0.2.0 255.255.255.0\r\n";
        const auto output = openVpnNativeDns::withoutBundledResolverScript(input, script);
        QVERIFY(!output.contains("up \"" + script + "\"\r\n"));
        QVERIFY(!output.contains("down " + script + "\r\n"));
        QVERIFY(output.contains("up /provider/route-hook\r\n"));
        QVERIFY(output.contains("down \"" + script + "\" --argument\r\n"));
        QVERIFY(output.contains("up \"/owned (test)/update-resolv-conf.sh\r\n")); // Do not repair malformed caller input.
        QVERIFY(output.contains("route 192.0.2.0 255.255.255.0\r\n"));
        for (const auto &opening : {QString("<auth-user-pass>"), QString("\"<auth-user-pass>\""),
                                    QString("'<auth-user-pass>'")}) {
            const auto credentials = opening + "\r\nup \"" + script
                + "\"\r\ndown " + script + "\r\n  </auth-user-pass> # native closing prefix\r\n";
            QCOMPARE(openVpnNativeDns::withoutBundledResolverScript(credentials, script), credentials);
            const auto combined = credentials + "up \"" + script + "\"\r\n";
            QCOMPARE(openVpnNativeDns::withoutBundledResolverScript(combined, script), credentials + "\n");
        }
    }
    void nativeSelectionPreservesOrderAndRejectsLossyPolicy()
    {
        QJsonObject metadata{{"dev", "owned-tun"}};
        for (int i = 1; i <= 12; ++i)
            metadata.insert("foreign_option_" + QString::number(i),
                "dhcp-option DNS 192.0.2." + QString::number(i));
        auto selection = openVpnDnsSelection(metadata);
        QVERIFY(selection); QCOMPARE(selection->servers.size(), 12);
        QCOMPARE(selection->servers[1], QHostAddress("192.0.2.2"));
        QCOMPARE(selection->servers[9], QHostAddress("192.0.2.10"));
        QCOMPARE(selection->metadata, metadata);
        metadata = {{"dev", "owned-tun"}, {"foreign_option_1", "dhcp-option DNS 2001:db8::53"},
                    {"foreign_option_2", "dhcp-option DNS 2001:db8::53"}};
        selection = openVpnDnsSelection(metadata);
        QVERIFY(selection); QCOMPARE(selection->servers.size(), 2);
        QCOMPARE(selection->servers[0], selection->servers[1]);
        for (const auto &unsupported : {
            QJsonObject{{"foreign_option_3", "dhcp-option DOMAIN private.example"}},
            QJsonObject{{"dns_server_1_address_1", "192.0.2.53"}, {"dns_server_1_transport", "DoH"}},
            QJsonObject{{"dns_server_1_address_1", "192.0.2.53"}, {"dns_server_1_port_1", "0"}},
            QJsonObject{{"dns_server_1_address_1", "192.0.2.53"}, {"dns_server_1_sni", "secure.example"}},
            QJsonObject{{"dns_server_1_address_1", "192.0.2.53"}, {"dns_server_1_dnssec", "yes"}},
            QJsonObject{{"dns_server_1_address_1", "192.0.2.53"}, {"dns_server_2_address_1", "192.0.2.54"}}
        }) {
            auto rejected = metadata;
            for (auto it = unsupported.begin(); it != unsupported.end(); ++it) rejected.insert(it.key(), it.value());
            QVERIFY(!openVpnDnsSelection(rejected));
        }
        metadata = {{"dev", "owned-tun"}, {"dns_server_1_address_1", "192.0.2.53"},
                    {"dns_server_1_address_2", "2001:db8::53"}, {"dns_server_1_transport", "plain"},
                    {"amnezia_dns_priority_1", "-3"}, {"dns_server_1_port_1", "53"}};
        selection = openVpnDnsSelection(metadata);
        QVERIFY(selection); QCOMPARE(selection->servers.size(), 2);
        QCOMPARE(selection->metadata, metadata);
        metadata["dns_server_2_transport"] = "plain";
        QVERIFY(!openVpnDnsSelection(metadata));
    }
    void nativeSelectionPreservesCustomPortsAndAuthenticatedDoTIdentity()
    {
        QJsonObject metadata{{"dev", "owned-tun"}, {"dns_server_1_address_1", "192.0.2.53"},
            {"dns_server_1_address_2", "2001:db8::53"}, {"dns_server_1_address_3", "192.0.2.53"},
            {"dns_server_1_transport", "DoT"}, {"dns_server_1_sni", "selected.example"},
            {"dns_server_1_port_2", "8853"}};
        auto selection = openVpnDnsSelection(metadata);
        QVERIFY(selection);
        QCOMPARE(selection->metadata, metadata);
        QCOMPARE(selection->resolverPolicy.size(), 3);
        QCOMPARE(selection->servers[0], selection->servers[2]);
        for (int i = 0; i < 3; ++i) {
            const auto policy = selection->resolverPolicy[i].toObject();
            QCOMPARE(policy["server"].toString(), selection->servers[i].toString());
            QCOMPARE(policy["transport"].toString(), QString("tls"));
            QCOMPARE(policy["server_name"].toString(), QString("selected.example"));
            QCOMPARE(policy["port"].toInt(), i == 1 ? 8853 : 853);
        }
        metadata.remove("dns_server_1_sni");
        metadata["dns_server_1_transport"] = "plain";
        metadata["dns_server_1_port_1"] = "853"; // Explicit port is NOT a TLS signal.
        selection = openVpnDnsSelection(metadata);
        QVERIFY(selection);
        QCOMPARE(selection->resolverPolicy[0].toObject()["port"].toInt(), 853);
        QCOMPARE(selection->resolverPolicy[0].toObject()["transport"].toString(), QString("plain"));
        QCOMPARE(selection->resolverPolicy[2].toObject()["port"].toInt(), 53);
        for (const auto &bad : {QString("0"), QString("65536"), QString("053"), QString("+53")}) {
            auto invalid = metadata;
            invalid["dns_server_1_port_1"] = bad;
            QVERIFY(!openVpnDnsSelection(invalid));
        }
        metadata["dns_server_2_sni"] = "orphan.example";
        QVERIFY(!openVpnDnsSelection(metadata));
    }
    void publishReconnectRestoreWithoutGui()
    {
        int publications = 0, restorations = 0;
        bool restore = false;
        QString owner;
        QJsonObject metadata;
        OpenVpnDnsSession session({
            [&](const QString &ticket, const QJsonObject &value) {
                if (owner.isEmpty()) owner = ticket;
                if (owner != ticket) return false;
                ++publications; metadata = value; return true;
            },
            [&](const QString &ticket) { if (owner != ticket) return false; ++restorations; return restore; }
        });
        QVERIFY(session.start()); QVERIFY(!session.start());
        QSignalSpy failure(&session, &OpenVpnDnsSession::failed);
        auto gui = std::make_unique<QObject>();
        int guiMessages = 0;
        connect(&session, &OpenVpnDnsSession::managementLine, gui.get(), [&](const QString &) { ++guiMessages; });
        QTcpSocket peer;
        peer.connectToHost(QHostAddress::LocalHost, session.port());
        QVERIFY(peer.waitForConnected(1000));
        frame(peer);
        QTest::qWait(30);
        QCOMPARE(publications, 0); QCOMPARE(guiMessages, 0); QVERIFY(!peer.bytesAvailable());
        request(peer, "PUBLISH", 1);
        QTRY_VERIFY_WITH_TIMEOUT(peer.canReadLine(), 1000);
        QCOMPARE(peer.readLine(), QByteArray("needok 'AMNEZIA-DNS-PUBLISH:1' ok\n"));
        QCOMPARE(publications, 1); QVERIFY(session.active());
        QCOMPARE(metadata["dns_server_1_sni"].toString(), QString("preserve  spaces=x"));
        QVERIFY(!metadata.contains("password"));
        QVERIFY(!owner.isEmpty());
        gui.reset(); // No management/DNS ownership is attached to this observer.
        send(peer, ">BYTECOUNT:7,9\r\n");
        frame(peer, "preserved");
        request(peer, "PUBLISH", 2);
        QTRY_VERIFY_WITH_TIMEOUT(peer.canReadLine(), 1000);
        QCOMPARE(peer.readLine(), QByteArray("needok 'AMNEZIA-DNS-PUBLISH:2' ok\n"));
        QCOMPARE(publications, 2); QCOMPARE(guiMessages, 0); QCOMPARE(failure.size(), 0);
        request(peer, "PUBLISH", 1); // Stale nonce cannot republish or tear down.
        QTest::qWait(30); QCOMPARE(publications, 2); QCOMPARE(restorations, 0);
        request(peer, "RESTORE", 3);
        QTRY_VERIFY_WITH_TIMEOUT(restorations > 0, 1000);
        QTest::qWait(300);
        QVERIFY(!peer.bytesAvailable()); QVERIFY(session.active()); QVERIFY(!session.cleanupConfirmed());
        QVERIFY(!session.nativeMetadata().isEmpty());
        restore = true;
        QTRY_VERIFY_WITH_TIMEOUT(peer.canReadLine(), 1000);
        QCOMPARE(peer.readLine(), QByteArray("needok 'AMNEZIA-DNS-RESTORE:3' ok\n"));
        QVERIFY(!session.active()); QVERIFY(session.cleanupConfirmed());
        const int beforeRepeat = restorations;
        request(peer, "RESTORE", 4);
        QTRY_VERIFY_WITH_TIMEOUT(peer.canReadLine(), 1000);
        QCOMPARE(peer.readLine(), QByteArray("needok 'AMNEZIA-DNS-RESTORE:4' ok\n"));
        QCOMPARE(restorations, beforeRepeat);
    }
    void failedPublicationWaitsForRollback()
    {
        int publications = 0, restorations = 0;
        bool restored = false;
        OpenVpnDnsSession session({
            [&](const QString &, const QJsonObject &) { ++publications; return false; },
            [&](const QString &) { ++restorations; return restored; }
        });
        QVERIFY(session.start());
        QSignalSpy failure(&session, &OpenVpnDnsSession::failed);
        QTcpSocket peer; peer.connectToHost(QHostAddress::LocalHost, session.port());
        QVERIFY(peer.waitForConnected(1000));
        frame(peer); request(peer, "PUBLISH", 1);
        QTRY_COMPARE_WITH_TIMEOUT(failure.size(), 1, 1000);
        QTest::qWait(300);
        QCOMPARE(publications, 1); QVERIFY(restorations > 0);
        QVERIFY(!peer.bytesAvailable()); QVERIFY(!session.cleanupConfirmed());
        QVERIFY(!session.nativeMetadata().isEmpty());
        QVERIFY(!session.command("needok 'AMNEZIA-DNS-PUBLISH:1' ok"));
        QVERIFY(!session.command("signal SIGKILL"));
        restored = true;
        QTRY_VERIFY_WITH_TIMEOUT(peer.bytesAvailable() > 0, 1000);
        QTest::qWait(20);
        const auto commands = peer.readAll();
        QVERIFY(commands.startsWith("needok 'AMNEZIA-DNS-PUBLISH:1' cancel\n"));
        QVERIFY(commands.contains("signal SIGTERM\n"));
        QCOMPARE(publications, 1); QVERIFY(session.cleanupConfirmed());
    }
    void stopDuringPublicationCannotAcknowledgeSuccess()
    {
        OpenVpnDnsSession *active = nullptr;
        bool restore = false, stopConfirmed = true;
        int publications = 0;
        OpenVpnDnsSession session({
            [&](const QString &, const QJsonObject &) {
                ++publications;
                stopConfirmed = active->requestStop();
                return true;
            },
            [&](const QString &) { return restore; }
        });
        active = &session;
        QVERIFY(session.start());
        QSignalSpy restored(&session, &OpenVpnDnsSession::stopRestored);
        QSignalSpy failed(&session, &OpenVpnDnsSession::failed);
        QTcpSocket peer; peer.connectToHost(QHostAddress::LocalHost, session.port());
        QVERIFY(peer.waitForConnected(1000));
        frame(peer); request(peer, "PUBLISH", 1);
        QTRY_COMPARE_WITH_TIMEOUT(publications, 1, 1000);
        QVERIFY(!stopConfirmed); QVERIFY(!session.cleanupConfirmed());
        QTest::qWait(300); QVERIFY(!peer.bytesAvailable());
        QCOMPARE(restored.size(), 0); QCOMPARE(failed.size(), 0);
        restore = true;
        QTRY_VERIFY_WITH_TIMEOUT(peer.canReadLine(), 1000);
        QCOMPARE(peer.readLine(), QByteArray("needok 'AMNEZIA-DNS-PUBLISH:1' cancel\n"));
        QTRY_COMPARE_WITH_TIMEOUT(restored.size(), 1, 1000);
        QVERIFY(session.cleanupConfirmed()); QCOMPARE(publications, 1);
    }
    void preservedCannotAuthorizeFreshOwner()
    {
        int publications = 0;
        OpenVpnDnsSession session({
            [&](const QString &, const QJsonObject &) { ++publications; return true; },
            [](const QString &) { return true; }
        });
        QVERIFY(session.start());
        QTcpSocket peer; peer.connectToHost(QHostAddress::LocalHost, session.port());
        QVERIFY(peer.waitForConnected(1000));
        frame(peer, "preserved"); request(peer, "PUBLISH", 1);
        QTRY_VERIFY_WITH_TIMEOUT(peer.canReadLine(), 1000);
        QCOMPARE(peer.readLine(), QByteArray("needok 'AMNEZIA-DNS-PUBLISH:1' cancel\n"));
        QCOMPARE(publications, 0); QVERIFY(!session.active());
    }
    void guardFailureAndNativeExitRetainCleanup()
    {
        bool restored = false;
        OpenVpnDnsSession session({
            [](const QString &, const QJsonObject &) { return true; },
            [&](const QString &) { return restored; }
        });
        QVERIFY(session.start());
        QTcpSocket peer; peer.connectToHost(QHostAddress::LocalHost, session.port());
        QVERIFY(peer.waitForConnected(1000));
        frame(peer); request(peer, "PUBLISH", 1);
        QTRY_VERIFY_WITH_TIMEOUT(peer.canReadLine(), 1000); peer.readLine();
        session.guardFailed();
        QVERIFY(!session.requestStop());
        QTest::qWait(300); QVERIFY(!peer.bytesAvailable());
        QSignalSpy finished(&session, &OpenVpnDnsSession::cleanupFinished);
        QVERIFY(!session.nativeFinished());
        QTest::qWait(300); QCOMPARE(finished.size(), 0);
        restored = true;
        QTRY_COMPARE_WITH_TIMEOUT(finished.size(), 1, 1000);
        QVERIFY(session.cleanupConfirmed());
        QTest::qWait(300); QCOMPARE(finished.size(), 1);
    }
    void managementLossRestoresBeforeKillPermission()
    {
        bool restored = false;
        OpenVpnDnsSession session({
            [](const QString &, const QJsonObject &) { return true; },
            [&](const QString &) { return restored; }
        });
        QVERIFY(session.start());
        QSignalSpy safe(&session, &OpenVpnDnsSession::disconnectedAfterRestore);
        QTcpSocket peer; peer.connectToHost(QHostAddress::LocalHost, session.port());
        QVERIFY(peer.waitForConnected(1000));
        frame(peer); request(peer, "PUBLISH", 1);
        QTRY_VERIFY_WITH_TIMEOUT(peer.canReadLine(), 1000); peer.readLine();
        peer.abort();
        QTest::qWait(300); QCOMPARE(safe.size(), 0); QVERIFY(!session.cleanupConfirmed());
        restored = true;
        QTRY_COMPARE_WITH_TIMEOUT(safe.size(), 1, 1000);
        QVERIFY(session.cleanupConfirmed());
    }
};

QTEST_GUILESS_MAIN(TestOpenVpnDnsSession)
#include "testOpenVpnDnsSession.moc"
