#include <QtTest>
#include <QJsonArray>
#include <QJsonDocument>
#include <QFile>
#include <QProcess>
#include <QSslCertificate>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include "core/utils/connectionUpdates.h"
#include "core/models/selfhosted/selfHostedUserServerConfig.h"

using namespace amnezia;
#include "fixtures.h"
using namespace connectionUpdateTestFixtures;
class TestConnectionUpdates : public QObject {
    Q_OBJECT
private slots:
    void keepsDeviceAndLocalSettings_data() { QTest::addColumn<bool>("awg"); QTest::newRow("wireguard") << false; QTest::newRow("awg") << true; }
    void keepsDeviceAndLocalSettings()
    {
        QFETCH(bool, awg); const auto original = profile(awg); QVERIFY(connectionUpdates::validateProfile(original));
        QJsonObject updated; QVERIFY(connectionUpdates::apply(original, sign(payload(original, awg)), 2000000001, updated));
        const auto before = client(original, awg), after = client(updated, awg);
        for (const auto *k : { "client_priv_key", "client_pub_key", "psk_key", "client_ip", "mtu", "allowed_ips", "persistent_keep_alive" }) QCOMPARE(after.value(k), before.value(k));
        for (const auto *k : { "description", "dns1", "splitTunnelSites" }) QCOMPARE(updated.value(k), original.value(k));
        QCOMPARE(after.value("hostName").toString(), "vpn2.example.test");
        QVERIFY(after.value("config").toString().contains("PrivateKey = local-device-key"));
        QVERIFY(after.value("config").toString().contains("DNS = 192.0.2.53"));
        QVERIFY(after.value("config").toString().contains("Endpoint = vpn2.example.test:51821"));
        QJsonObject renewed; QVERIFY(connectionUpdates::apply(updated, sign(payload(original, awg)), 2000000002, renewed));
        auto bad = payload(original, awg); auto s = bad["settings"].toObject(); s["hostName"] = "other.example.test"; bad["settings"] = s;
        QVERIFY(!connectionUpdates::apply(updated, sign(bad), 2000000002, renewed));
    }
    void signedPathProbeMigratesExistingKeys_data() { keepsDeviceAndLocalSettings_data(); }
    void signedPathProbeMigratesExistingKeys()
    {
        QFETCH(bool, awg); const auto original = profile(awg); auto update = payload(original, awg);
        update["pathMtuProbe"] = "10.8.0.1";
        QJsonObject migrated; QVERIFY(connectionUpdates::apply(original, sign(update), 2000000001, migrated));
        const auto before = client(original, awg), after = client(migrated, awg);
        QCOMPARE(after.value("path_mtu_probe").toString(), "10.8.0.1");
        for (const auto *key : { "client_priv_key", "client_pub_key", "psk_key", "client_ip", "mtu", "allowed_ips" }) QCOMPARE(after.value(key), before.value(key));
        QVERIFY(connectionUpdates::validateProfile(migrated));
        QJsonObject renewed; QVERIFY(connectionUpdates::apply(migrated, sign(update), 2000000002, renewed));
        auto changed = update; changed["pathMtuProbe"] = "10.8.0.9";
        QJsonObject rejected { { "sentinel", true } };
        QVERIFY(!connectionUpdates::apply(migrated, sign(changed), 2000000002, rejected)); QCOMPARE(rejected.size(), 1);
        changed["revision"] = "2";
        QVERIFY(connectionUpdates::apply(migrated, sign(changed), 2000000002, renewed));
        QCOMPARE(client(renewed, awg).value("path_mtu_probe").toString(), "10.8.0.9");
        for (const auto &bad : { "127.0.0.1", "0.0.0.0", "255.255.255.255", "224.0.0.1", "fe80::1", "vpn.example.test", "10.8.0.1\n" }) {
            auto invalid = update; invalid["pathMtuProbe"] = bad; QJsonObject output { { "sentinel", true } };
            QVERIFY2(!connectionUpdates::apply(original, sign(invalid), 2000000001, output), bad); QCOMPARE(output.size(), 1);
        }
        // Old delivery service omits the extension; valid cached target survives.
        auto legacy = payload(original, awg); legacy["revision"] = "3";
        QVERIFY(connectionUpdates::apply(renewed, sign(legacy), 2000000003, migrated));
        QCOMPARE(client(migrated, awg).value("path_mtu_probe").toString(), "10.8.0.9");
    }
    void signedIPv6ProbeRequiresCapturedFamilyAndAllowedRoute()
    {
        auto original = profile(); auto containers = original["containers"].toArray(); auto container = containers[0].toObject();
        auto proto = container["wireguard"].toObject(); auto c = client(original, false);
        c["client_ip"] = "10.8.0.2/32, fd77::2/128"; c["allowed_ips"] = QJsonArray { "0.0.0.0/0", "fd77::/64" };
        proto["last_config"] = QString::fromUtf8(QJsonDocument(c).toJson(QJsonDocument::Compact)); container["wireguard"] = proto; containers[0] = container; original["containers"] = containers;
        auto update = payload(original); update["pathMtuProbe"] = "fd77::1";
        QJsonObject migrated; QVERIFY(connectionUpdates::apply(original, sign(update), 2000000001, migrated));
        QCOMPARE(client(migrated, false).value("path_mtu_probe").toString(), "fd77::1");
        QCOMPARE(client(migrated, false).value("client_ip"), c.value("client_ip"));
        update["pathMtuProbe"] = "fd78::1"; QJsonObject rejected { { "sentinel", true } };
        QVERIFY(connectionUpdates::apply(original, sign(update), 2000000001, rejected));
        QVERIFY(!client(rejected, false).contains("path_mtu_probe"));
        QCOMPARE(client(rejected, false).value("allowed_ips"), c.value("allowed_ips"));
        update["pathMtuProbe"] = 42; QVERIFY(!connectionUpdates::apply(original, sign(update), 2000000001, rejected));
    }
    void signedClientIPv6Lifecycle_data() { keepsDeviceAndLocalSettings_data(); }
    void signedClientIPv6Lifecycle()
    {
        QFETCH(bool, awg); const auto original = profile(awg); const auto before = client(original, awg);
        auto update = payload(original, awg); update["clientIpv6"] = "fd77::2";
        QJsonObject added; QVERIFY(connectionUpdates::apply(original, sign(update), 2000000001, added));
        auto after = client(added, awg);
        QCOMPARE(after.value("client_ip").toString(), "10.8.0.2, fd77::2/128");
        QVERIFY(after.value("config").toString().contains("Address = 10.8.0.2/32, fd77::2/128\n"));
        for (const auto *key : { "client_priv_key", "client_pub_key", "psk_key", "mtu", "allowed_ips" }) QCOMPARE(after.value(key), before.value(key));
        QVERIFY(after.value("config").toString().contains("DNS = 192.0.2.53\n"));
        QJsonObject repeated; QVERIFY(connectionUpdates::apply(added, sign(update), 2000000002, repeated));
        QCOMPARE(client(repeated, awg), after);
        auto changed = update; changed["clientIpv6"] = "fd77::3";
        QJsonObject rejected { { "sentinel", true } };
        QVERIFY(!connectionUpdates::apply(added, sign(changed), 2000000002, rejected)); QCOMPARE(rejected.size(), 1);
        changed["revision"] = "2";
        QJsonObject replaced; QVERIFY(connectionUpdates::apply(added, sign(changed), 2000000002, replaced));
        QCOMPARE(client(replaced, awg).value("client_ip").toString(), "10.8.0.2, fd77::3/128");
        auto legacy = payload(original, awg); legacy["revision"] = "3";
        QJsonObject retained; QVERIFY(connectionUpdates::apply(replaced, sign(legacy), 2000000003, retained));
        QCOMPARE(client(retained, awg), client(replaced, awg));
        changed["revision"] = "4"; changed["clientIpv6"] = "";
        QJsonObject withdrawn; QVERIFY(connectionUpdates::apply(retained, sign(changed), 2000000004, withdrawn));
        QCOMPARE(client(withdrawn, awg).value("client_ip"), before.value("client_ip"));
        QVERIFY(client(withdrawn, awg).value("config").toString().contains("Address = 10.8.0.2/32\n"));
        QVERIFY(!withdrawn.value("connectionUpdates").toObject().contains("managedClientIpv6"));
    }
    void signedClientIPv6RespectsLocalConfiguration()
    {
        auto changeClient = [](QJsonObject p, const QJsonObject &c) {
            auto containers = p["containers"].toArray(); auto container = containers[0].toObject();
            auto proto = container["wireguard"].toObject();
            proto["last_config"] = QString::fromUtf8(QJsonDocument(c).toJson(QJsonDocument::Compact));
            container["wireguard"] = proto; containers[0] = container; p["containers"] = containers; return p;
        };
        const auto original = profile(); auto local = client(original, false);
        local["client_ip"] = "10.8.0.2, fd77::2/128";
        auto native = local["config"].toString(); native.replace("Address = 10.8.0.2/32", "Address = 10.8.0.2/32, fd77::2/128");
        local["config"] = native; const auto preexisting = changeClient(original, local);
        auto update = payload(original); update["clientIpv6"] = "fd77::2";
        QJsonObject adopted; QVERIFY(connectionUpdates::apply(preexisting, sign(update), 2000000001, adopted));
        QVERIFY(!adopted["connectionUpdates"].toObject().contains("managedClientIpv6"));
        update["revision"] = "2"; update["clientIpv6"] = "";
        QJsonObject withdrawn; QVERIFY(connectionUpdates::apply(adopted, sign(update), 2000000002, withdrawn));
        QCOMPARE(client(withdrawn, false).value("client_ip"), local.value("client_ip"));
        auto subnetLocal = local;
        subnetLocal["client_ip"] = "10.8.0.2, fd77::2/64";
        subnetLocal["config"] = native.replace("fd77::2/128", "fd77::2/64");
        auto subnetUpdate = payload(original); subnetUpdate["clientIpv6"] = "fd77::2";
        QJsonObject subnetResult;
        QVERIFY(connectionUpdates::apply(changeClient(original, subnetLocal), sign(subnetUpdate), 2000000001, subnetResult));
        QCOMPARE(client(subnetResult, false).value("client_ip"), subnetLocal.value("client_ip"));
        QVERIFY(!subnetResult["connectionUpdates"].toObject().contains("managedClientIpv6"));
        update["revision"] = "1"; update["clientIpv6"] = "fd77::3";
        for (int scenario = 0; scenario < 4; ++scenario) {
            auto bad = client(original, false);
            if (scenario == 0) bad["mtu"] = "1200";
            if (scenario == 1) bad["client_ip"] = "10.8.0.9";
            if (scenario == 2) bad["config"] = bad["config"].toString() + "[Interface]\nAddress = 10.8.0.2/32\n";
            if (scenario == 3) { auto config = bad["config"].toString(); config.remove("Address = 10.8.0.2/32\n"); bad["config"] = config; }
            QJsonObject output { { "sentinel", true } };
            QVERIFY(!connectionUpdates::apply(changeClient(original, bad), sign(update), 2000000001, output));
            QCOMPARE(output, (QJsonObject { { "sentinel", true } }));
        }
    }
    void rejectsMalformedSignedClientIPv6_data() { keepsDeviceAndLocalSettings_data(); }
    void rejectsMalformedSignedClientIPv6()
    {
        QFETCH(bool, awg); const auto original = profile(awg);
        const QList<QJsonValue> invalid { QJsonValue(), QJsonValue(42), QJsonValue(true),
            QJsonArray { "fd77::2" }, "10.8.0.2", "::", "::1", "::2", "::ffff:192.0.2.1",
            "fe80::2", "ff02::2", "fd77::2/128", "fd77::2%eth0", "FD77::2", "fd77:0::2",
            "fd77::2\n", "vpn.example.test" };
        for (const auto &address : invalid) {
            auto update = payload(original, awg); update["clientIpv6"] = address;
            QJsonObject output { { "sentinel", true } };
            QVERIFY2(!connectionUpdates::apply(original, sign(update), 2000000001, output),
                     qPrintable(QJsonDocument(QJsonArray { address }).toJson(QJsonDocument::Compact)));
            QCOMPARE(output, (QJsonObject { { "sentinel", true } }));
        }
    }
    void rejectsInvalidUpdates()
    {
        const auto original = profile(); const auto good = payload(original);
        const QList<QPair<QString, QJsonValue>> mutations { { "id", QString(32, 'a') }, { "clientPublicKey", "other" }, { "container", "amnezia-awg2" },
            { "version", 2 }, { "type", "other" }, { "revision", "0" }, { "revision", "01" }, { "revision", "18446744073709551616" },
            { "issuedAt", 2000000400 }, { "expiresAt", 2000000000 }, { "expiresAt", 2000000601 } };
        for (const auto &mutation : mutations) { auto bad = good; bad[mutation.first] = mutation.second; QJsonObject output { { "sentinel", true } };
            QVERIFY2(!connectionUpdates::apply(original, sign(bad), 2000000001, output), qPrintable(mutation.first)); QCOMPARE(output.size(), 1); }
        for (const auto *k : { "client_priv_key", "dns1", "allowed_ips", "config", "PostUp", "token" }) {
            auto bad = good; auto s = settings(); s[k] = "injected"; bad["settings"] = s; QJsonObject out;
            QVERIFY(!connectionUpdates::apply(original, sign(bad), 2000000001, out));
        }
        auto tampered = QJsonDocument::fromJson(sign(good)).object(); tampered["signature"] = QString::fromLatin1(QByteArray(64, 'z').toBase64()); QJsonObject out;
        QVERIFY(!connectionUpdates::apply(original, QJsonDocument(tampered).toJson(), 2000000001, out));
        QVERIFY(!connectionUpdates::apply(original, QByteArray(65537, 'x'), 2000000001, out));
        auto newer = good; newer["revision"] = "2"; QVERIFY(connectionUpdates::apply(original, sign(newer), 2000000001, out));
        QJsonObject rejected; QVERIFY(!connectionUpdates::apply(out, sign(good), 2000000002, rejected));
    }
    void rejectsUnsafeBootstrap()
    {
        const auto good = profile();
        for (const auto &url : { "http://updates.example.test/v1/connections/0123456789abcdef0123456789abcdef", "https://u:p@updates.example.test/v1/connections/0123456789abcdef0123456789abcdef", "https://updates.example.test/path", "https://updates.example.test/v1/connections/0123456789abcdef0123456789abcdef?token=x" }) {
            auto bad = good; auto m = bad["connectionUpdates"].toObject(); m["url"] = url; bad["connectionUpdates"] = m; QVERIFY(!connectionUpdates::validateProfile(bad));
        }
        auto bad = good; bad["userName"] = "root"; QVERIFY(!connectionUpdates::validateProfile(bad));
        bad = good; auto m = bad["connectionUpdates"].toObject(); m["clientPublicKey"] = "other"; bad["connectionUpdates"] = m; QVERIFY(!connectionUpdates::validateProfile(bad));
    }
    void invitationDoesNotExposeAdministrativeState()
    {
        auto admin = profile().value("connectionUpdates").toObject();
        admin["pendingRevocations"] = QJsonArray { QJsonObject { { "clientPublicKey", "another-client" } } };
        const auto invitation = connectionUpdates::invitationMetadata(admin);
        QCOMPARE(invitation.keys(), QStringList({ "certificate", "publicKey", "url", "version" }));
    }
    void attachKeepsExistingIdentityAndReplayState()
    {
        auto staticProfile = profile(); const auto metadata = staticProfile.take("connectionUpdates").toObject();
        const QJsonObject invitation { { "type", "amnezia-update-invitation" }, { "version", 1 },
            { "existingServerPublicKey", client(staticProfile, false).value("server_pub_key") }, { "connectionUpdates", metadata } };
        QJsonObject attached; QVERIFY(connectionUpdates::attachInvitation(staticProfile, invitation, attached));
        auto unchanged = attached; unchanged.remove("connectionUpdates"); QCOMPARE(unchanged, staticProfile);
        QJsonObject refreshed; QVERIFY(connectionUpdates::apply(attached, sign(payload(attached)), 2000000001, refreshed));
        auto replay = refreshed; auto m = replay["connectionUpdates"].toObject(); m["futureLocalField"] = "keep"; replay["connectionUpdates"] = m;
        QJsonObject reattached; QVERIFY(connectionUpdates::attachInvitation(replay, invitation, reattached));
        QCOMPARE(reattached.value("connectionUpdates"), replay.value("connectionUpdates"));
        auto wrong = invitation; wrong["existingServerPublicKey"] = QString::fromLatin1(QByteArray(32, 'X').toBase64());
        QVERIFY(!connectionUpdates::attachInvitation(staticProfile, wrong, reattached));
        wrong = staticProfile; wrong["userName"] = "root"; QVERIFY(!connectionUpdates::attachInvitation(wrong, invitation, reattached));
    }
    void administratorMergeKeepsSshAndOtherContainers()
    {
        auto admin = profile(true); admin["hostName"] = "192.0.2.10"; admin["vpnHostName"] = "vpn1.example.test"; admin["userName"] = "root"; admin["port"] = 22;
        auto containers = admin["containers"].toArray(); const auto other = profile()["containers"].toArray().at(0); containers.append(other); admin["containers"] = containers;
        QJsonObject merged; QVERIFY(connectionUpdates::mergeServerSettings(admin, "amnezia-awg2", settings(true), true, merged));
        QCOMPARE(merged.value("hostName"), admin.value("hostName")); QCOMPARE(merged.value("vpnHostName"), admin.value("vpnHostName"));
        QCOMPARE(merged.value("port"), admin.value("port")); QCOMPARE(merged["containers"].toArray()[1], other);
        QCOMPARE(client(merged, true).value("client_priv_key"), client(admin, true).value("client_priv_key"));
        QCOMPARE(client(merged, true).value("HeaderProtectionKey"), settings(true).value("HeaderProtectionKey"));
    }
    void managementProbeMergeKeepsCredentialsAndOtherContainers()
    {
        auto admin = profile(true); admin["userName"] = "root"; admin["password"] = "local-secret"; admin["port"] = 2222;
        auto containers = admin["containers"].toArray(); const auto other = profile()["containers"].toArray().at(0); containers.append(other); admin["containers"] = containers;
        QJsonObject merged; QVERIFY(connectionUpdates::mergePathProbe(admin, "amnezia-awg2", "10.8.0.1", merged));
        QCOMPARE(merged.value("userName"), admin.value("userName")); QCOMPARE(merged.value("password"), admin.value("password"));
        QCOMPARE(merged.value("port"), admin.value("port")); QCOMPARE(merged["containers"].toArray()[1], other);
        const auto before = client(admin, true), after = client(merged, true);
        for (const auto *key : { "client_priv_key", "client_pub_key", "psk_key", "client_ip", "allowed_ips", "config", "hostName" }) QCOMPARE(after.value(key), before.value(key));
        QCOMPARE(after.value("path_mtu_probe").toString(), "10.8.0.1");
        QJsonObject rejected { { "sentinel", true } };
        QVERIFY(!connectionUpdates::mergePathProbe(admin, "amnezia-awg2", "localhost", rejected)); QCOMPARE(rejected.size(), 1);
        containers.append(containers.at(0)); admin["containers"] = containers;
        QVERIFY(!connectionUpdates::mergePathProbe(admin, "amnezia-awg2", "10.8.0.1", rejected)); QCOMPARE(rejected.size(), 1);
    }
    void readinessProofMatchesGoWithoutSendingPrivateKey()
    {
        QFile file(":/connection-updates/readiness-interop.json"); QVERIFY(file.open(QIODevice::ReadOnly));
        const auto fixture = QJsonDocument::fromJson(file.readAll()).object();
        const auto envelope = QJsonDocument(fixture.value("envelope").toObject()).toJson(QJsonDocument::Compact);
        const auto proof = connectionUpdates::readinessProof(profile(), envelope, 2000000001);
        QCOMPARE(proof.size(), 32); QCOMPARE(QString::fromLatin1(proof.toBase64()), fixture.value("proof").toString());
        auto wrong = QJsonDocument::fromJson(envelope).object(); wrong["signature"] = QString::fromLatin1(QByteArray(64, 'X').toBase64());
        QVERIFY(connectionUpdates::readinessProof(profile(), QJsonDocument(wrong).toJson(), 2000000001).isEmpty());
        QVERIFY(connectionUpdates::readinessProof(profile(), envelope, 2000000601).isEmpty());
        auto zero = payload(profile()); zero["ackChallenge"] = QString::fromLatin1(QByteArray(32, '\0').toBase64());
        QVERIFY(connectionUpdates::readinessProof(profile(), sign(zero), 2000000001).isEmpty());
    }
    void activeInterfaceProbeRequiresSuccessfulRead()
    {
        QString target = "keep";
        const QString marker = "\namnezia_interface_addresses=ok\n";
        QFile captured(":/connection-updates/interface-addresses.txt"); QVERIFY(captured.open(QIODevice::ReadOnly));
        QVERIFY(connectionUpdates::parsePathProbeAddress(QString::fromUtf8(captured.readAll()), "wg0", target)); QCOMPARE(target, "10.77.0.9");
        QVERIFY(connectionUpdates::parsePathProbeAddress("7: wg0 inet 10.77.0.9/24 scope global wg0\n7: wg0 inet6 fd77::1/64 scope global" + marker, "wg0", target));
        QCOMPARE(target, "10.77.0.9");
        QVERIFY(connectionUpdates::parsePathProbeAddress("8: awg0 inet6 fd77::9/64 scope global" + marker, "awg0", target)); QCOMPARE(target, "fd77::9");
        const QStringList invalid { "", "7: wg0 inet 10.77.0.9/24 scope global", "7: eth0 inet 10.77.0.9/24 scope global" + marker,
            "7: wg0 inet 127.0.0.1/8 scope global" + marker, "7: wg0 inet6 fe80::1/64 scope global" + marker,
            "7: wg0 inet 10.77.0.9/99 scope global" + marker, "7: wg0 inet 10.77.0.9 scope global" + marker,
            "Address = 10.77.0.9/24" + marker, "7: wg0 inet6 10.77.0.9/24 scope global" + marker };
        for (const auto &output : invalid) { target = "keep"; QVERIFY(!connectionUpdates::parsePathProbeAddress(output, "wg0", target)); QCOMPARE(target, "keep"); }
    }
    void peerListRequiresSuccessfulTerminalMarker()
    {
        const auto pub = QString::fromLatin1(publicKey(deviceSeed, EVP_PKEY_X25519).toBase64());
        QStringList peers { "keep" };
        QVERIFY(!connectionUpdates::parsePeerList("", peers)); QCOMPARE(peers, QStringList { "keep" });
        QVERIFY(!connectionUpdates::parsePeerList(pub + "\n", peers));
        QVERIFY(!connectionUpdates::parsePeerList("bad-key\n\namnezia_peers=ok\n", peers));
        QVERIFY(connectionUpdates::parsePeerList(pub + "\n\namnezia_peers=ok\n", peers)); QCOMPARE(peers, QStringList { pub });
        QVERIFY(connectionUpdates::parsePeerList("\namnezia_peers=ok\n", peers)); QVERIFY(peers.isEmpty());
    }
    void probeExtensionKeepsLegacyPublicSettings()
    {
        QFile file(":/connection-updates/path-probe-interop.json"); QVERIFY(file.open(QIODevice::ReadOnly));
        const auto fixture = QJsonDocument::fromJson(file.readAll()).object(); const auto original = profile(); QJsonObject updated;
        QVERIFY(connectionUpdates::apply(original, QJsonDocument(fixture.value("envelope").toObject()).toJson(), 2000000001, updated));
        QCOMPARE(client(updated, false).value("hostName").toString(), "vpn2.example.test");
        QCOMPARE(client(updated, false).value("client_priv_key"), client(original, false).value("client_priv_key"));
        QCOMPARE(client(updated, false).value("allowed_ips"), client(original, false).value("allowed_ips"));
    }
    void goPathProbeInteroperability()
    {
        QFile file(":/connection-updates/path-probe-interop.json"); QVERIFY(file.open(QIODevice::ReadOnly));
        const auto fixture = QJsonDocument::fromJson(file.readAll()).object(); const auto original = profile(); QJsonObject migrated;
        QVERIFY(connectionUpdates::apply(original, QJsonDocument(fixture.value("envelope").toObject()).toJson(), 2000000001, migrated));
        QCOMPARE(client(migrated, false).value("path_mtu_probe").toString(), "10.8.0.1");
        QCOMPARE(client(migrated, false).value("client_priv_key"), client(original, false).value("client_priv_key"));
    }
    void signedIPv6WithdrawalRevalidatesCachedProbe()
    {
        auto original = profile(); auto c = client(original, false);
        c["allowed_ips"] = QJsonArray { "0.0.0.0/0", "::/0" };
        auto containers = original["containers"].toArray(); auto container = containers[0].toObject();
        auto proto = container["wireguard"].toObject();
        proto["last_config"] = QString::fromUtf8(QJsonDocument(c).toJson(QJsonDocument::Compact));
        container["wireguard"] = proto; containers[0] = container; original["containers"] = containers;
        auto update = payload(original); update["clientIpv6"] = "fd77::2"; update["pathMtuProbe"] = "fd77::1";
        QJsonObject migrated; QVERIFY(connectionUpdates::apply(original, sign(update), 2000000001, migrated));
        QCOMPARE(client(migrated, false).value("path_mtu_probe").toString(), "fd77::1");
        update.remove("pathMtuProbe"); update["clientIpv6"] = ""; update["revision"] = "2";
        QJsonObject withdrawn; QVERIFY(connectionUpdates::apply(migrated, sign(update), 2000000002, withdrawn));
        QVERIFY(!client(withdrawn, false).contains("path_mtu_probe"));
        // Keep authenticated metadata so a later compatible address can restore the target.
        update["clientIpv6"] = "fd77::3"; update["revision"] = "3";
        QJsonObject restored; QVERIFY(connectionUpdates::apply(withdrawn, sign(update), 2000000003, restored));
        QCOMPARE(client(restored, false).value("path_mtu_probe").toString(), "fd77::1");
        QCOMPARE(client(restored, false).value("allowed_ips"), c.value("allowed_ips"));
    }
    void livePeerIPv6AssignmentsRequireUnambiguousKeyBinding()
    {
        const auto a = QString::fromLatin1(QByteArray(32, 'A').toBase64());
        const auto b = QString::fromLatin1(QByteArray(32, 'B').toBase64());
        const QString marker = "\namnezia_peer_addresses=ok\n";
        QJsonObject result;
        QVERIFY(connectionUpdates::parsePeerIPv6Assignments(a + "\t10.8.0.2/32 fd77::2/128\n" + b + "\t10.8.0.3/32\n" + marker, result));
        QCOMPARE(result.value(a).toString(), "fd77::2"); QCOMPARE(result.value(b).toString(), "");
        QVERIFY(connectionUpdates::parsePeerIPv6Assignments(a + "\t10.8.0.2/32, fd77::2/128\n" + marker, result));
        QCOMPARE(result.value(a).toString(), "fd77::2");
        QVERIFY(connectionUpdates::parsePeerIPv6Assignments(a + "\t(none)\n" + marker, result));
        QCOMPARE(result.value(a).toString(), "");
        const QStringList invalid {
            a + "\tfd77::/64\n", a + "\t::/0\n", a + "\tfd77::2/128 fd77::3/128\n",
            a + "\tfd77::2/128\n" + b + "\tfd77::2/128\n", a + "\tfd77::2/128\n" + a + "\t10.8.0.2/32\n",
            "bad-key\tfd77::2/128\n", a + "\tfe80::2/128\n", a + "\t::ffff:192.0.2.1/128\n",
            a + "\tfd77::2\n", a + "\tvpn.example.test/128\n", a + "\t\n", a + "\t10.8.0.2/999\n",
            a + "\tFD77::2/128\n", a + " fd77::2/128\n", a + "\tfd77::2/128\textra\n"
        };
        for (const auto &body : invalid) {
            QJsonObject unchanged { { "sentinel", true } };
            QVERIFY2(!connectionUpdates::parsePeerIPv6Assignments(body + marker, unchanged), qPrintable(body));
            QCOMPARE(unchanged, (QJsonObject { { "sentinel", true } }));
        }
        QJsonObject unchanged { { "sentinel", true } };
        QVERIFY(!connectionUpdates::parsePeerIPv6Assignments(a + "\tfd77::2/128\n", unchanged));
        QCOMPARE(unchanged.size(), 1);
        QVERIFY(!connectionUpdates::parsePeerIPv6Assignments(QString(1024 * 1024, 'x') + marker, unchanged));
        QVERIFY(connectionUpdates::parsePeerIPv6Assignments(marker, result)); QVERIFY(result.isEmpty());
    }
    void exportedIPv6AssignmentContainsOnlyRequestedClient()
    {
        const auto a = QString::fromLatin1(QByteArray(32, 'A').toBase64());
        const auto b = QString::fromLatin1(QByteArray(32, 'B').toBase64());
        QJsonObject assignments { { a, "fd77::2" }, { b, "fd77::3" } }, selected;
        QVERIFY(connectionUpdates::individualIPv6Assignment(assignments, a, selected));
        QCOMPARE(selected, (QJsonObject { { a, "fd77::2" } }));
        QVERIFY(connectionUpdates::individualIPv6Assignment(assignments, b, selected));
        QCOMPARE(selected, (QJsonObject { { b, "fd77::3" } }));
        assignments[a] = "";
        QVERIFY(connectionUpdates::individualIPv6Assignment(assignments, a, selected));
        QCOMPARE(selected, (QJsonObject { { a, "" } }));
        for (const auto &key : { QString("bad"), QString::fromLatin1(QByteArray(32, 'C').toBase64()) }) {
            QJsonObject output { { "sentinel", true } };
            QVERIFY(!connectionUpdates::individualIPv6Assignment(assignments, key, output)); QCOMPARE(output.size(), 1);
        }
        assignments[a] = "fd77::/64";
        QJsonObject output { { "sentinel", true } };
        QVERIFY(!connectionUpdates::individualIPv6Assignment(assignments, a, output)); QCOMPARE(output.size(), 1);
    }
    void goClientIPv6Interoperability()
    {
        QFile file(":/connection-updates/client-ipv6-interop.json"); QVERIFY(file.open(QIODevice::ReadOnly));
        const auto fixture = QJsonDocument::fromJson(file.readAll()).object(); const auto original = profile();
        QJsonObject migrated;
        QVERIFY(connectionUpdates::apply(original, QJsonDocument(fixture["envelope"].toObject()).toJson(), 2000000001, migrated));
        QCOMPARE(client(migrated, false).value("client_ip").toString(), "10.8.0.2, fd77::2/128");
        QCOMPARE(client(migrated, false).value("client_priv_key"), client(original, false).value("client_priv_key"));
        QCOMPARE(client(migrated, false).value("allowed_ips"), client(original, false).value("allowed_ips"));
    }
    void goInteroperability()
    {
        QFile file(QStringLiteral(":/connection-updates/interop.json")); QVERIFY(file.open(QIODevice::ReadOnly));
        const auto fixture = QJsonDocument::fromJson(file.readAll()).object(); auto p = profile(); auto m = p["connectionUpdates"].toObject();
        m["publicKey"] = fixture["publicKey"]; p["connectionUpdates"] = m; QJsonObject out;
        QVERIFY(connectionUpdates::apply(p, QJsonDocument(fixture["envelope"].toObject()).toJson(), 2000000001, out));
    }
};
QTEST_GUILESS_MAIN(TestConnectionUpdates)
#include "testConnectionUpdates.moc"
