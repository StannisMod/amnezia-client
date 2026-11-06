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
