#include <QtTest>
#include <QDateTime>
#include <QSignalSpy>
#include <QSslSocket>
#include <QSslKey>
#include <QTcpServer>
#include <QTimer>
#include <QUuid>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include "connection-updates/fixtures.h"
#include "core/controllers/selfhosted/connectionUpdatesController.h"
#include "core/controllers/selfhosted/importController.h"
#include "core/controllers/selfhosted/exportController.h"
#include "core/controllers/connectionController.h"
#include "core/controllers/serversController.h"
#include "ui/controllers/connectionUiController.h"
#include "vpnConnection.h"
#include "secureQSettings.h"

using namespace amnezia;
using namespace connectionUpdateTestFixtures;
class FeedServer : public QTcpServer {
public:
    QSslCertificate certificate;
    QSslKey key;
    QByteArray body, location, authorization;
    int status = 200, requests = 0, delay = 0;
    FeedServer()
    {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
        EVP_PKEY_keygen_init(ctx); EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1);
        EVP_PKEY *privateKey = nullptr; EVP_PKEY_keygen(ctx, &privateKey); EVP_PKEY_CTX_free(ctx);
        X509 *cert = X509_new(); X509_set_version(cert, 2); ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
        X509_gmtime_adj(X509_getm_notBefore(cert), -3600); X509_gmtime_adj(X509_getm_notAfter(cert), 86400); X509_set_pubkey(cert, privateKey);
        auto *name = X509_get_subject_name(cert);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("127.0.0.1"), -1, -1, 0);
        X509_set_issuer_name(cert, name);
        auto *san = X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name, const_cast<char *>("IP:127.0.0.1"));
        X509_add_ext(cert, san, -1); X509_EXTENSION_free(san); X509_sign(cert, privateKey, EVP_sha256());
        unsigned char *der = nullptr; const int size = i2d_X509(cert, &der); certificate = QSslCertificate(QByteArray(reinterpret_cast<char *>(der), size), QSsl::Der); OPENSSL_free(der);
        BIO *bio = BIO_new(BIO_s_mem()); PEM_write_bio_PrivateKey(bio, privateKey, nullptr, nullptr, 0, nullptr, nullptr);
        char *pem = nullptr; const auto len = BIO_get_mem_data(bio, &pem); key = QSslKey(QByteArray(pem, len), QSsl::Ec);
        BIO_free(bio); X509_free(cert); EVP_PKEY_free(privateKey);
    }
    void incomingConnection(qintptr descriptor) override
    {
        auto *socket = new QSslSocket(this); socket->setSocketDescriptor(descriptor); socket->setLocalCertificate(certificate); socket->setPrivateKey(key);
        socket->setPeerVerifyMode(QSslSocket::VerifyNone);
        connect(socket, &QSslSocket::disconnected, socket, &QObject::deleteLater);
        connect(socket, &QSslSocket::readyRead, this, [this, socket, buffer = QByteArray(), sent = false]() mutable {
            buffer += socket->readAll(); if (sent || !buffer.contains("\r\n\r\n")) return; sent = true; ++requests;
            for (const auto &line : buffer.split('\n')) if (line.toLower().startsWith("authorization:")) authorization = line.trimmed();
            const auto response = "HTTP/1.1 " + QByteArray::number(status) + " Result\r\nContent-Length: " + QByteArray::number(body.size()) + "\r\nConnection: close\r\n" + (location.isEmpty() ? QByteArray() : "Location: " + location + "\r\n") + "\r\n" + body;
            QTimer::singleShot(delay, socket, [socket, response] { socket->write(response); socket->disconnectFromHost(); });
        });
        socket->startServerEncryption();
    }
    QJsonObject bootstrap() const
    {
        auto p = profile(); auto m = p["connectionUpdates"].toObject();
        m["url"] = QString("https://127.0.0.1:%1/v1/connections/%2").arg(serverPort()).arg(m["id"].toString());
        m["certificate"] = QString::fromLatin1(certificate.toDer().toBase64()); p["connectionUpdates"] = m; return p;
    }
    void setUpdate(const QJsonObject &p)
    {
        auto data = payload(p); const auto now = QDateTime::currentSecsSinceEpoch(); data["issuedAt"] = now; data["expiresAt"] = now + 600; body = sign(data);
    }
};
class TestConnectionUpdatesController : public QObject {
    Q_OBJECT
private slots:
    void verifiedFetchAndPreservedStorage()
    {
        FeedServer feed; QVERIFY(feed.listen(QHostAddress::LocalHost)); auto p = feed.bootstrap(); feed.setUpdate(p);
        SecureQSettings settings("Amnezia-Updates-" + QUuid::createUuid().toString(), "test", nullptr, false);
        SecureServersRepository servers(&settings); SecureAppSettingsRepository app(&settings); VpnConnection vpn(&servers, &app); ConnectionController connection(&servers, &app, &vpn);
        app.setDomainRoutingConfig({ { "local-marker", "keep" } }); app.setPrimaryDns("192.0.2.53");
        ImportController importer(&servers, &app); importer.importConfig(p); QCOMPARE(servers.serversCount(), 1);
        const auto id = servers.serverIdAt(0); const auto before = *servers.serverJsonById(id);
        ConnectionUpdatesController updates(&servers, &connection); QSignalSpy finished(&updates, &ConnectionUpdatesController::finished);
        QVERIFY(updates.available(id)); updates.refresh(id); QTRY_COMPARE(finished.count(), 1); QVERIFY(finished[0][0].toBool());
        QCOMPARE(feed.requests, 1); QVERIFY(feed.authorization.startsWith("Authorization: Bearer "));
        auto result = *servers.serverJsonById(id); QCOMPARE(result["hostName"].toString(), "vpn2.example.test");
        QCOMPARE(client(result, false)["client_priv_key"], client(before, false)["client_priv_key"]);
        QCOMPARE(app.primaryDns(), "192.0.2.53"); QCOMPARE(app.domainRoutingConfig().value("local-marker").toString(), "keep");
        // Typed profile edits and application restart retain trust and replay state.
        auto typed = *servers.selfHostedUserConfig(id); typed.description = "Renamed locally"; servers.editServer(id, typed.toJson(), serverConfigUtils::SelfHostedUser);
        servers.invalidateCache(); QVERIFY(updates.available(id)); QCOMPARE(servers.selfHostedUserConfig(id)->connectionUpdates.value("revision").toString(), "1");
        // A second publication cannot overwrite a local edit made while fetching.
        feed.delay = 100; const auto snapshot = *servers.serverJsonById(id); updates.refresh(id);
        auto renamed = snapshot; renamed["description"] = "Edited during request"; servers.editServer(id, renamed, serverConfigUtils::SelfHostedUser);
        QTRY_COMPARE(finished.count(), 2); QVERIFY(!finished[1][0].toBool()); QCOMPARE(*servers.serverJsonById(id), renamed);
        settings.clearSettings();
    }
    void rejectsTransportAndRetainsCachedProfile_data()
    {
        QTest::addColumn<QString>("failure");
        for (const auto *name : { "wrong-certificate", "redirect", "revoked", "tampered", "oversized" }) QTest::newRow(name) << QString(name);
    }
    void rejectsTransportAndRetainsCachedProfile()
    {
        QFETCH(QString, failure); FeedServer feed; QVERIFY(feed.listen(QHostAddress::LocalHost)); auto p = feed.bootstrap(); feed.setUpdate(p);
        FeedServer other; QVERIFY(other.listen(QHostAddress::LocalHost));
        if (failure == "wrong-certificate") { auto m = p["connectionUpdates"].toObject(); m["certificate"] = QString::fromLatin1(other.certificate.toDer().toBase64()); p["connectionUpdates"] = m; }
        if (failure == "redirect") { feed.status = 302; feed.location = QString("https://127.0.0.1:%1/stolen").arg(other.serverPort()).toLatin1(); }
        if (failure == "revoked") feed.status = 401;
        if (failure == "tampered") feed.body = "{}";
        if (failure == "oversized") feed.body = QByteArray(65537, 'x');
        SecureQSettings settings("Amnezia-Updates-" + QUuid::createUuid().toString(), "test", nullptr, false);
        SecureServersRepository servers(&settings); SecureAppSettingsRepository app(&settings); VpnConnection vpn(&servers, &app); ConnectionController connection(&servers, &app, &vpn);
        const auto id = servers.addServer({}, p, serverConfigUtils::SelfHostedUser); const auto original = *servers.serverJsonById(id);
        ConnectionUpdatesController updates(&servers, &connection); QSignalSpy finished(&updates, &ConnectionUpdatesController::finished);
        updates.refresh(id); QTRY_COMPARE(finished.count(), 1); QVERIFY(!finished[0][0].toBool()); QCOMPARE(*servers.serverJsonById(id), original); QCOMPARE(other.requests, 0);
        if (failure == "wrong-certificate") QCOMPARE(feed.requests, 0);
        bool continued = false; updates.refreshBeforeConnect(id, [&] { continued = true; }); QTRY_VERIFY(continued); QCOMPARE(*servers.serverJsonById(id), original);
        settings.clearSettings();
    }
    void administratorSharingRetainsServiceIdentity()
    {
        SecureQSettings settings("Amnezia-Updates-" + QUuid::createUuid().toString(), "test", nullptr, false);
        SecureServersRepository servers(&settings); SecureAppSettingsRepository app(&settings);
        auto admin = profile(); admin["userName"] = "root"; admin["password"] = "synthetic-ssh-secret"; admin["port"] = 22;
        auto metadata = admin["connectionUpdates"].toObject();
        for (const auto *field : { "id", "token", "revision", "clientPublicKey", "container" }) metadata.remove(field);
        admin["connectionUpdates"] = metadata;
        const auto id = servers.addServer({}, admin, serverConfigUtils::SelfHostedAdmin);
        ExportController exporter(&servers, &app); const auto exported = exporter.generateFullAccessConfig(id);
        QCOMPARE(exported.errorCode, ErrorCode::NoError);
        ImportController importer(&servers, &app); const auto parsed = importer.extractConfigFromData(exported.config);
        QCOMPARE(parsed.errorCode, ErrorCode::NoError); QSignalSpy imported(&importer, &ImportController::importFinished);
        importer.importConfig(parsed.config); QCOMPARE(imported.count(), 1);
        QCOMPARE(servers.selfHostedAdminConfig(servers.serverIdAt(1))->connectionUpdates, metadata);
        auto bad = profile(); auto badMetadata = bad["connectionUpdates"].toObject(); badMetadata["token"] = "bad"; bad["connectionUpdates"] = badMetadata;
        QSignalSpy errors(&importer, &ImportController::importErrorOccurred); importer.importConfig(bad);
        QCOMPARE(errors.count(), 1); QCOMPARE(servers.serversCount(), 2);
        settings.clearSettings();
    }
    void ordinaryProfileCanRetryAfterError()
    {
        SecureQSettings settings("Amnezia-Updates-" + QUuid::createUuid().toString(), "test", nullptr, false);
        SecureServersRepository servers(&settings); SecureAppSettingsRepository app(&settings); VpnConnection vpn(&servers, &app);
        ConnectionController connection(&servers, &app, &vpn);
        disconnect(&connection, &ConnectionController::openConnectionRequested, &vpn, &VpnConnection::connectToVpn);
        auto p = profile(); p.remove("connectionUpdates"); const auto id = servers.addServer({}, p, serverConfigUtils::SelfHostedUser);
        servers.setDefaultServer(id); ServersController serverController(&servers, &app);
        ConnectionUiController ui(&connection, &serverController); ConnectionUpdatesController updates(&servers, &connection);
        ui.setConnectionUpdatesController(&updates); QSignalSpy attempts(&connection, &ConnectionController::openConnectionRequested);
        vpn.setConnectionState(Vpn::ConnectionState::Error); ui.openConnection(); QCOMPARE(attempts.count(), 1);
        settings.clearSettings();
    }
    void canceledConnectDoesNotResume()
    {
        FeedServer feed; QVERIFY(feed.listen(QHostAddress::LocalHost)); auto p = feed.bootstrap(); feed.setUpdate(p); feed.delay = 150;
        SecureQSettings settings("Amnezia-Updates-" + QUuid::createUuid().toString(), "test", nullptr, false);
        SecureServersRepository servers(&settings); SecureAppSettingsRepository app(&settings); VpnConnection vpn(&servers, &app); ConnectionController connection(&servers, &app, &vpn);
        // Observe connection requests without activating an OS tunnel.
        disconnect(&connection, &ConnectionController::openConnectionRequested, &vpn, &VpnConnection::connectToVpn);
        const auto id = servers.addServer({}, p, serverConfigUtils::SelfHostedUser); servers.setDefaultServer(id);
        ServersController serverController(&servers, &app); ConnectionUpdatesController updates(&servers, &connection);
        ConnectionUiController ui(&connection, &serverController); ui.setConnectionUpdatesController(&updates);
        QSignalSpy attempts(&connection, &ConnectionController::openConnectionRequested), finished(&updates, &ConnectionUpdatesController::busyChanged);
        ui.openConnection(); QVERIFY(updates.busy()); ui.closeConnection(); QTRY_VERIFY(!updates.busy()); QCOMPARE(attempts.count(), 0);
        ui.openConnection(); ui.openConnection(); QTRY_COMPARE(attempts.count(), 1);
        QCOMPARE(attempts[0][2].toJsonObject().value("hostName").toString(), "vpn2.example.test");
        settings.clearSettings();
    }
};
QTEST_MAIN(TestConnectionUpdatesController)
#include "testConnectionUpdatesController.moc"
