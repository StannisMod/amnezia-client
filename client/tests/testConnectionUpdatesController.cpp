#include <QtTest>
#include <QDateTime>
#include <QSignalSpy>
#include <QSslSocket>
#include <QSslKey>
#include <QTcpServer>
#include <QTimer>
#include <QUuid>
#include <QSemaphore>
#include <QScopeGuard>
#include <atomic>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include "connection-updates/fixtures.h"
#include "core/utils/connectionUpdates.h"
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
    QString pathMtuProbe;
    int status = 200, requests = 0, delay = 0;
    bool advertiseAck = false;
    int ackStatus = 204, acknowledgements = 0, ackDelay = 0;
    QByteArray acknowledgementBody, ackLocation;
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
            buffer += socket->readAll(); const auto end = buffer.indexOf("\r\n\r\n");
            if (sent || end < 0) return;
            int length = 0;
            for (const auto &line : buffer.left(end).split('\n')) {
                if (line.toLower().startsWith("content-length:")) length = line.mid(line.indexOf(':') + 1).trimmed().toInt();
                if (line.toLower().startsWith("authorization:")) authorization = line.trimmed();
            }
            if (buffer.size() - end - 4 < length) return;
            sent = true; const bool receipt = buffer.startsWith("POST ");
            if (receipt) { ++acknowledgements; acknowledgementBody = buffer.mid(end + 4, length); } else ++requests;
            const auto responseBody = receipt ? QByteArray() : body;
            const auto redirect = receipt ? ackLocation : location;
            const auto code = receipt ? ackStatus : status;
            const auto response = "HTTP/1.1 " + QByteArray::number(code) + " Result\r\nContent-Length: " + QByteArray::number(responseBody.size())
                + "\r\nConnection: close\r\n" + (redirect.isEmpty() ? QByteArray() : "Location: " + redirect + "\r\n")
                + (!receipt && advertiseAck ? QByteArray("X-Amnezia-Update-Features: ack-v1\r\n") : QByteArray()) + "\r\n" + responseBody;
            QTimer::singleShot(receipt ? ackDelay : delay, socket, [socket, response] { socket->write(response); socket->disconnectFromHost(); });
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
        auto data = payload(p); const auto now = QDateTime::currentSecsSinceEpoch(); data["issuedAt"] = now; data["expiresAt"] = now + 600;
        if (advertiseAck) data["ackChallenge"] = QString::fromLatin1(publicKey(QByteArray(32, 'R'), EVP_PKEY_X25519).toBase64());
        if (!pathMtuProbe.isEmpty()) data["pathMtuProbe"] = pathMtuProbe;
        body = sign(data);
    }
};
class TestConnectionUpdatesController : public QObject {
    Q_OBJECT
private slots:
    void oldAdministratorProfileNeedsProbeRefreshOnce()
    {
        SecureQSettings settings("Amnezia-Probe-" + QUuid::createUuid().toString(), "test", nullptr, false);
        SecureServersRepository servers(&settings); SecureAppSettingsRepository app(&settings); VpnConnection vpn(&servers, &app); ConnectionController connection(&servers, &app, &vpn);
        auto administrator = profile(); administrator.remove("connectionUpdates"); administrator["userName"] = "root"; administrator["password"] = "test-password"; administrator["port"] = 22;
        const auto id = servers.addServer({}, administrator, serverConfigUtils::SelfHostedAdmin);
        ConnectionUpdatesController updates(&servers, &connection);
        QVERIFY(!updates.available(id)); QVERIFY(updates.needsRefreshBeforeConnect(id));
        QJsonObject migrated; QVERIFY(connectionUpdates::mergePathProbe(*servers.serverJsonById(id), "amnezia-wireguard", "10.8.0.1", migrated));
        servers.editServer(id, migrated, serverConfigUtils::SelfHostedAdmin);
        QVERIFY(!updates.needsRefreshBeforeConnect(id));
        settings.clearSettings();
    }
    void asynchronousAdminProbeRefresh_data()
    {
        QTest::addColumn<QString>("scenario");
        for (const auto *name : { "success", "failure", "edited", "deadline", "canceled" }) QTest::newRow(name) << QString(name);
    }
    void asynchronousAdminProbeRefresh()
    {
        QFETCH(QString, scenario);
        SecureQSettings settings("Amnezia-Probe-Async-" + QUuid::createUuid().toString(), "test", nullptr, false);
        SecureServersRepository servers(&settings); SecureAppSettingsRepository app(&settings); VpnConnection vpn(&servers, &app); ConnectionController connection(&servers, &app, &vpn);
        disconnect(&connection, &ConnectionController::openConnectionRequested, &vpn, &VpnConnection::connectToVpn);
        auto administrator = profile(); administrator.remove("connectionUpdates"); administrator["userName"] = "root"; administrator["password"] = "test-password"; administrator["port"] = 22;
        const auto id = servers.addServer({}, administrator, serverConfigUtils::SelfHostedAdmin); servers.setDefaultServer(id);
        const auto original = *servers.serverJsonById(id);
        QSemaphore gate; std::atomic<int> calls { 0 }; std::atomic<bool> correctReaderArguments { false };
        ConnectionUpdatesController updates(&servers, &connection, nullptr, [&](const ServerCredentials &credentials, DockerContainer container, QString &target) {
            correctReaderArguments.store(credentials.userName == "root" && container == DockerContainer::WireGuard);
            calls.fetch_add(1); gate.acquire(); target = "10.8.0.1";
            return scenario == "failure" ? ErrorCode::InternalError : ErrorCode::NoError;
        });
        const auto unblock = qScopeGuard([&] { gate.release(); });
        ServersController serverController(&servers, &app); ConnectionUiController ui(&connection, &serverController); ui.setConnectionUpdatesController(&updates);
        QSignalSpy attempts(&connection, &ConnectionController::openConnectionRequested);
        int continuations = 0;
        if (scenario == "canceled") ui.openConnection();
        else updates.refreshBeforeConnect(id, [&] { ++continuations; });
        QVERIFY(updates.busy()); QTRY_COMPARE(calls.load(), 1); QVERIFY(correctReaderArguments.load());
        if (scenario == "edited") { auto edited = original; edited["description"] = "user edit"; servers.editServer(id, edited, serverConfigUtils::SelfHostedAdmin); }
        if (scenario == "canceled") ui.closeConnection();
        if (scenario == "deadline") {
            QTRY_COMPARE_WITH_TIMEOUT(continuations, 1, 2500); QVERIFY(updates.busy()); QCOMPARE(*servers.serverJsonById(id), original);
        }
        gate.release(); QTRY_VERIFY(!updates.busy());
        if (scenario == "canceled") QCOMPARE(attempts.count(), 0);
        else QCOMPARE(continuations, 1);
        const auto result = *servers.serverJsonById(id);
        if (scenario == "success") {
            QCOMPARE(client(result, false).value("path_mtu_probe").toString(), "10.8.0.1");
            QCOMPARE(client(result, false).value("client_priv_key"), client(original, false).value("client_priv_key"));
        } else if (scenario == "failure" || scenario == "deadline") QCOMPARE(result, original);
        else if (scenario == "edited") { QCOMPARE(result.value("description").toString(), "user edit"); QVERIFY(!client(result, false).contains("path_mtu_probe")); }
        settings.clearSettings();
    }
    void realAdminProbeAddressRead()
    {
        const auto host = qEnvironmentVariable("AMNEZIA_SSH_PROBE_HOST");
        if (host.isEmpty()) QSKIP("Run scripts/local-tests/path-probe-ssh.sh with this test executable");
        ServerCredentials credentials; credentials.hostName = host; credentials.port = qEnvironmentVariableIntValue("AMNEZIA_SSH_PROBE_PORT");
        credentials.userName = "root"; credentials.secretData = "synthetic-probe-fixture";
        QString target = "keep";
        if (qEnvironmentVariable("AMNEZIA_SSH_PROBE_PHASE") == "missing") {
            QVERIFY(ConnectionUpdatesController::fetchPathMtuProbeAddress(credentials, DockerContainer::WireGuard, target) != ErrorCode::NoError);
            QCOMPARE(target, "keep"); return;
        }
        QCOMPARE(ConnectionUpdatesController::fetchPathMtuProbeAddress(credentials, DockerContainer::WireGuard, target), ErrorCode::NoError);
        QCOMPARE(target, "10.77.0.9");
        QCOMPARE(ConnectionUpdatesController::fetchPathMtuProbeAddress(credentials, DockerContainer::Awg2, target), ErrorCode::NoError);
        QCOMPARE(target, "fd88::9");
        SecureQSettings settings("Amnezia-Probe-SSH-" + QUuid::createUuid().toString(), "test", nullptr, false);
        SecureServersRepository servers(&settings); SecureAppSettingsRepository app(&settings); VpnConnection vpn(&servers, &app); ConnectionController connection(&servers, &app, &vpn);
        auto administrator = profile(); administrator.remove("connectionUpdates"); administrator["hostName"] = host;
        administrator["userName"] = credentials.userName; administrator["password"] = credentials.secretData; administrator["port"] = credentials.port;
        const auto id = servers.addServer({}, administrator, serverConfigUtils::SelfHostedAdmin);
        const auto original = *servers.serverJsonById(id);
        ConnectionUpdatesController updates(&servers, &connection); int continuations = 0;
        updates.refreshBeforeConnect(id, [&] { ++continuations; }); QTRY_VERIFY_WITH_TIMEOUT(!updates.busy(), 5000);
        QCOMPARE(continuations, 1); const auto migrated = *servers.serverJsonById(id);
        QCOMPARE(client(migrated, false).value("path_mtu_probe").toString(), "10.77.0.9");
        for (const auto *key : { "client_priv_key", "client_pub_key", "psk_key", "client_ip", "allowed_ips", "config" }) QCOMPARE(client(migrated, false).value(key), client(original, false).value(key));
        QCOMPARE(migrated.value("password"), original.value("password"));
        settings.clearSettings();
    }
    void realAdminPeerIPv6Read()
    {
        const auto host = qEnvironmentVariable("AMNEZIA_SSH_PROBE_HOST");
        if (host.isEmpty()) QSKIP("Run scripts/local-tests/path-probe-ssh.sh with this test executable");
        ServerCredentials credentials; credentials.hostName = host; credentials.port = qEnvironmentVariableIntValue("AMNEZIA_SSH_PROBE_PORT");
        credentials.userName = "root"; credentials.secretData = "synthetic-probe-fixture";
        for (const auto container : { DockerContainer::WireGuard, DockerContainer::Awg2 }) {
            QJsonObject assignments { { "sentinel", true } };
            const auto error = ConnectionUpdatesController::fetchPeerIPv6Assignments(credentials, container, assignments);
            if (qEnvironmentVariable("AMNEZIA_SSH_PROBE_PHASE") != "present") {
                QVERIFY(error != ErrorCode::NoError); QCOMPARE(assignments, (QJsonObject { { "sentinel", true } })); continue;
            }
            QCOMPARE(error, ErrorCode::NoError);
            const auto a = QString::fromLatin1(QByteArray(32, 'A').toBase64());
            const auto b = QString::fromLatin1(QByteArray(32, 'B').toBase64());
            const auto c = QString::fromLatin1(QByteArray(32, 'C').toBase64());
            QCOMPARE(assignments, (QJsonObject { { a, container == DockerContainer::Awg2 ? "fd88::2" : "fd77::2" }, { b, "" }, { c, "" } }));
        }
    }
    void verifiedFetchAndPreservedStorage()
    {
        FeedServer feed; QVERIFY(feed.listen(QHostAddress::LocalHost)); auto p = feed.bootstrap(); feed.pathMtuProbe = "10.8.0.1"; feed.setUpdate(p);
        SecureQSettings settings("Amnezia-Updates-" + QUuid::createUuid().toString(), "test", nullptr, false);
        SecureServersRepository servers(&settings); SecureAppSettingsRepository app(&settings); VpnConnection vpn(&servers, &app); ConnectionController connection(&servers, &app, &vpn);
        app.setDomainRoutingConfig({ { "local-marker", "keep" } }); app.setPrimaryDns("192.0.2.53");
        ImportController importer(&servers, &app); importer.importConfig(p); QCOMPARE(servers.serversCount(), 1);
        const auto id = servers.serverIdAt(0); const auto before = *servers.serverJsonById(id);
        ConnectionUpdatesController updates(&servers, &connection); QSignalSpy finished(&updates, &ConnectionUpdatesController::finished);
        QVERIFY(updates.available(id)); updates.refresh(id); QTRY_COMPARE(finished.count(), 1); QVERIFY(finished[0][0].toBool());
        QCOMPARE(feed.requests, 1); QVERIFY(feed.authorization.startsWith("Authorization: Bearer "));
        auto result = *servers.serverJsonById(id); QCOMPARE(result["hostName"].toString(), "vpn2.example.test");
        QCOMPARE(client(result, false).value("path_mtu_probe").toString(), "10.8.0.1");
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
    void verifiedFetchConfirmsDeviceReadiness()
    {
        FeedServer feed; feed.advertiseAck = true; QVERIFY(feed.listen(QHostAddress::LocalHost)); auto p = feed.bootstrap(); feed.setUpdate(p);
        SecureQSettings settings("Amnezia-Updates-" + QUuid::createUuid().toString(), "test", nullptr, false);
        SecureServersRepository servers(&settings); SecureAppSettingsRepository app(&settings); VpnConnection vpn(&servers, &app); ConnectionController connection(&servers, &app, &vpn);
        const auto id = servers.addServer({}, p, serverConfigUtils::SelfHostedUser); const auto original = *servers.serverJsonById(id);
        ConnectionUpdatesController updates(&servers, &connection); QSignalSpy finished(&updates, &ConnectionUpdatesController::finished);
        updates.refresh(id); QTRY_COMPARE(finished.count(), 1); QVERIFY(finished[0][0].toBool()); QCOMPARE(feed.requests, 1); QCOMPARE(feed.acknowledgements, 1);
        const auto receipt = QJsonDocument::fromJson(feed.acknowledgementBody).object();
        QCOMPARE(receipt.value("proof").toString(), QString::fromLatin1(connectionUpdates::readinessProof(original, feed.body, QDateTime::currentSecsSinceEpoch()).toBase64()));
        QVERIFY(!feed.acknowledgementBody.contains("client_priv_key")); QVERIFY(!feed.acknowledgementBody.contains(client(p, false).value("client_priv_key").toString().toLatin1()));
        FeedServer other; QVERIFY(other.listen(QHostAddress::LocalHost));
        feed.ackStatus = 302; feed.ackLocation = QString("https://127.0.0.1:%1/stolen").arg(other.serverPort()).toLatin1();
        updates.refresh(id); QTRY_COMPARE(finished.count(), 2); QVERIFY(finished[1][0].toBool()); QCOMPARE(other.requests, 0); QCOMPARE(other.acknowledgements, 0);
        QVERIFY(finished[1][1].toString() != finished[0][1].toString());
        settings.clearSettings();
    }
    void cancellingDuringReadinessDoesNotConnect()
    {
        FeedServer feed; feed.advertiseAck = true; feed.ackDelay = 200; QVERIFY(feed.listen(QHostAddress::LocalHost)); auto p = feed.bootstrap(); feed.setUpdate(p);
        SecureQSettings settings("Amnezia-Updates-" + QUuid::createUuid().toString(), "test", nullptr, false);
        SecureServersRepository servers(&settings); SecureAppSettingsRepository app(&settings); VpnConnection vpn(&servers, &app); ConnectionController connection(&servers, &app, &vpn);
        disconnect(&connection, &ConnectionController::openConnectionRequested, &vpn, &VpnConnection::connectToVpn);
        const auto id = servers.addServer({}, p, serverConfigUtils::SelfHostedUser); servers.setDefaultServer(id);
        ServersController serverController(&servers, &app); ConnectionUpdatesController updates(&servers, &connection);
        ConnectionUiController ui(&connection, &serverController); ui.setConnectionUpdatesController(&updates);
        QSignalSpy attempts(&connection, &ConnectionController::openConnectionRequested);
        ui.openConnection(); QTRY_COMPARE(feed.acknowledgements, 1); QVERIFY(updates.busy()); ui.closeConnection();
        QTRY_VERIFY(!updates.busy()); QCOMPARE(attempts.count(), 0); settings.clearSettings();
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
    void invitationAttachesWithoutAddingOrSelectingServer()
    {
        SecureQSettings settings("Amnezia-Updates-" + QUuid::createUuid().toString(), "test", nullptr, false);
        SecureServersRepository servers(&settings); SecureAppSettingsRepository app(&settings);
        auto original = profile(); const auto metadata = original.take("connectionUpdates").toObject();
        const auto target = servers.addServer({}, original, serverConfigUtils::SelfHostedUser);
        auto other = profile(); auto containers = other["containers"].toArray(); auto container = containers[0].toObject(); auto proto = container["wireguard"].toObject();
        auto differentClient = client(other, false); differentClient["server_pub_key"] = QString::fromLatin1(QByteArray(32, 'X').toBase64());
        proto["last_config"] = QString::fromUtf8(QJsonDocument(differentClient).toJson()); container["wireguard"] = proto; containers[0] = container; other["containers"] = containers;
        const auto selected = servers.addServer({}, other, serverConfigUtils::SelfHostedUser); servers.setDefaultServer(selected);
        ImportController importer(&servers, &app); QSignalSpy imported(&importer, &ImportController::importFinished), attached(&importer, &ImportController::updatesAttached), errors(&importer, &ImportController::importErrorOccurred);
        const QJsonObject invitation { { "type", "amnezia-update-invitation" }, { "version", 1 },
            { "existingServerPublicKey", client(original, false).value("server_pub_key") }, { "connectionUpdates", metadata } };
        const auto url = "vpn://" + QString::fromLatin1(qCompress(QJsonDocument(invitation).toJson(), 8).toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
        const auto extracted = importer.extractConfigFromData(url); QCOMPARE(extracted.errorCode, ErrorCode::NoError);
        importer.importConfig(extracted.config); QCOMPARE(attached.count(), 1); QCOMPARE(attached[0][0].toString(), target); QCOMPARE(imported.count(), 0);
        QCOMPARE(servers.serversCount(), 2); QCOMPARE(servers.defaultServerId(), selected);
        auto retained = *servers.serverJsonById(target); retained.remove("connectionUpdates");
        QCOMPARE(client(retained, false), client(original, false));
        QCOMPARE(retained.value("description"), original.value("description"));
        QCOMPARE(retained.value("dns1"), original.value("dns1"));
        QCOMPARE(retained.value("splitTunnelSites"), original.value("splitTunnelSites"));
        servers.addServer({}, *servers.serverJsonById(target), serverConfigUtils::SelfHostedUser);
        importer.importConfig(invitation); QCOMPARE(errors.count(), 1); QCOMPARE(attached.count(), 1); QCOMPARE(servers.serversCount(), 3);
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
