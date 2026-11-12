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
#include <QTemporaryDir>
#include <QProcess>
#include <QFile>
#include <atomic>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include "connection-updates/fixtures.h"
#include "core/utils/connectionUpdates.h"
#include "core/controllers/selfhosted/connectionUpdatesController.h"
#include "core/controllers/selfhosted/importController.h"
#include "core/controllers/selfhosted/exportController.h"
#include "core/controllers/selfhosted/usersController.h"
#include "core/controllers/connectionController.h"
#include "core/controllers/serversController.h"
#include "ui/controllers/connectionUiController.h"
#include "ui/controllers/selfhosted/exportUiController.h"
#include "vpnConnection.h"
#include "secureQSettings.h"
#include "core/configurators/wireguardConfigurator.h"

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
    QJsonObject bootstrap(bool awg = false) const
    {
        auto p = profile(awg); auto m = p["connectionUpdates"].toObject();
        m["url"] = QString("https://127.0.0.1:%1/v1/connections/%2").arg(serverPort()).arg(m["id"].toString());
        m["certificate"] = QString::fromLatin1(certificate.toDer().toBase64()); p["connectionUpdates"] = m; return p;
    }
    void setUpdate(const QJsonObject &p, const QJsonObject &extensions = {})
    {
        auto data = payload(p, p.value("defaultContainer").toString() == "amnezia-awg2"); const auto now = QDateTime::currentSecsSinceEpoch(); data["issuedAt"] = now; data["expiresAt"] = now + 600;
        if (advertiseAck) data["ackChallenge"] = QString::fromLatin1(publicKey(QByteArray(32, 'R'), EVP_PKEY_X25519).toBase64());
        if (!pathMtuProbe.isEmpty()) data["pathMtuProbe"] = pathMtuProbe;
        for (auto it = extensions.begin(); it != extensions.end(); ++it) data[it.key()] = it.value();
        body = sign(data);
    }
};
class TestConnectionUpdatesController : public QObject {
    Q_OBJECT
private slots:
    void pendingPeerExportSurvivesRepositoryRestartAndStaysLocal()
    {
        const QJsonObject pending{{"version",1},{"operation","synthetic-operation"},{"privateKey","synthetic-private-material"}};
        if (qEnvironmentVariableIsSet("AMNEZIA_TEST_PENDING_READER")) {
            SecureQSettings settings(qEnvironmentVariable("AMNEZIA_TEST_PENDING_READER"),"test",nullptr,false);
            SecureServersRepository servers(&settings); QJsonObject current;
            QVERIFY(servers.pendingPeerExport(qEnvironmentVariable("AMNEZIA_TEST_PENDING_SERVER"),DockerContainer::WireGuard,current));
            QCOMPARE(current,pending); return;
        }
        const auto organization="Amnezia-Pending-Export-"+QUuid::createUuid().toString();
        QString id;
        {
            SecureQSettings settings(organization,"test",nullptr,false);
            SecureServersRepository servers(&settings);
            auto administrator=profile(); administrator["userName"]="root";
            administrator["password"]="synthetic-admin-secret"; administrator["port"]=22;
            id=servers.addServer({},administrator,serverConfigUtils::SelfHostedAdmin);
            QJsonObject current;
            QVERIFY(servers.pendingPeerExport(id,DockerContainer::WireGuard,current)); QVERIFY(current.isEmpty());
            QVERIFY(servers.compareAndSetPendingPeerExport(id,DockerContainer::WireGuard,{},pending));
            // A separate process must see the data before either writer object
            // is destroyed; destructor flushing cannot make this test pass.
            QProcess reader; auto environment=QProcessEnvironment::systemEnvironment();
            environment.insert("AMNEZIA_TEST_PENDING_READER",organization);
            environment.insert("AMNEZIA_TEST_PENDING_SERVER",id); reader.setProcessEnvironment(environment);
            reader.start(QCoreApplication::applicationFilePath(),{"pendingPeerExportSurvivesRepositoryRestartAndStaysLocal"});
            QVERIFY(reader.waitForFinished(30000)); QCOMPARE(reader.exitStatus(),QProcess::NormalExit); QCOMPARE(reader.exitCode(),0);
            QVERIFY(!servers.compareAndSetPendingPeerExport(id,DockerContainer::WireGuard,{},{{"different",true}}));
            QVERIFY(!servers.compareAndSetPendingPeerExport(id,DockerContainer::Awg,{},pending));
            QVERIFY(!settings.backupAppConfig().contains("synthetic-private-material"));
            QVERIFY(!settings.backupAppConfig().contains("pendingPeerExports"));
            QVERIFY(!QJsonDocument(*servers.serverJsonById(id)).toJson().contains("synthetic-private-material"));
            ExportController exporter(&servers,nullptr);
            const auto exported=exporter.generateFullAccessConfig(id);
            const auto json=qUncompress(QByteArray::fromBase64(exported.config.mid(6).toLatin1(),QByteArray::Base64UrlEncoding));
            QVERIFY(!json.contains("synthetic-private-material")); QVERIFY(!json.contains("pendingPeerExports"));
        }
        {
            SecureQSettings settings(organization,"test",nullptr,false);
            SecureServersRepository servers(&settings);
            QJsonObject current;
            QVERIFY(servers.pendingPeerExport(id,DockerContainer::WireGuard,current)); QCOMPARE(current,pending);
            QVERIFY(servers.compareAndSetPendingPeerExport(id,DockerContainer::WireGuard,pending,{}));
            QVERIFY(servers.pendingPeerExport(id,DockerContainer::WireGuard,current)); QVERIFY(current.isEmpty());
            const QJsonObject emptyRecord{{"version",1},{"operations",QJsonObject{{id+":amnezia-wireguard",QJsonObject{}}}}};
            settings.setValue("Conf/pendingPeerExports",QJsonDocument(emptyRecord).toJson(QJsonDocument::Compact));
            QVERIFY(!servers.pendingPeerExport(id,DockerContainer::WireGuard,current));
            QVERIFY(!servers.compareAndSetPendingPeerExport(id,DockerContainer::WireGuard,{},pending));
            settings.setValue("Conf/pendingPeerExports",QByteArray("corrupt"));
            QVERIFY(!servers.pendingPeerExport(id,DockerContainer::WireGuard,current));
            QVERIFY(!servers.compareAndSetPendingPeerExport(id,DockerContainer::WireGuard,{},pending));
            settings.clearSettings();
        }
    }
    void durablePeerExportRejectsStorageFailure()
    {
        if (!qEnvironmentVariableIsSet("AMNEZIA_TEST_STORAGE_FAILURE_CHILD")) {
            QProcess child; auto environment=QProcessEnvironment::systemEnvironment();
            environment.insert("AMNEZIA_TEST_STORAGE_FAILURE_CHILD","1"); child.setProcessEnvironment(environment);
            child.start(QCoreApplication::applicationFilePath(),{"durablePeerExportRejectsStorageFailure"});
            QVERIFY(child.waitForFinished(30000)); QCOMPARE(child.exitStatus(),QProcess::NormalExit); QCOMPARE(child.exitCode(),0);
            return;
        }
        QTemporaryDir directory; QVERIFY(directory.isValid());
        const auto blocked=directory.path()+"/not-a-directory";
        QFile file(blocked); QVERIFY(file.open(QIODevice::WriteOnly)); file.close();
        QSettings::setPath(QSettings::IniFormat,QSettings::UserScope,blocked);
        SecureQSettings settings("Amnezia-Durable-Failure-"+QUuid::createUuid().toString(),"test",nullptr,false,QSettings::IniFormat);
        QVERIFY(!settings.compareAndSetDurable("Conf/pendingPeerExports",{},QByteArray("must-not-report-durable")));
    }
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
            const auto a = QString::fromLatin1(publicKey(deviceSeed, EVP_PKEY_X25519).toBase64());
            const auto b = QString::fromLatin1(QByteArray(32, 'B').toBase64());
            const auto c = QString::fromLatin1(QByteArray(32, 'C').toBase64());
            QCOMPARE(assignments, (QJsonObject { { a, container == DockerContainer::Awg2 ? "fd88::2" : "fd77::2" }, { b, "" }, { c, "" } }));
        }
    }
    void realAdminIPv6InvitationExport()
    {
        const auto host = qEnvironmentVariable("AMNEZIA_SSH_PROBE_HOST");
        if (host.isEmpty()) QSKIP("Run scripts/local-tests/path-probe-ssh.sh with this test executable");
        ServerCredentials credentials; credentials.hostName = host; credentials.port = qEnvironmentVariableIntValue("AMNEZIA_SSH_PROBE_PORT");
        credentials.userName = "root"; credentials.secretData = "synthetic-probe-fixture";
        QJsonObject info;
        QCOMPARE(ConnectionUpdatesController::command(credentials, "info", {}, info), ErrorCode::NoError);
        QVERIFY(info.value("features").toArray().contains("client-ipv6-v1"));
        for (const bool awg : { false, true }) {
            const auto container = awg ? DockerContainer::Awg2 : DockerContainer::WireGuard;
            QJsonObject live; QCOMPARE(ConnectionUpdatesController::fetchPublicSettings(credentials, container, host, live), ErrorCode::NoError);
            auto administrator = profile(awg); administrator["hostName"] = host;
            administrator["userName"] = credentials.userName; administrator["password"] = credentials.secretData; administrator["port"] = credentials.port;
            auto metadata = info; metadata["url"] = QString("https://%1:8443").arg(host);
            administrator["connectionUpdates"] = metadata;
            SecureQSettings settings("Amnezia-IPv6-Export-" + QUuid::createUuid().toString(), "test", nullptr, false);
            SecureServersRepository servers(&settings); SecureAppSettingsRepository app(&settings);
            const auto id = servers.addServer({}, administrator, serverConfigUtils::SelfHostedAdmin);
            ExportController exporter(&servers, &app);
            const auto key = client(administrator, awg).value("client_pub_key").toString();
            const auto exported = exporter.generateConnectionUpdates(id, static_cast<int>(container), key);
            QCOMPARE(exported.errorCode, ErrorCode::NoError); QVERIFY(exported.config.startsWith("vpn://"));
            const auto invitation = QJsonDocument::fromJson(qUncompress(QByteArray::fromBase64(exported.config.mid(6).toLatin1(), QByteArray::Base64UrlEncoding))).object();
            QCOMPARE(invitation.value("connectionUpdates").toObject().value("clientPublicKey").toString(), key);
            auto user = profile(awg);
            QJsonObject synchronized;
            QVERIFY(connectionUpdates::mergeServerSettings(user, awg ? "amnezia-awg2" : "amnezia-wireguard", live, false, synchronized));
            synchronized.remove("connectionUpdates"); QJsonObject attached;
            QVERIFY(connectionUpdates::attachInvitation(synchronized, invitation, attached));
            const auto userId = servers.addServer({}, attached, serverConfigUtils::SelfHostedUser);
            VpnConnection vpn(&servers, &app); ConnectionController connection(&servers, &app, &vpn);
            ConnectionUpdatesController updates(&servers, &connection); QSignalSpy finished(&updates, &ConnectionUpdatesController::finished);
            updates.refresh(userId); QTRY_COMPARE_WITH_TIMEOUT(finished.count(), 1, 10000); QVERIFY(finished[0][0].toBool());
            const auto received = client(*servers.serverJsonById(userId), awg);
            QCOMPARE(received.value("client_ip").toString(), awg ? "10.8.0.2, fd88::2/128" : "10.8.0.2, fd77::2/128");
            QCOMPARE(received.value("client_priv_key"), client(user, awg).value("client_priv_key"));
            QCOMPARE(received.value("allowed_ips"), client(user, awg).value("allowed_ips"));
            settings.clearSettings();
        }
    }
    void realAdminNewIPv6ProfileExport()
    {
        if (qEnvironmentVariableIsSet("AMNEZIA_TEST_RESUME_EXPORT_ORGANIZATION")) {
            SecureQSettings settings(qEnvironmentVariable("AMNEZIA_TEST_RESUME_EXPORT_ORGANIZATION"),"test",nullptr,false);
            SecureServersRepository servers(&settings); SecureAppSettingsRepository app(&settings);
            ExportController exporter(&servers,&app);
            const auto serverId=qEnvironmentVariable("AMNEZIA_TEST_RESUME_EXPORT_SERVER");
            const auto index=qEnvironmentVariableIntValue("AMNEZIA_TEST_RESUME_EXPORT_CONTAINER");
            if (qEnvironmentVariableIsSet("AMNEZIA_TEST_ACK_EXPORT")) {
                const auto expected=settings.value("Conf/testRecoveredExport").toString(); QVERIFY(!expected.isEmpty());
                ExportUiController ui(&exporter); bool pendingWhenDisplayed=false;
                connect(&ui,&ExportUiController::exportConfigChanged,&ui,[&] {
                    if (ui.getConfig().isEmpty()) return;
                    QJsonObject pending;
                    pendingWhenDisplayed=servers.pendingPeerExport(serverId,static_cast<DockerContainer>(index),pending)
                        && pending.value("result").toObject().value("config")==expected;
                });
                QSignalSpy errors(&ui,qOverload<ErrorCode>(&ExportUiController::exportErrorOccurred));
                ui.generateConnectionConfig(serverId,index,"synthetic IPv6 peer",true);
                QCOMPARE(errors.count(),0); QVERIFY(ui.getConfig()==expected); QVERIFY(!ui.getQrCodes().isEmpty());
                QVERIFY(pendingWhenDisplayed);
                QJsonObject acknowledged; QVERIFY(servers.pendingPeerExport(serverId,static_cast<DockerContainer>(index),acknowledged)); QVERIFY(acknowledged.isEmpty());
                return;
            }
            const auto result=exporter.generateConnectionConfig(qEnvironmentVariable("AMNEZIA_TEST_RESUME_EXPORT_SERVER"),
                qEnvironmentVariableIntValue("AMNEZIA_TEST_RESUME_EXPORT_CONTAINER"),"synthetic IPv6 peer",true);
            QCOMPARE(result.errorCode,ErrorCode::NoError); QVERIFY(!result.config.isEmpty());
            QVERIFY(settings.compareAndSetDurable("Conf/testRecoveredExport",{},result.config));
            return;
        }
        const auto host = qEnvironmentVariable("AMNEZIA_SSH_PROBE_HOST");
        if (host.isEmpty()) QSKIP("Run scripts/local-tests/path-probe-ssh.sh with this test executable");
        ServerCredentials credentials; credentials.hostName = host; credentials.port = qEnvironmentVariableIntValue("AMNEZIA_SSH_PROBE_PORT");
        credentials.userName = "root"; credentials.secretData = "synthetic-probe-fixture";
        QJsonObject info; QCOMPARE(ConnectionUpdatesController::command(credentials, "info", {}, info), ErrorCode::NoError);
        for (const bool awg : { false, true }) {
            const auto container = awg ? DockerContainer::Awg2 : DockerContainer::WireGuard;
            QJsonObject live; QCOMPARE(ConnectionUpdatesController::fetchPublicSettings(credentials, container, host, live), ErrorCode::NoError);
            auto administrator = profile(awg); administrator["hostName"] = host;
            administrator["userName"] = credentials.userName; administrator["password"] = credentials.secretData; administrator["port"] = credentials.port;
            QJsonObject synchronized;
            QVERIFY(connectionUpdates::mergeServerSettings(administrator, awg ? "amnezia-awg2" : "amnezia-wireguard", live, true, synchronized));
            auto metadata = info; metadata["url"] = QString("https://%1:8443").arg(host); synchronized["connectionUpdates"] = metadata;
            const auto organization="Amnezia-IPv6-New-Export-"+QUuid::createUuid().toString();
            SecureQSettings settings(organization,"test",nullptr,false);
            SecureServersRepository servers(&settings); SecureAppSettingsRepository app(&settings);
            const auto id = servers.addServer({}, synchronized, serverConfigUtils::SelfHostedAdmin);
            ExportController exporter(&servers, &app);
            // A pending server mutation must block another app writer without
            // falling back to a direct upload.
            if (qEnvironmentVariable("AMNEZIA_PEER_TRANSACTIONS") == "enabled") {
                SshSession manager; ErrorCode read = ErrorCode::NoError;
                const QString configPath = awg ? "/opt/amnezia/awg/awg0.conf" : "/opt/amnezia/wireguard/wg0.conf";
                const auto before = QString::fromUtf8(manager.getTextFileFromContainer(container, credentials, configPath, read));
                QCOMPARE(read, ErrorCode::NoError);
                const auto pending = before + "\n# pending server mutation\n";
                QJsonObject staged;
                QCOMPARE(manager.protocolConfigTransaction(container, credentials, {
                    {"action", "stage-live"}, {"expected", QString::fromLatin1(before.toUtf8().toBase64())},
                    {"candidate", QString::fromLatin1(pending.toUtf8().toBase64())} }, staged), ErrorCode::NoError);
                bool handled = false;
                QVERIFY(manager.replaceLiveProtocolConfig(container, credentials, before,
                    before + "\n# conflicting app writer\n", handled) != ErrorCode::NoError);
                QVERIFY(handled);
                QVERIFY(QString::fromUtf8(manager.getTextFileFromContainer(container, credentials, configPath, read)) == pending);
                const auto name = ContainerUtils::containerToString(container);
                const auto restoreCommand = QString("sudo docker exec %1 mv /opt/amnezia/config-helper.fixture-hidden /opt/amnezia/config-helper").arg(name);
                auto restoreHelper = qScopeGuard([&] { manager.runScript(credentials, restoreCommand); });
                QString hidden;
                QCOMPARE(manager.runScript(credentials, QString("sudo docker exec %1 mv /opt/amnezia/config-helper /opt/amnezia/config-helper.fixture-hidden && printf missing").arg(name),
                    [&](const QString &data, libssh::Client &) { hidden += data; return ErrorCode::NoError; }), ErrorCode::NoError);
                QCOMPARE(hidden, QString("missing"));
                handled = false;
                QVERIFY(manager.replaceLiveProtocolConfig(container, credentials, before,
                    before + "\n# blocked without helper\n", handled) != ErrorCode::NoError);
                QVERIFY(handled);
                QVERIFY(QString::fromUtf8(manager.getTextFileFromContainer(container, credentials, configPath, read)) == pending);
                QCOMPARE(manager.runScript(credentials, restoreCommand), ErrorCode::NoError);
                restoreHelper.dismiss();
                QJsonObject restored;
                QCOMPARE(manager.protocolConfigTransaction(container, credentials, {
                    {"action", "rollback-live"}, {"operation", staged.value("operation")} }, restored), ErrorCode::NoError);
                QVERIFY(QString::fromUtf8(manager.getTextFileFromContainer(container, credentials, configPath, read)) == before);
                // No transaction is pending now. Ownership alone must still
                // prevent downgrading to an uncoordinated legacy writer.
                auto restoreOwnedHelper = qScopeGuard([&] { manager.runScript(credentials, restoreCommand); });
                QCOMPARE(manager.runScript(credentials, QString("sudo docker exec %1 mv /opt/amnezia/config-helper /opt/amnezia/config-helper.fixture-hidden").arg(name)), ErrorCode::NoError);
                handled = false;
                QVERIFY(manager.replaceLiveProtocolConfig(container, credentials, before,
                    before + "\n# blocked managed helper disappearance\n", handled) != ErrorCode::NoError);
                QVERIFY(handled);
                QVERIFY(QString::fromUtf8(manager.getTextFileFromContainer(container, credentials, configPath, read)) == before);
                QCOMPARE(manager.runScript(credentials, restoreCommand), ErrorCode::NoError);
                restoreOwnedHelper.dismiss();
                const auto config=servers.selfHostedAdminConfig(id)->containerConfig(container);
                const DnsSettings dns{"192.0.2.53","192.0.2.54"};
                QJsonObject checkpoint;
                WireguardConfigurator interrupted(&manager,awg);
                interrupted.setPendingPeerExport({},[&](const QJsonObject &state) {
                    if (!servers.compareAndSetPendingPeerExport(id,container,{},state)) return false;
                    checkpoint=state;
                    // Model interruption after durable preparation, before any write.
                    return false;
                });
                ErrorCode interruptedError=ErrorCode::NoError;
                interrupted.createConfig(credentials,container,config,dns,interruptedError);
                QVERIFY(interruptedError!=ErrorCode::NoError); QVERIFY(!checkpoint.isEmpty());
                QVERIFY(QString::fromUtf8(manager.getTextFileFromContainer(container, credentials, configPath, read)) == before);
                SecureServersRepository reopened(&settings); QJsonObject persisted;
                QVERIFY(reopened.pendingPeerExport(id,container,persisted));
                QVERIFY(persisted==checkpoint);
                const auto serialized=QJsonDocument::fromJson(QJsonDocument(persisted).toJson()).object();
                // Stop after server staging as well: the first successful stage
                // response is discarded by the disposable transport fixture.
                QJsonObject lostStage;
                QVERIFY(manager.protocolConfigTransaction(container,credentials,{{"action","stage-live"},
                    {"expected",QString::fromLatin1(serialized.value("expected").toString().toUtf8().toBase64())},
                    {"candidate",QString::fromLatin1(serialized.value("candidate").toString().toUtf8().toBase64())}},lostStage)!=ErrorCode::NoError);
                QJsonObject stagedStatus;
                QCOMPARE(manager.protocolConfigTransaction(container,credentials,{{"action","status"}},stagedStatus),ErrorCode::NoError);
                QVERIFY(!stagedStatus.value("nativeWriteIntent").toBool()); QVERIFY(!stagedStatus.value("nativeApplied").toBool());
                auto confirmOwnership=[&](const QJsonObject &state) {
                    return reopened.compareAndSetPendingPeerExport(id,container,persisted,state);
                };
                WireguardConfigurator resumed(&manager,awg);
                resumed.setPendingPeerExport(serialized,confirmOwnership);
                ErrorCode resumedError=ErrorCode::NoError;
                const auto recovered=resumed.createConfig(credentials,container,config,dns,resumedError);
                QCOMPARE(resumedError,ErrorCode::NoError);
                QVERIFY(recovered.clientId()==persisted.value("clientPubKey").toString());
                const auto afterCreate=QString::fromUtf8(manager.getTextFileFromContainer(container,credentials,configPath,read));
                WireguardConfigurator committedRetry(&manager,awg);
                committedRetry.setPendingPeerExport(serialized,confirmOwnership);
                const auto repeated=committedRetry.createConfig(credentials,container,config,dns,resumedError);
                QCOMPARE(resumedError,ErrorCode::NoError); QVERIFY(repeated.clientId()==recovered.clientId());
                QVERIFY(repeated.getClientConfigJson()==recovered.getClientConfigJson());
                QVERIFY(QString::fromUtf8(manager.getTextFileFromContainer(container,credentials,configPath,read))==afterCreate);
                auto corrupt=serialized; corrupt["clientPubKey"]=QString::fromLatin1(QByteArray(32,'X').toBase64());
                WireguardConfigurator invalid(&manager,awg); invalid.setPendingPeerExport(corrupt,confirmOwnership);
                invalid.createConfig(credentials,container,config,dns,resumedError);
                QVERIFY(resumedError!=ErrorCode::NoError);
                QJsonObject stillOwned; QVERIFY(reopened.pendingPeerExport(id,container,stillOwned)); QVERIFY(stillOwned==persisted);
                QVERIFY(QString::fromUtf8(manager.getTextFileFromContainer(container,credentials,configPath,read))==afterCreate);
                QString removed; QVERIFY(connectionUpdates::removePeerFromServerConfig(afterCreate,recovered.clientId(),removed));
                QVERIFY(removed==before);
                handled=false;
                QCOMPARE(manager.replaceLiveProtocolConfig(container,credentials,afterCreate,removed,handled),ErrorCode::NoError); QVERIFY(handled);
                QVERIFY(reopened.compareAndSetPendingPeerExport(id,container,persisted,{}));
                // Keep the existing export loss checks independent of this resume test.
                QCOMPARE(manager.runScript(credentials,QString("sudo docker exec %1 rm -f /opt/amnezia/protocol-loss-stage /opt/amnezia/protocol-loss-commit").arg(name)),ErrorCode::NoError);
            }
            ExportController::ExportResult exported;
            QString recoveredExportKey;
            if (qEnvironmentVariable("AMNEZIA_PEER_TRANSACTIONS")=="enabled") {
                SshSession failDelivery; bool hidden=false;
                auto restoreDelivery=qScopeGuard([&] { if (hidden) failDelivery.runScript(credentials,
                    "sudo docker rename amnezia-connection-updates.fixture-hidden amnezia-connection-updates"); });
                const auto hook=connect(&exporter,&ExportController::appendClientRequested,&exporter,[&] {
                    hidden=failDelivery.runScript(credentials,
                        "sudo docker rename amnezia-connection-updates amnezia-connection-updates.fixture-hidden")==ErrorCode::NoError;
                });
                const auto interrupted=exporter.generateConnectionConfig(id,static_cast<int>(container),"synthetic IPv6 peer",true);
                disconnect(hook); QVERIFY(hidden); QVERIFY(interrupted.errorCode!=ErrorCode::NoError); QVERIFY(interrupted.config.isEmpty());
                QJsonObject pending; QVERIFY(servers.pendingPeerExport(id,container,pending)); QVERIFY(!pending.isEmpty());
                recoveredExportKey=pending.value("prepared").toObject().value("clientPubKey").toString(); QVERIFY(!recoveredExportKey.isEmpty());
                QCOMPARE(failDelivery.runScript(credentials,"sudo docker rename amnezia-connection-updates.fixture-hidden amnezia-connection-updates"),ErrorCode::NoError);
                hidden=false; restoreDelivery.dismiss();
                // A local client preference change must not invalidate server identity.
                auto changedAdministrator=*servers.selfHostedAdminConfig(id);
                auto changedContainer=changedAdministrator.containerConfig(container);
                auto changedClient=changedContainer.protocolConfig.getClientConfigJson(); changedClient["mtu"]="1300";
                changedContainer.protocolConfig.setClientConfigJson(changedClient);
                changedAdministrator.containers[container]=changedContainer;
                servers.editServer(id,changedAdministrator.toJson(),serverConfigUtils::SelfHostedAdmin);
                QVERIFY(servers.compareAndSetPendingPeerExport(id,container,pending,pending));
                QProcess restartedProcess; auto environment=QProcessEnvironment::systemEnvironment();
                environment.insert("AMNEZIA_TEST_RESUME_EXPORT_ORGANIZATION",organization);
                environment.insert("AMNEZIA_TEST_RESUME_EXPORT_SERVER",id);
                environment.insert("AMNEZIA_TEST_RESUME_EXPORT_CONTAINER",QString::number(static_cast<int>(container)));
                restartedProcess.setProcessEnvironment(environment);
                restartedProcess.start(QCoreApplication::applicationFilePath(),{"realAdminNewIPv6ProfileExport"});
                QVERIFY(restartedProcess.waitForFinished(30000)); QCOMPARE(restartedProcess.exitStatus(),QProcess::NormalExit);
                QCOMPARE(restartedProcess.exitCode(),0);
                QSettings disk(organization,"test"); disk.sync();
                exported.config=disk.value("Conf/testRecoveredExport").toString();
                SecureQSettings recoveredSettings(organization,"test",nullptr,false);
                SecureServersRepository restarted(&recoveredSettings);
                QJsonObject finished; QVERIFY(restarted.pendingPeerExport(id,container,finished)); QVERIFY(!finished.isEmpty());
                QVERIFY(finished.value("result").toObject().value("config")==exported.config);
                ExportController acknowledgment(&restarted,&app);
                QVERIFY(!acknowledgment.acknowledgeConnectionExport(id,static_cast<int>(container),exported.config+"wrong"));
                QJsonObject unchanged; QVERIFY(restarted.pendingPeerExport(id,container,unchanged)); QVERIFY(unchanged==finished);
                auto corruptReady=finished; auto corruptResult=corruptReady.value("result").toObject();
                corruptResult["digest"]=QString(64,'0'); corruptReady["result"]=corruptResult;
                QVERIFY(restarted.compareAndSetPendingPeerExport(id,container,finished,corruptReady));
                const auto refused=acknowledgment.generateConnectionConfig(id,static_cast<int>(container),"synthetic IPv6 peer",true);
                QVERIFY(refused.errorCode!=ErrorCode::NoError); QVERIFY(refused.config.isEmpty());
                QVERIFY(restarted.pendingPeerExport(id,container,unchanged)); QVERIFY(unchanged==corruptReady);
                QVERIFY(restarted.compareAndSetPendingPeerExport(id,container,corruptReady,finished));
                // The next process receives the completed result while delivery is
                // unavailable, then the actual UI acknowledges only after display.
                bool cachedDeliveryHidden=false;
                auto restoreCachedDelivery=qScopeGuard([&] { if (cachedDeliveryHidden) failDelivery.runScript(credentials,
                    "sudo docker rename amnezia-connection-updates.fixture-hidden amnezia-connection-updates"); });
                QCOMPARE(failDelivery.runScript(credentials,"sudo docker rename amnezia-connection-updates amnezia-connection-updates.fixture-hidden"),ErrorCode::NoError);
                cachedDeliveryHidden=true;
                environment.insert("AMNEZIA_TEST_ACK_EXPORT","1"); restartedProcess.setProcessEnvironment(environment);
                restartedProcess.start(QCoreApplication::applicationFilePath(),{"realAdminNewIPv6ProfileExport"});
                QVERIFY(restartedProcess.waitForFinished(30000)); QCOMPARE(restartedProcess.exitStatus(),QProcess::NormalExit); QCOMPARE(restartedProcess.exitCode(),0);
                QCOMPARE(failDelivery.runScript(credentials,"sudo docker rename amnezia-connection-updates.fixture-hidden amnezia-connection-updates"),ErrorCode::NoError);
                cachedDeliveryHidden=false; restoreCachedDelivery.dismiss();
                disk.sync(); SecureQSettings acknowledgedSettings(organization,"test",nullptr,false);
                SecureServersRepository acknowledgedServers(&acknowledgedSettings);
                QVERIFY(acknowledgedServers.pendingPeerExport(id,container,finished)); QVERIFY(finished.isEmpty());
                SshSession fault; QString receipt;
                QCOMPARE(fault.runScript(credentials,QString("cat /tmp/issue-reply-loss-%1").arg(ContainerUtils::containerToString(container)),
                    [&](const QString &data,libssh::Client &){receipt+=data;return ErrorCode::NoError;}),ErrorCode::NoError);
                const auto replay=QJsonDocument::fromJson(receipt.toUtf8()).object();
                QCOMPARE(replay.value("calls").toInt(),2); QVERIFY(replay.value("replayed").toBool());
                QVERIFY(!replay.value("droppedId").toString().isEmpty()); QCOMPARE(replay.value("droppedId"),replay.value("replayedId"));
            } else exported=exporter.generateConnectionConfig(id,static_cast<int>(container),"synthetic IPv6 peer",true);
            QCOMPARE(exported.errorCode, ErrorCode::NoError); QVERIFY(exported.config.startsWith("vpn://"));
            if (recoveredExportKey.isEmpty()) QVERIFY(exporter.acknowledgeConnectionExport(id,static_cast<int>(container),exported.config));
            const auto user = QJsonDocument::fromJson(qUncompress(QByteArray::fromBase64(exported.config.mid(6).toLatin1(), QByteArray::Base64UrlEncoding))).object();
            if (!recoveredExportKey.isEmpty()) {
                QVERIFY(user.value("connectionUpdates").toObject().value("clientPublicKey").toString()==recoveredExportKey);
                QCOMPARE(client(user,awg).value("mtu").toString(),QString("1300"));
            }
            if (qEnvironmentVariable("AMNEZIA_PEER_TRANSACTIONS") == "enabled") {
                SshSession verified; ErrorCode observed = ErrorCode::NoError;
                QCOMPARE(verified.getTextFileFromContainer(container, credentials, "/opt/amnezia/protocol-loss-stage", observed), QByteArray("1"));
                QCOMPARE(observed, ErrorCode::NoError);
                QCOMPARE(verified.getTextFileFromContainer(container, credentials, "/opt/amnezia/protocol-loss-commit", observed), QByteArray("1"));
                QCOMPARE(observed, ErrorCode::NoError);
            }
            QVERIFY(connectionUpdates::validateProfile(user)); const auto generated = client(user, awg);
            QVERIFY(generated.value("client_pub_key") != client(administrator, awg).value("client_pub_key"));
            QJsonObject assignments;
            QCOMPARE(ConnectionUpdatesController::fetchPeerIPv6Assignments(credentials, container, assignments), ErrorCode::NoError);
            const auto assigned = assignments.value(generated.value("client_pub_key").toString()).toString();
            QCOMPARE(user.value("connectionUpdates").toObject().value("managedClientIpv6").toString(), assigned);
            QVERIFY(!assigned.isEmpty()); QVERIFY(generated.value("client_ip").toString().contains(assigned + "/128"));
            const auto userId = servers.addServer({}, user, serverConfigUtils::SelfHostedUser);
            VpnConnection vpn(&servers, &app); ConnectionController connection(&servers, &app, &vpn);
            ConnectionUpdatesController updates(&servers, &connection); QSignalSpy finished(&updates, &ConnectionUpdatesController::finished);
            updates.refresh(userId); QTRY_COMPARE_WITH_TIMEOUT(finished.count(), 1, 10000); QVERIFY(finished[0][0].toBool());
            const auto received = client(*servers.serverJsonById(userId), awg);
            QCOMPARE(received.value("client_ip"), generated.value("client_ip"));
            QCOMPARE(received.value("client_priv_key"), generated.value("client_priv_key"));
            QCOMPARE(received.value("allowed_ips"), generated.value("allowed_ips"));
            QJsonObject published;
            QCOMPARE(ConnectionUpdatesController::command(credentials, "publish", {
                { "container", awg ? "amnezia-awg2" : "amnezia-wireguard" }, { "settings", live },
                { "clientIpv6", QJsonObject { { generated.value("client_pub_key").toString(), "" } } }
            }, published), ErrorCode::NoError);
            updates.refresh(userId); QTRY_COMPARE_WITH_TIMEOUT(finished.count(), 2, 10000); QVERIFY(finished[1][0].toBool());
            const auto withdrawn = client(*servers.serverJsonById(userId), awg);
            QCOMPARE(withdrawn.value("client_ip").toString(), generated.value("client_ip").toString().section(',', 0, 0).trimmed());
            QCOMPARE(withdrawn.value("client_priv_key"), generated.value("client_priv_key"));
            // A key mentioned in an earlier Interface comment must not cause
            // revocation to remove that section or another peer.
            SshSession ssh; ErrorCode readError = ErrorCode::NoError;
            const QString path = awg ? "/opt/amnezia/awg/awg0.conf" : "/opt/amnezia/wireguard/wg0.conf";
            const auto original = QString::fromUtf8(ssh.getTextFileFromContainer(container, credentials, path, readError));
            QCOMPARE(readError, ErrorCode::NoError);
            auto misleading = original;
            misleading.replace("[Interface]\n", "[Interface]\n# preserved comment mentioning " + generated.value("client_pub_key").toString() + "\n");
            QVERIFY(misleading != original);
            QCOMPARE(ssh.uploadTextFileToContainer(container, credentials, misleading, path), ErrorCode::NoError);
            const auto tablePath = "/opt/amnezia/" + ContainerUtils::containerTypeToString(container) + "/clientsTable";
            const QJsonArray table { QJsonObject { { "clientId", generated.value("client_pub_key") }, { "userData", QJsonObject { { "clientName", "synthetic peer" } } } } };
            QCOMPARE(ssh.uploadTextFileToContainer(container, credentials, QString::fromUtf8(QJsonDocument(table).toJson()), tablePath), ErrorCode::NoError);
            UsersController users(&servers); QSignalSpy listed(&users, &UsersController::clientsUpdated);
            QCOMPARE(users.updateClients(id, container), ErrorCode::NoError);
            QVERIFY(!listed.isEmpty());
            const auto currentTable = qvariant_cast<QJsonArray>(listed.last().at(0));
            int targetRow = -1;
            for (int row = 0; row < currentTable.size(); ++row)
                if (currentTable[row].toObject().value("clientId") == generated.value("client_pub_key")) targetRow = row;
            QVERIFY(targetRow >= 0);
            QCOMPARE(users.revokeClient(id, targetRow, container), ErrorCode::NoError);
            QString expected;
            QVERIFY(connectionUpdates::removePeerFromServerConfig(misleading, generated.value("client_pub_key").toString(), expected));
            const auto actual = QString::fromUtf8(ssh.getTextFileFromContainer(container, credentials, path, readError));
            QCOMPARE(readError, ErrorCode::NoError);
            QVERIFY2(actual == expected, "server configuration differs from exact peer removal");
            QVERIFY(actual.section("[Peer]", 0, 0) == misleading.section("[Peer]", 0, 0));
            QJsonObject unchangedSettings;
            QCOMPARE(ConnectionUpdatesController::fetchPublicSettings(credentials, container, host, unchangedSettings), ErrorCode::NoError);
            QCOMPARE(unchangedSettings, live);
            QJsonObject remaining;
            QCOMPARE(ConnectionUpdatesController::fetchPeerIPv6Assignments(credentials, container, remaining), ErrorCode::NoError);
            assignments.remove(generated.value("client_pub_key").toString());
            QCOMPARE(remaining, assignments);
            settings.clearSettings();
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
    void signedIPv6SurvivesRepositoryReload_data()
    {
        QTest::addColumn<bool>("awg"); QTest::newRow("wireguard") << false; QTest::newRow("awg") << true;
    }
    void signedIPv6SurvivesRepositoryReload()
    {
        QFETCH(bool, awg);
        FeedServer feed; QVERIFY(feed.listen(QHostAddress::LocalHost)); const auto p = feed.bootstrap(awg);
        feed.setUpdate(p, { { "clientIpv6", "fd77::2" } });
        SecureQSettings settings("Amnezia-IPv6-Storage-" + QUuid::createUuid().toString(), "test", nullptr, false);
        SecureServersRepository servers(&settings); SecureAppSettingsRepository app(&settings);
        VpnConnection vpn(&servers, &app); ConnectionController connection(&servers, &app, &vpn);
        const auto id = servers.addServer({}, p, serverConfigUtils::SelfHostedUser);
        ConnectionUpdatesController updates(&servers, &connection); QSignalSpy finished(&updates, &ConnectionUpdatesController::finished);
        updates.refresh(id); QTRY_COMPARE(finished.count(), 1); QVERIFY(finished[0][0].toBool());
        auto typed = *servers.selfHostedUserConfig(id); typed.description = "IPv6 retained after edit";
        servers.editServer(id, typed.toJson(), serverConfigUtils::SelfHostedUser); servers.invalidateCache();
        const auto stored = *servers.serverJsonById(id);
        QCOMPARE(client(stored, awg).value("client_ip").toString(), "10.8.0.2, fd77::2/128");
        QVERIFY(client(stored, awg).value("config").toString().contains("Address = 10.8.0.2/32, fd77::2/128\n"));
        QCOMPARE(stored.value("connectionUpdates").toObject().value("managedClientIpv6").toString(), "fd77::2");
        for (const auto *key : { "client_priv_key", "client_pub_key", "psk_key", "mtu", "allowed_ips" })
            QCOMPARE(client(stored, awg).value(key), client(p, awg).value(key));
        // A correctly signed but invalid assignment must leave persistent storage intact.
        feed.setUpdate(p, { { "revision", "2" }, { "clientIpv6", "fe80::2" } });
        updates.refresh(id); QTRY_COMPARE(finished.count(), 2); QVERIFY(!finished[1][0].toBool());
        servers.invalidateCache(); QCOMPARE(*servers.serverJsonById(id), stored);
        feed.setUpdate(p, { { "revision", "3" }, { "clientIpv6", "" } });
        updates.refresh(id); QTRY_COMPARE(finished.count(), 3); QVERIFY(finished[2][0].toBool());
        servers.invalidateCache(); const auto withdrawn = *servers.serverJsonById(id);
        QCOMPARE(client(withdrawn, awg).value("client_ip"), client(p, awg).value("client_ip"));
        QVERIFY(!withdrawn.value("connectionUpdates").toObject().contains("managedClientIpv6"));
        QCOMPARE(withdrawn.value("description").toString(), "IPv6 retained after edit");
        QCOMPARE(client(withdrawn, awg).value("client_priv_key"), client(p, awg).value("client_priv_key"));
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
