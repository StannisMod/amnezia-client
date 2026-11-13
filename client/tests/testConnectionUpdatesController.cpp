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
#include "core/controllers/selfhosted/installController.h"
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
#include "core/utils/selfhosted/proxyIpv6Upgrade.h"
#include "core/utils/selfhosted/scriptsRegistry.h"

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
    void realProxyServerIpv6Activation()
    {
        if(qEnvironmentVariable("AMNEZIA_PROXY_IPV6_TEST")!="isolated-docker") QSKIP("requires the isolated proxy IPv6 fixture");
        const auto name=qEnvironmentVariable("AMNEZIA_PROXY_IPV6_CONTAINER");
        QVERIFY(name=="amnezia-xray"||name=="amnezia-ssxray");
        const auto backend=name=="amnezia-xray"?DockerContainer::Xray:DockerContainer::SSXray;
        ServerCredentials credentials{"127.0.0.1","root","synthetic-probe-fixture",2222};
        SshSession guard;
        QCOMPARE(guard.runScript(credentials,"test -f /run/amnezia-proxy-ipv6-fixture && sudo docker info -f '{{range .Labels}}{{println .}}{{end}}' | grep -Fxq amnezia.test-environment=disposable"),ErrorCode::NoError);
        const auto expected=qEnvironmentVariable("AMNEZIA_PROXY_IPV6_EXPECT");
        if(expected=="create-ipv4"||expected=="create-ipv6") {
            // Use the actual packaged run script, including its IPv6 prefix.
            auto script=amnezia::scriptData(ProtocolScriptType::run_container,DockerContainer::Xray);
            QVERIFY(!script.isEmpty());
            script.replace("$CONTAINER_NAME",name).replace("$XRAY_SERVER_PORT","38443");
            QCOMPARE(guard.runScript(credentials,SshSession::wholeScriptCommand(script)),ErrorCode::NoError);
            return;
        }
        QJsonObject outcome;
        QCOMPARE(proxyIpv6Upgrade::prepare(credentials,backend,outcome),ErrorCode::NoError);
        QCOMPARE(outcome.value("result").toString(),expected);
        if(expected=="verified") {
            QCOMPARE(QHostAddress(outcome.value("remoteAddress").toString()).protocol(),QAbstractSocket::IPv6Protocol);
            QCOMPARE(QHostAddress(outcome.value("localAddress").toString()).protocol(),QAbstractSocket::IPv6Protocol);
            QVERIFY(QRegularExpression("^[a-f0-9]{64}$").match(outcome.value("containerId").toString()).hasMatch());
        }
        qInfo().noquote()<<"AMNEZIA_PROXY_IPV6_RESULT"<<QJsonDocument(outcome).toJson(QJsonDocument::Compact);
    }

    void proxyIpv6Preflight_data()
    {
        QTest::addColumn<QString>("scenario");
        for(const auto *name:{"late-success","failure","edited","canceled","third-party"}) QTest::newRow(name)<<QString(name);
    }
    void proxyIpv6Preflight()
    {
        QFETCH(QString,scenario);
        SecureQSettings settings("Amnezia-Proxy-IPv6-"+QUuid::createUuid().toString(),"test",nullptr,false);
        SecureServersRepository servers(&settings);SecureAppSettingsRepository app(&settings);VpnConnection vpn(&servers,&app);ConnectionController connection(&servers,&app,&vpn);
        disconnect(&connection,&ConnectionController::openConnectionRequested,&vpn,&VpnConnection::connectToVpn);
        XrayProtocolConfig protocol;protocol.serverConfig.applyDefaults();protocol.serverConfig.isThirdPartyConfig=scenario=="third-party";
        protocol.setClientConfig(XrayClientConfig{QStringLiteral("{}"),QStringLiteral("10808"),QStringLiteral("11111111-1111-4111-8111-111111111111")});
        const ContainerConfig container{DockerContainer::Xray,ProtocolConfig{protocol}};
        const QJsonObject administrator{{"format_version",1},{"description","Proxy IPv6 fixture"},{"hostName","proxy.example.test"},
            {"userName","root"},{"password","synthetic-admin-secret"},{"port",22},{"defaultContainer","amnezia-xray"},
            {"containers",QJsonArray{container.toJson()}}};
        const auto id=servers.addServer({},administrator,serverConfigUtils::SelfHostedAdmin);servers.setDefaultServer(id);
        const auto original=*servers.serverJsonById(id);
        QSemaphore gate;std::atomic<int> calls{0};std::atomic<bool> correctArguments{false};
        ConnectionUpdatesController updates(&servers,&connection,nullptr,{}, {},[&](const ServerCredentials &credentials,DockerContainer backend,QJsonObject &outcome) {
            correctArguments.store(credentials.userName=="root"&&backend==DockerContainer::Xray);calls.fetch_add(1);gate.acquire();
            outcome={{"result","verified"}};return scenario=="failure"?ErrorCode::InternalError:ErrorCode::NoError;
        });
        const auto unblock=qScopeGuard([&]{gate.release();});
        int continuations=0;
        if(scenario=="third-party") {
            QVERIFY(!updates.needsRefreshBeforeConnect(id));updates.refreshBeforeConnect(id,[&]{++continuations;});
            QCOMPARE(continuations,1);QCOMPARE(calls.load(),0);settings.clearSettings();return;
        }
        QVERIFY(updates.needsRefreshBeforeConnect(id));
        ServersController serverController(&servers,&app);ConnectionUiController ui(&connection,&serverController);ui.setConnectionUpdatesController(&updates);
        QSignalSpy attempts(&connection,&ConnectionController::openConnectionRequested);
        QSignalSpy stops(&connection,&ConnectionController::closeConnectionRequested);
        if(scenario=="canceled") {ui.openConnection();ui.closeConnection();}
        else updates.refreshBeforeConnect(id,[&]{++continuations;});
        QTRY_COMPARE(calls.load(),1);QVERIFY(correctArguments.load());
        auto expected=original;
        if(scenario=="edited") {expected["description"]="changed while IPv6 was prepared";servers.editServer(id,expected,serverConfigUtils::SelfHostedAdmin);}
        if(scenario=="late-success") {QTRY_COMPARE_WITH_TIMEOUT(continuations,1,2500);QVERIFY(updates.busy());}
        gate.release();QTRY_VERIFY(!updates.busy());
        if(scenario=="canceled") {QCOMPARE(attempts.count(),0);QCOMPARE(stops.count(),0);} else QCOMPARE(continuations,1);
        QCOMPARE(*servers.serverJsonById(id),expected);
        QCOMPARE(updates.needsRefreshBeforeConnect(id),scenario=="failure"||scenario=="edited");
        settings.clearSettings();
    }

    void proxyIpv6ProbeRejectsShortcuts()
    {
        const auto body=QStringLiteral(R"({"Status":0,"Question":[{"name":".","type":2}],"Answer":[{"type":2,"data":"a.root-servers.net."}]})");
        const auto remote=QStringLiteral("2606:4700:4700::1111");
        const QJsonObject proof{{"http",200},{"verify",0},{"remote",remote},{"local","fd42::2"}};
        auto response=[&](const QJsonObject &metadata,const QString &answer) {
            return answer+"\namnezia_ipv6_probe="+QString::fromUtf8(QJsonDocument(metadata).toJson(QJsonDocument::Compact))+"\n";
        };
        QJsonObject evidence;
        QVERIFY(proxyIpv6Upgrade::parseProbeResponse(response(proof,body),remote,evidence));
        QCOMPARE(evidence.value("localAddress").toString(),QStringLiteral("fd42::2"));
        for(const auto &change:QList<QPair<QString,QJsonValue>>{{"http",302},{"verify",60},{"local","192.0.2.2"},{"local","::ffff:192.0.2.2"},{"remote","2001:db8::1"}}) {
            auto bad=proof;bad[change.first]=change.second;
            QVERIFY(!proxyIpv6Upgrade::parseProbeResponse(response(bad,body),remote,evidence));QVERIFY(evidence.isEmpty());
        }
        QVERIFY(!proxyIpv6Upgrade::parseProbeResponse(response(proof,QStringLiteral("{\"Status\":0}")),remote,evidence));
        QVERIFY(!proxyIpv6Upgrade::parseProbeResponse(response(proof,body)+response(proof,body),remote,evidence));
    }

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
    void pendingPeerRevocationIsDurableAndSeparateFromExport()
    {
        const QJsonObject pending{{"version",1},{"clientPublicKey","synthetic-target"},{"original","synthetic-private-revocation-context"}};
        if (qEnvironmentVariableIsSet("AMNEZIA_TEST_REVOCATION_READER")) {
            SecureQSettings settings(qEnvironmentVariable("AMNEZIA_TEST_REVOCATION_READER"),"test",nullptr,false);
            SecureServersRepository servers(&settings); QJsonObject operation;
            QVERIFY(servers.pendingPeerRevocation(qEnvironmentVariable("AMNEZIA_TEST_PENDING_SERVER"),DockerContainer::WireGuard,operation));
            QCOMPARE(operation,pending); return;
        }
        const auto organization="Amnezia-Pending-Revoke-"+QUuid::createUuid().toString();
        SecureQSettings settings(organization,"test",nullptr,false);
        SecureServersRepository servers(&settings);
        auto administrator=profile(); administrator["userName"]="root";
        administrator["password"]="synthetic-admin-secret"; administrator["port"]=22;
        const auto id=servers.addServer({},administrator,serverConfigUtils::SelfHostedAdmin);
        QJsonObject operation;
        QVERIFY(servers.pendingPeerRevocation(id,DockerContainer::WireGuard,operation)); QVERIFY(operation.isEmpty());
        QVERIFY(servers.compareAndSetPendingPeerRevocation(id,DockerContainer::WireGuard,{},pending));
        QProcess child; auto environment=QProcessEnvironment::systemEnvironment();
        environment.insert("AMNEZIA_TEST_REVOCATION_READER",organization); environment.insert("AMNEZIA_TEST_PENDING_SERVER",id);
        child.setProcessEnvironment(environment);
        child.start(QCoreApplication::applicationFilePath(),{"pendingPeerRevocationIsDurableAndSeparateFromExport"});
        QVERIFY(child.waitForFinished(30000)); QCOMPARE(child.exitStatus(),QProcess::NormalExit); QCOMPARE(child.exitCode(),0);
        const QJsonObject exportPending{{"independent-export",true}};
        QVERIFY(servers.compareAndSetPendingPeerExport(id,DockerContainer::WireGuard,{},exportPending));
        QVERIFY(servers.pendingPeerRevocation(id,DockerContainer::WireGuard,operation)); QCOMPARE(operation,pending);
        QVERIFY(!servers.compareAndSetPendingPeerRevocation(id,DockerContainer::WireGuard,{},{{"different",true}}));
        QVERIFY(!servers.compareAndSetPendingPeerRevocation(id,DockerContainer::Awg,{},pending));
        QVERIFY(!servers.compareAndSetPendingPeerRevocation("missing",DockerContainer::WireGuard,{},pending));
        QVERIFY(!settings.backupAppConfig().contains("pendingPeerRevocations"));
        QVERIFY(!settings.backupAppConfig().contains("synthetic-private-revocation-context"));
        QVERIFY(!QJsonDocument(*servers.serverJsonById(id)).toJson().contains("synthetic-private-revocation-context"));
        ExportController exporter(&servers,nullptr);
        const auto exported=exporter.generateFullAccessConfig(id);
        const auto json=qUncompress(QByteArray::fromBase64(exported.config.mid(6).toLatin1(),QByteArray::Base64UrlEncoding));
        QVERIFY(!json.contains("pendingPeerRevocations")); QVERIFY(!json.contains("synthetic-private-revocation-context"));
        const auto injected=QJsonDocument(QJsonObject{{"Conf/pendingPeerRevocations",QJsonObject{{"untrusted",true}}},{"Conf/testRestore",true}}).toJson();
        QVERIFY(settings.restoreAppConfig(injected));
        QVERIFY(servers.pendingPeerRevocation(id,DockerContainer::WireGuard,operation)); QCOMPARE(operation,pending);
        QVERIFY(servers.compareAndSetPendingPeerRevocation(id,DockerContainer::WireGuard,pending,{}));
        QVERIFY(servers.pendingPeerExport(id,DockerContainer::WireGuard,operation)); QCOMPARE(operation,exportPending);
        const auto key="Conf/pendingPeerRevocations";
        for (const auto &bad: {QByteArray("corrupt"),QByteArray("{\"version\":99,\"operations\":{}}"),
            QJsonDocument(QJsonObject{{"version",1},{"operations",QJsonObject{{id+":amnezia-wireguard",QJsonObject{}}}}}).toJson()}) {
            settings.setValue(key,bad);
            QVERIFY(!servers.pendingPeerRevocation(id,DockerContainer::WireGuard,operation));
            QVERIFY(!servers.compareAndSetPendingPeerRevocation(id,DockerContainer::WireGuard,{},pending));
        }
        settings.clearSettings();
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
        QVERIFY(!settings.compareAndSetDurable("Conf/pendingPeerRevocations",{},QByteArray("must-not-report-durable")));
        QVERIFY(!settings.value("Conf/pendingPeerExports").isValid());
        QVERIFY(!settings.value("Conf/pendingPeerRevocations").isValid());
        const QByteArray previous("previous accepted view");
        settings.setValue("Conf/pendingPeerRevocations",previous);
        QVERIFY(!settings.compareAndSetDurable("Conf/pendingPeerRevocations",previous,QByteArray("unconfirmed replacement")));
        QCOMPARE(settings.value("Conf/pendingPeerRevocations").toByteArray(),previous);
    }
    void administratorIPv6CommitRejectsChangedProfile()
    {
        SecureQSettings settings("Amnezia-IPv6-Commit-"+QUuid::createUuid().toString(),"test",nullptr,false);
        SecureServersRepository servers(&settings);SecureAppSettingsRepository app(&settings);InstallController installer(&servers,&app);
        auto original=profile();original.remove("connectionUpdates");original["userName"]="root";original["password"]="local-secret";original["port"]=22;
        const auto id=servers.addServer({},original,serverConfigUtils::SelfHostedAdmin);
        const auto expected=servers.selfHostedAdminConfig(id)->toJson();
        const QJsonObject assignments{{client(original,false).value("client_pub_key").toString(),"fd77::2"}};
        auto edited=*servers.serverJsonById(id);edited["description"]="concurrent user edit";servers.editServer(id,edited,serverConfigUtils::SelfHostedAdmin);
        QVERIFY(!installer.applyPreparedAdministratorIPv6(id,DockerContainer::WireGuard,expected,assignments,{"10.8.0.1","fd77::1"}));QCOMPARE(*servers.serverJsonById(id),edited);
        const auto current=servers.selfHostedAdminConfig(id)->toJson();
        QVERIFY(installer.applyPreparedAdministratorIPv6(id,DockerContainer::WireGuard,current,assignments,{"10.8.0.1","fd77::1"}));
        const auto result=*servers.serverJsonById(id);QCOMPARE(result.value("description"),edited.value("description"));
        QCOMPARE(client(result,false).value("client_priv_key"),client(original,false).value("client_priv_key"));
        QCOMPARE(client(result,false).value("client_ip").toString(),"10.8.0.2, fd77::2/128");
        settings.clearSettings();
    }
    void oldAdministratorProfileNeedsProbeRefreshOnce()
    {
        SecureQSettings settings("Amnezia-Probe-" + QUuid::createUuid().toString(), "test", nullptr, false);
        SecureServersRepository servers(&settings); SecureAppSettingsRepository app(&settings); VpnConnection vpn(&servers, &app); ConnectionController connection(&servers, &app, &vpn);
        auto administrator = profile(); administrator.remove("connectionUpdates"); administrator["userName"] = "root"; administrator["password"] = "test-password"; administrator["port"] = 22;
        const auto id = servers.addServer({}, administrator, serverConfigUtils::SelfHostedAdmin);
        ConnectionUpdatesController updates(&servers, &connection);
        QVERIFY(!updates.available(id)); QVERIFY(updates.needsRefreshBeforeConnect(id));
        QJsonObject migrated;
        QVERIFY(connectionUpdates::mergePathProbe(*servers.serverJsonById(id),"amnezia-wireguard","10.8.0.1",migrated));
        servers.editServer(id,migrated,serverConfigUtils::SelfHostedAdmin);
        QVERIFY(updates.needsRefreshBeforeConnect(id)); // The old single-target format also needs migration.
        QVERIFY(connectionUpdates::mergePathProbes(*servers.serverJsonById(id), "amnezia-wireguard", {"10.8.0.1"}, migrated));
        servers.editServer(id, migrated, serverConfigUtils::SelfHostedAdmin);
        QVERIFY(!updates.needsRefreshBeforeConnect(id));
        settings.clearSettings();
    }
    void asynchronousAdminProbeRefresh_data()
    {
        QTest::addColumn<QString>("scenario");QTest::addColumn<bool>("missingIPv6");
        for(bool ipv6:{false,true}) for (const auto *name : { "success", "failure", "edited", "deadline", "canceled" })
            QTest::newRow(qPrintable(QString(name)+(ipv6?"-missing-ipv6":"-probe-only"))) << QString(name) << ipv6;
    }
    void asynchronousAdminProbeRefresh()
    {
        QFETCH(QString, scenario);QFETCH(bool,missingIPv6);
        SecureQSettings settings("Amnezia-Probe-Async-" + QUuid::createUuid().toString(), "test", nullptr, false);
        SecureServersRepository servers(&settings); SecureAppSettingsRepository app(&settings); VpnConnection vpn(&servers, &app); ConnectionController connection(&servers, &app, &vpn);
        disconnect(&connection, &ConnectionController::openConnectionRequested, &vpn, &VpnConnection::connectToVpn);
        auto administrator = profile(); administrator.remove("connectionUpdates"); administrator["userName"] = "root"; administrator["password"] = "test-password"; administrator["port"] = 22;
        if(missingIPv6) {
            auto containers=administrator["containers"].toArray();auto container=containers[0].toObject();auto proto=container["wireguard"].toObject();auto cached=client(administrator,false);
            cached["allowed_ips"]=QJsonArray{"0.0.0.0/0","::/0"};cached["path_mtu_probes"]=QJsonArray{"10.8.0.1"};
            proto["last_config"]=QString::fromUtf8(QJsonDocument(cached).toJson(QJsonDocument::Compact));container["wireguard"]=proto;containers[0]=container;administrator["containers"]=containers;
        }
        const auto id = servers.addServer({}, administrator, serverConfigUtils::SelfHostedAdmin); servers.setDefaultServer(id);
        const auto original = *servers.serverJsonById(id);
        QSemaphore gate; std::atomic<int> calls { 0 }; std::atomic<bool> correctReaderArguments { false };
        ConnectionUpdatesController updates(&servers, &connection, nullptr, [&](const ServerCredentials &credentials, DockerContainer container, QStringList &targets) {
            correctReaderArguments.store(credentials.userName == "root" && container == DockerContainer::WireGuard);
            calls.fetch_add(1); gate.acquire(); targets = {"10.8.0.1", "fd77::1"};
            return scenario == "failure" ? ErrorCode::InternalError : ErrorCode::NoError;
        },[&](const ServerCredentials &,DockerContainer,QJsonObject &assignments) {
            assignments={{client(original,false).value("client_pub_key").toString(),"fd77::2"}};return ErrorCode::NoError;
        });
        QVERIFY(updates.needsRefreshBeforeConnect(id));
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
            if(missingIPv6) {
                QCOMPARE(client(result,false).value("client_ip").toString(),"10.8.0.2, fd77::2/128");
                QCOMPARE(client(result,false).value("path_mtu_probes").toArray(),QJsonArray({"10.8.0.1","fd77::1"}));
                QVERIFY(!updates.needsRefreshBeforeConnect(id));
            }
        } else if (scenario == "failure" || scenario == "deadline") QCOMPARE(result, original);
        else if (scenario == "edited") { QCOMPARE(result.value("description").toString(), "user edit"); QVERIFY(!client(result, false).contains("path_mtu_probe")); }
        settings.clearSettings();
    }
    void realServerIPv6Activation()
    {
        if (qEnvironmentVariable("AMNEZIA_IPV6_ACTIVATION_TEST") != "isolated-docker")
            QSKIP("Run server/ipv6/lab/test_activation.py with this executable");
        QCOMPARE(qEnvironmentVariable("AMNEZIA_SSH_PROBE_HOST"), QString("127.0.0.1"));
        ServerCredentials credentials; credentials.hostName="127.0.0.1";
        credentials.port=qEnvironmentVariableIntValue("AMNEZIA_SSH_PROBE_PORT");
        credentials.userName="root"; credentials.secretData="synthetic-probe-fixture";
        const auto selected=qEnvironmentVariable("AMNEZIA_IPV6_CONTAINER");
        QVERIFY(selected=="amnezia-wireguard" || selected=="amnezia-awg2");
        const auto container=selected=="amnezia-awg2"?DockerContainer::Awg2:DockerContainer::WireGuard;
        const auto tool=container==DockerContainer::Awg2?QString("awg"):QString("wg");
        const auto iface=container==DockerContainer::Awg2?QString("awg0"):QString("wg0");
        SshSession ssh; QString labels;
        QCOMPARE(ssh.runScript(credentials,"test -f /run/amnezia-ipv6-fixture && sudo docker info --format '{{json .Labels}}'",
            [&](const QString &data,libssh::Client &){labels+=data;return ErrorCode::NoError;}),ErrorCode::NoError);
        QVERIFY(QJsonDocument::fromJson(labels.toUtf8()).array().contains("amnezia.test-environment=disposable"));
        auto publicKey=[&]() {
            QString value;
            const auto error=ssh.runScript(credentials,QString("sudo docker exec %1 %2 show %3 public-key").arg(selected,tool,iface),
                [&](const QString &data,libssh::Client &){value+=data;return ErrorCode::NoError;});
            if(error!=ErrorCode::NoError)return QString();
            return value.trimmed();
        };
        const auto original=publicKey();QVERIFY(!original.isEmpty());
        QJsonObject metadata;
        QCOMPARE(ConnectionUpdatesController::command(credentials,"info",{},metadata),ErrorCode::NoError);
        QJsonObject outcome;
        const auto error=ConnectionUpdatesController::prepareServerIPv6(credentials,container,outcome,metadata);
        QVERIFY2(error==ErrorCode::NoError,qPrintable(QString::fromUtf8(QJsonDocument(outcome).toJson(QJsonDocument::Compact))));
        QCOMPARE(outcome.value("result").toString(),qEnvironmentVariable("AMNEZIA_IPV6_EXPECT"));
        QCOMPARE(publicKey(),original);
        QJsonObject assignments;
        QCOMPARE(ConnectionUpdatesController::fetchPeerIPv6Assignments(credentials,container,assignments),ErrorCode::NoError);
        QCOMPARE(assignments.size(),2);
        for(auto it=assignments.begin();it!=assignments.end();++it)
            QCOMPARE(!it.value().toString().isEmpty(),outcome.value("result")=="applied");
        if(outcome.value("result")=="applied") {
            QString raw;
            QCOMPARE(ssh.runScript(credentials,"cat /run/amnezia-cached-client.json",[&](const QString &data,libssh::Client &){if(raw.size()+data.size()>65536)return ErrorCode::InternalError;raw+=data;return ErrorCode::NoError;}),ErrorCode::NoError);
            const auto cached=QJsonDocument::fromJson(raw.toUtf8()).object();
            QStringList probes;QCOMPARE(ConnectionUpdatesController::fetchPathMtuProbeAddresses(credentials,container,probes),ErrorCode::NoError);
            auto administrator=cached;administrator["hostName"]=credentials.hostName;administrator["userName"]=credentials.userName;administrator["password"]=credentials.secretData;administrator["port"]=credentials.port;
            auto containers=administrator["containers"].toArray();auto chosen=containers[0].toObject();const auto protoName=container==DockerContainer::Awg2?"awg":"wireguard";auto proto=chosen[protoName].toObject();auto oldClient=client(cached,container==DockerContainer::Awg2);
            oldClient["path_mtu_probes"]=QJsonArray{probes.first()};proto["last_config"]=QString::fromUtf8(QJsonDocument(oldClient).toJson(QJsonDocument::Compact));chosen[protoName]=proto;containers[0]=chosen;administrator["containers"]=containers;
            SecureQSettings localSettings("Amnezia-Live-IPv6-"+QUuid::createUuid().toString(),"test",nullptr,false);
            SecureServersRepository localServers(&localSettings);SecureAppSettingsRepository localApp(&localSettings);VpnConnection localVpn(&localServers,&localApp);ConnectionController localConnection(&localServers,&localApp,&localVpn);
            const auto localId=localServers.addServer({},administrator,serverConfigUtils::SelfHostedAdmin);ConnectionUpdatesController localUpdates(&localServers,&localConnection);
            QVERIFY(localUpdates.needsRefreshBeforeConnect(localId));int completed=0;localUpdates.refreshBeforeConnect(localId,[&]{++completed;});
            QTRY_VERIFY_WITH_TIMEOUT(!localUpdates.busy(),4000);QCOMPARE(completed,1);
            const auto updated=*localServers.serverJsonById(localId);QVERIFY(!localUpdates.needsRefreshBeforeConnect(localId));
            localSettings.clearSettings();
            for(const auto *key:{"client_priv_key","client_pub_key","allowed_ips"})QCOMPARE(client(updated,container==DockerContainer::Awg2).value(key),client(cached,container==DockerContainer::Awg2).value(key));
            QCOMPARE(ssh.uploadFileToHost(credentials,QJsonDocument(updated).toJson(QJsonDocument::Compact),"/run/amnezia-cached-client-ipv6.json"),ErrorCode::NoError);
            const auto cachedClient=client(cached,container==DockerContainer::Awg2);
            auto operation=[&](const QByteArray &label) { return QString::fromLatin1(QCryptographicHash::hash(selected.toUtf8()+label,QCryptographicHash::Sha256).toHex()); };
            QJsonObject oldRequest{{"operation",operation("legacy-probe-replay")},{"container",selected},
                {"clientPublicKey",cachedClient.value("client_pub_key")},{"settings",connectionUpdates::publicSettings(cachedClient,container==DockerContainer::Awg2)},
                {"pathMtuProbe",probes.first()}};
            QJsonObject first,replayed,before,after;
            QCOMPARE(ConnectionUpdatesController::command(credentials,"issue",oldRequest,first),ErrorCode::NoError);
            QCOMPARE(ConnectionUpdatesController::command(credentials,"info",{},before),ErrorCode::NoError);
            auto upgraded=oldRequest;upgraded["pathMtuProbes"]=QJsonArray::fromStringList(probes);
            QCOMPARE(ConnectionUpdatesController::issue(credentials,upgraded,replayed),ErrorCode::NoError);
            QVERIFY(replayed.value("replayed").toBool());QCOMPARE(replayed.value("id"),first.value("id"));QCOMPARE(replayed.value("token"),first.value("token"));
            QCOMPARE(ConnectionUpdatesController::command(credentials,"info",{},after),ErrorCode::NoError);QCOMPARE(after.value("stateTag"),before.value("stateTag"));
            upgraded["operation"]=operation("new-probe-replay");
            QCOMPARE(ConnectionUpdatesController::issue(credentials,upgraded,first),ErrorCode::NoError);
            QCOMPARE(ConnectionUpdatesController::command(credentials,"info",{},before),ErrorCode::NoError);
            upgraded["pathMtuProbes"]=QJsonArray{probes.first(),"fd77:ffff::1"};
            QVERIFY(ConnectionUpdatesController::issue(credentials,upgraded,replayed)!=ErrorCode::NoError);
            QCOMPARE(ConnectionUpdatesController::command(credentials,"info",{},after),ErrorCode::NoError);QCOMPARE(after.value("stateTag"),before.value("stateTag"));
        }
        qInfo().noquote()<<"IPV6_ACTIVATION_RESULT "+QString::fromUtf8(QJsonDocument(outcome).toJson(QJsonDocument::Compact));
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
        QStringList targets;
        QCOMPARE(ConnectionUpdatesController::fetchPathMtuProbeAddresses(credentials,DockerContainer::WireGuard,targets),ErrorCode::NoError);
        QCOMPARE(targets,QStringList({"10.77.0.9","fd77::1"}));
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
    void realAdminStagePublicationRecovery()
    {
        const auto host=qEnvironmentVariable("AMNEZIA_SSH_PROBE_HOST");
        if (host.isEmpty()) QSKIP("Run scripts/local-tests/path-probe-ssh.sh with this test executable");
        ServerCredentials credentials; credentials.hostName=host;
        credentials.port=qEnvironmentVariableIntValue("AMNEZIA_SSH_PROBE_PORT");
        credentials.userName="root"; credentials.secretData="synthetic-probe-fixture";
        for (const auto container:{DockerContainer::WireGuard,DockerContainer::Awg2}) {
            SshSession manager; ErrorCode read=ErrorCode::NoError;
            const auto name=ContainerUtils::containerToString(container);
            const QString path=container==DockerContainer::Awg2?"/opt/amnezia/awg/awg0.conf":"/opt/amnezia/wireguard/wg0.conf";
            const auto original=QString::fromUtf8(manager.getTextFileFromContainer(container,credentials,path,read));
            QCOMPARE(read,ErrorCode::NoError); QVERIFY(!original.isEmpty());
            const auto candidate=original+"\n# interrupted journal publication regression\n";
            QJsonObject staged;
            QCOMPARE(manager.protocolConfigTransaction(container,credentials,{{"action","stage-live"},
                {"expected",QString::fromLatin1(original.toUtf8().toBase64())},
                {"candidate",QString::fromLatin1(candidate.toUtf8().toBase64())}},staged),ErrorCode::NoError);
            // State after durable journal publication but before candidate rename.
            // Private data stays inside the disposable server, never in arguments.
            const auto restoreOriginal=QString("sudo docker exec %1 python3 -c 'import json,pathlib,base64; p=pathlib.Path(\"%2\"); j=json.loads(pathlib.Path(str(p)+\".amnezia-journal\").read_bytes()); p.write_bytes(base64.b64decode(j[\"original\"]))'").arg(name,path);
            QCOMPARE(manager.runScript(credentials,restoreOriginal),ErrorCode::NoError);
            QJsonObject status;
            QCOMPARE(manager.protocolConfigTransaction(container,credentials,{{"action","status"}},status),ErrorCode::NoError);
            QCOMPARE(status.value("state").toString(),QString("original"));
            QJsonObject denied;
            QVERIFY(manager.protocolConfigTransaction(container,credentials,{{"action","discard-stage"},
                {"operation",QString(64,'0')}},denied)!=ErrorCode::NoError);
            bool handled=false;
            QCOMPARE(manager.replaceLiveProtocolConfig(container,credentials,original,candidate,handled),ErrorCode::NoError);
            QVERIFY(handled);
            QVERIFY(QString::fromUtf8(manager.getTextFileFromContainer(container,credentials,path,read))==candidate);
            QCOMPARE(read,ErrorCode::NoError);
            QVERIFY(manager.protocolConfigTransaction(container,credentials,{{"action","status"}},status)!=ErrorCode::NoError);
            handled=false;
            QCOMPARE(manager.replaceLiveProtocolConfig(container,credentials,candidate,original,handled),ErrorCode::NoError);
            QVERIFY(handled);
            QVERIFY(QString::fromUtf8(manager.getTextFileFromContainer(container,credentials,path,read))==original);
            QCOMPARE(read,ErrorCode::NoError);
            const auto tablePath=QString("/opt/amnezia/%1/clientsTable").arg(ContainerUtils::containerTypeToString(container));
            const auto table=manager.getTextFileFromContainer(container,credentials,tablePath,read);
            QCOMPARE(read,ErrorCode::NoError);
            const auto tableDocument=QJsonDocument::fromJson(table); QVERIFY(tableDocument.isArray());
            auto changed=tableDocument.array();
            changed.append(QJsonObject{{"clientId","synthetic-cas-only-metadata"},{"unknown",QJsonObject{{"preserve",true}}}});
            const auto replacement=QJsonDocument(changed).toJson();
            QJsonObject receipt;
            QCOMPARE(manager.protocolConfigTransaction(container,credentials,{{"action","replace-client-table"},
                {"expected",QString::fromLatin1(table.toBase64())},{"candidate",QString::fromLatin1(replacement.toBase64())}},receipt),ErrorCode::NoError);
            QVERIFY(manager.protocolConfigTransaction(container,credentials,{{"action","replace-client-table"},
                {"expected",QString::fromLatin1(table.toBase64())},{"candidate",QString::fromLatin1(QByteArray("[]").toBase64())}},receipt)!=ErrorCode::NoError);
            QVERIFY(manager.getTextFileFromContainer(container,credentials,tablePath,read)==replacement);
            QCOMPARE(read,ErrorCode::NoError);
            QCOMPARE(manager.protocolConfigTransaction(container,credentials,{{"action","check-client-table"},
                {"expected",QString::fromLatin1(replacement.toBase64())}},receipt),ErrorCode::NoError);
            QCOMPARE(manager.protocolConfigTransaction(container,credentials,{{"action","replace-client-table"},
                {"expected",QString::fromLatin1(replacement.toBase64())},{"candidate",QString::fromLatin1(table.toBase64())}},receipt),ErrorCode::NoError);
            QVERIFY(manager.getTextFileFromContainer(container,credentials,tablePath,read)==table);
            QCOMPARE(read,ErrorCode::NoError);
        }
    }
    void realAdminManagedClientMetadata()
    {
        const auto host=qEnvironmentVariable("AMNEZIA_SSH_PROBE_HOST");
        if (host.isEmpty()) QSKIP("Run scripts/local-tests/path-probe-ssh.sh with this test executable");
        ServerCredentials credentials; credentials.hostName=host; credentials.port=qEnvironmentVariableIntValue("AMNEZIA_SSH_PROBE_PORT");
        credentials.userName="root"; credentials.secretData="synthetic-probe-fixture";
        for (const auto container:{DockerContainer::WireGuard,DockerContainer::Awg2}) {
            SecureQSettings settings("Amnezia-Managed-Metadata-"+QUuid::createUuid().toString(),"test",nullptr,false);
            SecureServersRepository servers(&settings);
            auto administrator=profile(container==DockerContainer::Awg2); administrator.remove("connectionUpdates");
            administrator["hostName"]=host; administrator["userName"]=credentials.userName;
            administrator["password"]=credentials.secretData; administrator["port"]=credentials.port;
            const auto id=servers.addServer({},administrator,serverConfigUtils::SelfHostedAdmin);
            SshSession ssh; ErrorCode error=ErrorCode::NoError;
            const auto name=ContainerUtils::containerToString(container);
            const auto tablePath=QString("/opt/amnezia/%1/clientsTable").arg(ContainerUtils::containerTypeToString(container));
            const QString configPath=container==DockerContainer::Awg2?"/opt/amnezia/awg/awg0.conf":"/opt/amnezia/wireguard/wg0.conf";
            const auto config=ssh.getTextFileFromContainer(container,credentials,configPath,error); QCOMPARE(error,ErrorCode::NoError);
            const auto baseline=ssh.getTextFileFromContainer(container,credentials,tablePath,error); QCOMPARE(error,ErrorCode::NoError);
            const auto a=QString::fromLatin1(QByteArray(32,'A').toBase64()),b=QString::fromLatin1(QByteArray(32,'B').toBase64());
            const auto y=QString::fromLatin1(QByteArray(32,'Y').toBase64());
            const QJsonObject oldData{{"clientName","old A"},{"creationDate","keep"},{"number",1000},{"custom",QJsonObject{{"nested",QJsonArray{true,7}}}}};
            auto legacy=QJsonDocument(QJsonObject{{a,oldData},{b,QJsonObject{{"clientName","old B"}}}}).toJson();
            legacy.replace("\"number\": 1000","\"number\": 1e3"); QVERIFY(legacy.contains("1e3"));
            QCOMPARE(ssh.uploadTextFileToContainer(container,credentials,QString::fromUtf8(legacy),tablePath),ErrorCode::NoError);
            QCOMPARE(ssh.runScript(credentials,QString("sudo docker exec %1 rm -f /opt/amnezia/protocol-loss-client-table-migration").arg(name)),ErrorCode::NoError);
            UsersController users(&servers); QSignalSpy listed(&users,&UsersController::clientsUpdated);
            QCOMPARE(users.updateClients(id,container),ErrorCode::NoError); QVERIFY(!listed.isEmpty());
            auto raw=ssh.getTextFileFromContainer(container,credentials,tablePath,error); QCOMPARE(error,ErrorCode::NoError);
            auto table=QJsonDocument::fromJson(raw).array();
            auto rowFor=[](const QJsonArray &entries,const QString &key){for (int i=0;i<entries.size();++i) if(entries[i].toObject().value("clientId")==key)return i;return -1;};
            const auto aRow=rowFor(table,a),bRow=rowFor(table,b); QVERIFY(aRow>=0 && bRow>=0);
            QVERIFY(table[aRow].toObject().value("userData").toObject()==oldData);
            QCOMPARE(ssh.getTextFileFromContainer(container,credentials,"/opt/amnezia/protocol-loss-client-table-migration",error),QByteArray("1")); QCOMPARE(error,ErrorCode::NoError);
            const auto stale=qvariant_cast<QJsonArray>(listed.last().first()); const auto staleRow=rowFor(stale,a); QVERIFY(staleRow>=0);
            auto changedB=table[bRow].toObject(); changedB["external"]=QJsonObject{{"preserve",true}}; table[bRow]=changedB;
            table.append(QJsonObject{{"clientId","independent metadata"},{"unknown",QJsonArray{1,2,3}}});
            auto moved=table.takeAt(aRow); table.append(moved);
            bool handled=false; auto parallel=QJsonDocument(table).toJson();
            QCOMPARE(ssh.replaceClientTable(container,credentials,raw,parallel,handled),ErrorCode::NoError); QVERIFY(handled);
            QCOMPARE(ssh.runScript(credentials,QString("sudo docker exec %1 rm -f /opt/amnezia/protocol-loss-client-table").arg(name)),ErrorCode::NoError);
            QCOMPARE(users.renameClient(id,staleRow,"new A",container),ErrorCode::NoError);
            raw=ssh.getTextFileFromContainer(container,credentials,tablePath,error); QCOMPARE(error,ErrorCode::NoError);
            auto renamed=QJsonDocument::fromJson(raw).array();
            QVERIFY(renamed[rowFor(renamed,b)]==changedB); QVERIFY(renamed[rowFor(renamed,"independent metadata")]==table[rowFor(table,"independent metadata")]);
            auto expectedData=oldData; expectedData["clientName"]="new A";
            QVERIFY(renamed[rowFor(renamed,a)].toObject().value("userData").toObject()==expectedData);
            QCOMPARE(ssh.getTextFileFromContainer(container,credentials,"/opt/amnezia/protocol-loss-client-table",error),QByteArray("1")); QCOMPARE(error,ErrorCode::NoError);
            QJsonObject pending;
            QCOMPARE(ssh.protocolConfigTransaction(container,credentials,{{"action","stage-live"},{"expected",QString::fromLatin1(config.toBase64())},
                {"candidate",QString::fromLatin1((config+"\n# metadata writer barrier\n").toBase64())}},pending),ErrorCode::NoError);
            const auto currentView=qvariant_cast<QJsonArray>(listed.last().first()); const auto row=rowFor(currentView,a); QVERIFY(row>=0);
            const auto signalsBefore=listed.count();
            QVERIFY(users.renameClient(id,row,"blocked rename",container)!=ErrorCode::NoError); QCOMPARE(listed.count(),signalsBefore);
            QVERIFY(ssh.getTextFileFromContainer(container,credentials,tablePath,error)==raw); QCOMPARE(error,ErrorCode::NoError);
            QJsonObject rolledBack;
            QCOMPARE(ssh.protocolConfigTransaction(container,credentials,{{"action","rollback-live"},{"operation",pending.value("operation")}},rolledBack),ErrorCode::NoError);
            QCOMPARE(users.appendClient(id,y,"new metadata",container),ErrorCode::NoError);
            QCOMPARE(users.appendClient(id,y,"updated metadata",container),ErrorCode::NoError);
            raw=ssh.getTextFileFromContainer(container,credentials,tablePath,error); QCOMPARE(error,ErrorCode::NoError);
            const auto appended=QJsonDocument::fromJson(raw).array(); int matches=0;
            for (const auto &entry:appended) if(entry.toObject().value("clientId")==y) ++matches;
            QCOMPARE(matches,1); QCOMPARE(appended[rowFor(appended,y)].toObject().value("userData").toObject().value("clientName").toString(),QString("updated metadata"));
            QVERIFY(appended[rowFor(appended,b)]==changedB);
            // Malformed old data must not be replaced with generated defaults.
            const auto beforeCorruptView=qvariant_cast<QJsonArray>(listed.last().first());
            QCOMPARE(ssh.uploadTextFileToContainer(container,credentials,"corrupt legacy metadata",tablePath),ErrorCode::NoError);
            QVERIFY(users.updateClients(id,container)!=ErrorCode::NoError);
            QVERIFY(qvariant_cast<QJsonArray>(listed.last().first())==beforeCorruptView);
            QCOMPARE(ssh.getTextFileFromContainer(container,credentials,tablePath,error),QByteArray("corrupt legacy metadata")); QCOMPARE(error,ErrorCode::NoError);
            QCOMPARE(ssh.uploadTextFileToContainer(container,credentials,QString::fromUtf8(baseline),tablePath),ErrorCode::NoError);
            QJsonObject native;
            QCOMPARE(ssh.protocolConfigTransaction(container,credentials,{{"action","check-live"},{"expected",QString::fromLatin1(config.toBase64())}},native),ErrorCode::NoError); QVERIFY(native.value("current").toBool());
            settings.clearSettings();
        }
    }
    void realAdminProfileRevokeMigratesMetadata_data()
    {
        QTest::addColumn<int>("containerIndex");
        QTest::newRow("wireguard")<<static_cast<int>(DockerContainer::WireGuard);
        QTest::newRow("awg")<<static_cast<int>(DockerContainer::Awg2);
    }
    void realAdminProfileRevokeMigratesMetadata()
    {
        const auto host=qEnvironmentVariable("AMNEZIA_SSH_PROBE_HOST");
        if (host.isEmpty()) QSKIP("Run scripts/local-tests/path-probe-ssh.sh with this test executable");
        ServerCredentials credentials; credentials.hostName=host; credentials.port=qEnvironmentVariableIntValue("AMNEZIA_SSH_PROBE_PORT");
        credentials.userName="root"; credentials.secretData="synthetic-probe-fixture";
        QFETCH(int,containerIndex);
        const auto container=static_cast<DockerContainer>(containerIndex);
        {
            SecureQSettings settings("Amnezia-Profile-Revoke-Migration-"+QUuid::createUuid().toString(),"test",nullptr,false);
            SecureServersRepository servers(&settings);
            auto administrator=profile(container==DockerContainer::Awg2); administrator.remove("connectionUpdates");
            administrator["hostName"]=host; administrator["userName"]=credentials.userName;
            administrator["password"]=credentials.secretData; administrator["port"]=credentials.port;
            const auto id=servers.addServer({},administrator,serverConfigUtils::SelfHostedAdmin);
            auto target=servers.selfHostedAdminConfig(id)->containerConfig(container);
            const auto key=QString::fromLatin1(QByteArray(32,'N').toBase64());
            const auto a=QString::fromLatin1(QByteArray(32,'B').toBase64());
            target.protocolConfig.setClientConfigJson({{"clientId",key},{"client_pub_key",key}});
            QCOMPARE(target.protocolConfig.clientId(),key);
            SshSession ssh; ErrorCode error=ErrorCode::NoError;
            const auto name=ContainerUtils::containerToString(container);
            const auto tablePath=QString("/opt/amnezia/%1/clientsTable").arg(ContainerUtils::containerTypeToString(container));
            const QString path=container==DockerContainer::Awg2?"/opt/amnezia/awg/awg0.conf":"/opt/amnezia/wireguard/wg0.conf";
            const auto baseline=QString::fromUtf8(ssh.getTextFileFromContainer(container,credentials,path,error)); QCOMPARE(error,ErrorCode::NoError); QVERIFY(!baseline.contains(key));
            const auto baselineTable=ssh.getTextFileFromContainer(container,credentials,tablePath,error); QCOMPARE(error,ErrorCode::NoError);
            const auto added=baseline+"\n[Peer]\nPublicKey = "+key+"\nAllowedIPs = 10.251.0.249/32\n";
            QString removed; QVERIFY(connectionUpdates::removePeerFromServerConfig(added,key,removed));
            const QJsonObject keep{{"clientName","preserved existing peer"},{"extra",QJsonObject{{"unchanged",true}}}};
            QVERIFY(baseline.contains(a)); // A peer actually installed by the fixture.
            const auto legacy=QJsonDocument(QJsonObject{{key,QJsonObject{{"clientName","old N"},{"extra",7}}},{a,keep}}).toJson();
            const auto missingRow=QJsonDocument(QJsonArray{QJsonObject{{"clientId",a},{"userData",keep}}}).toJson();
            for (const auto &old: {legacy,QByteArray{},QByteArray("[]"),missingRow,QByteArray("corrupt profile metadata")}) {
                bool handled=false;
                QCOMPARE(ssh.replaceLiveProtocolConfig(container,credentials,baseline,added,handled),ErrorCode::NoError); QVERIFY(handled);
                QCOMPARE(ssh.uploadTextFileToContainer(container,credentials,QString::fromUtf8(old),tablePath),ErrorCode::NoError);
                QCOMPARE(ssh.runScript(credentials,QString("sudo docker exec %1 rm -f /opt/amnezia/protocol-loss-client-table-migration").arg(name)),ErrorCode::NoError);
                UsersController fresh(&servers); // Never calls updateClients before profile revoke.
                const auto result=fresh.revokeClient(id,target,container);
                QJsonObject pending; QVERIFY(servers.pendingPeerRevocation(id,container,pending)); QVERIFY(pending.isEmpty());
                if (old=="corrupt profile metadata") {
                    QVERIFY(result!=ErrorCode::NoError);
                    QVERIFY(QString::fromUtf8(ssh.getTextFileFromContainer(container,credentials,path,error))==added); QCOMPARE(error,ErrorCode::NoError);
                    QCOMPARE(ssh.getTextFileFromContainer(container,credentials,tablePath,error),old); QCOMPARE(error,ErrorCode::NoError);
                    QJsonObject unchanged;
                    QCOMPARE(ssh.protocolConfigTransaction(container,credentials,{{"action","check-live"},{"expected",QString::fromLatin1(added.toUtf8().toBase64())}},unchanged),ErrorCode::NoError);
                    handled=false; QCOMPARE(ssh.replaceLiveProtocolConfig(container,credentials,added,baseline,handled),ErrorCode::NoError); QVERIFY(handled);
                } else {
                    QCOMPARE(result,ErrorCode::NoError);
                    QVERIFY(QString::fromUtf8(ssh.getTextFileFromContainer(container,credentials,path,error))==removed); QCOMPARE(error,ErrorCode::NoError);
                    const auto entries=QJsonDocument::fromJson(ssh.getTextFileFromContainer(container,credentials,tablePath,error)).array(); QCOMPARE(error,ErrorCode::NoError);
                    bool preserved=false;
                    for (const auto &entry:entries) {
                        QVERIFY(entry.toObject().value("clientId")!=key);
                        if (entry.toObject().value("clientId")==a) {
                            preserved=true;
                            if (old==legacy || old==missingRow) QVERIFY(entry.toObject().value("userData").toObject()==keep);
                        }
                    }
                    QVERIFY(preserved);
                    if (!QJsonDocument::fromJson(old).isArray()) {
                        QCOMPARE(ssh.getTextFileFromContainer(container,credentials,"/opt/amnezia/protocol-loss-client-table-migration",error),QByteArray("1")); QCOMPARE(error,ErrorCode::NoError);
                    }
                    QJsonObject unchanged;
                    QCOMPARE(ssh.protocolConfigTransaction(container,credentials,{{"action","check-live"},{"expected",QString::fromLatin1(removed.toUtf8().toBase64())}},unchanged),ErrorCode::NoError);
                    handled=false; QCOMPARE(ssh.replaceLiveProtocolConfig(container,credentials,removed,baseline,handled),ErrorCode::NoError); QVERIFY(handled);
                }
                QCOMPARE(ssh.uploadTextFileToContainer(container,credentials,QString::fromUtf8(baselineTable),tablePath),ErrorCode::NoError);
            }
            settings.clearSettings();
        }
    }
    void realAdminV1RevocationContext()
    {
        const auto host=qEnvironmentVariable("AMNEZIA_SSH_PROBE_HOST");
        if (host.isEmpty()) QSKIP("Run scripts/local-tests/path-probe-ssh.sh with this test executable");
        ServerCredentials credentials; credentials.hostName=host; credentials.port=qEnvironmentVariableIntValue("AMNEZIA_SSH_PROBE_PORT");
        credentials.userName="root"; credentials.secretData="synthetic-probe-fixture";
        for (const auto container:{DockerContainer::WireGuard,DockerContainer::Awg2}) {
            SecureQSettings settings("Amnezia-V1-Revoke-"+QUuid::createUuid().toString(),"test",nullptr,false);
            SecureServersRepository servers(&settings);
            auto administrator=profile(container==DockerContainer::Awg2); administrator.remove("connectionUpdates");
            administrator["hostName"]=host; administrator["userName"]=credentials.userName;
            administrator["password"]=credentials.secretData; administrator["port"]=credentials.port;
            const auto id=servers.addServer({},administrator,serverConfigUtils::SelfHostedAdmin);
            SshSession ssh; ErrorCode error=ErrorCode::NoError;
            const QString path=container==DockerContainer::Awg2?"/opt/amnezia/awg/awg0.conf":"/opt/amnezia/wireguard/wg0.conf";
            const auto baseline=QString::fromUtf8(ssh.getTextFileFromContainer(container,credentials,path,error)); QCOMPARE(error,ErrorCode::NoError);
            const auto key=QString::fromLatin1(QByteArray(32,'V').toBase64()); QVERIFY(!baseline.contains(key));
            const auto withPeer=baseline+"\n[Peer]\nPublicKey = "+key+"\nAllowedIPs = 10.251.0.250/32\n";
            QString candidate; QVERIFY(connectionUpdates::removePeerFromServerConfig(withPeer,key,candidate));
            bool handled=false;
            QCOMPARE(ssh.replaceLiveProtocolConfig(container,credentials,baseline,withPeer,handled),ErrorCode::NoError); QVERIFY(handled);
            const auto tablePath=QString("/opt/amnezia/%1/clientsTable").arg(ContainerUtils::containerTypeToString(container));
            const auto baselineTable=ssh.getTextFileFromContainer(container,credentials,tablePath,error); QCOMPARE(error,ErrorCode::NoError);
            auto table=QJsonDocument::fromJson(baselineTable).array(); table.append(QJsonObject{{"clientId",key}});
            const auto originalTable=QJsonDocument(table).toJson();
            QJsonObject receipt;
            QCOMPARE(ssh.protocolConfigTransaction(container,credentials,{{"action","replace-client-table"},
                {"expected",QString::fromLatin1(baselineTable.toBase64())},{"candidate",QString::fromLatin1(originalTable.toBase64())}},receipt),ErrorCode::NoError);
            const QJsonObject target{{"host",credentials.hostName},{"port",credentials.port},{"user",credentials.userName},
                {"secret",credentials.secretData},{"container",ContainerUtils::containerToString(container)},{"updates",QJsonObject{}}};
            const auto binding=QString::fromLatin1(QCryptographicHash::hash(QJsonDocument(target).toJson(QJsonDocument::Compact),QCryptographicHash::Sha256).toHex());
            const QJsonObject pending{{"version",1},{"binding",binding},{"clientPublicKey",key},{"original",withPeer},
                {"candidate",candidate},{"table",QString::fromLatin1(originalTable.toBase64())}};
            QVERIFY(servers.compareAndSetPendingPeerRevocation(id,container,{},pending));
            handled=false;
            QCOMPARE(ssh.replaceLiveProtocolConfig(container,credentials,withPeer,candidate,handled),ErrorCode::NoError); QVERIFY(handled);
            UsersController users(&servers); QCOMPARE(users.updateClients(id,container),ErrorCode::NoError);
            QJsonObject current; QVERIFY(servers.pendingPeerRevocation(id,container,current)); QVERIFY(current.isEmpty());
            QVERIFY(QJsonDocument::fromJson(ssh.getTextFileFromContainer(container,credentials,tablePath,error)).array()==QJsonDocument::fromJson(baselineTable).array());
            QCOMPARE(error,ErrorCode::NoError);
            handled=false;
            QCOMPARE(ssh.replaceLiveProtocolConfig(container,credentials,candidate,baseline,handled),ErrorCode::NoError); QVERIFY(handled);
            settings.clearSettings();
        }
    }
    void realAdminNewIPv6ProfileExport()
    {
        if (qEnvironmentVariableIsSet("AMNEZIA_TEST_RESUME_REVOCATION")) {
            SecureQSettings settings(qEnvironmentVariable("AMNEZIA_TEST_RESUME_REVOCATION"),"test",nullptr,false);
            SecureServersRepository servers(&settings); UsersController users(&servers);
            const auto id=qEnvironmentVariable("AMNEZIA_TEST_REVOCATION_SERVER");
            const auto container=static_cast<DockerContainer>(qEnvironmentVariableIntValue("AMNEZIA_TEST_REVOCATION_CONTAINER"));
            QJsonObject pending; QVERIFY(servers.pendingPeerRevocation(id,container,pending)); QVERIFY(!pending.isEmpty());
            // Opening the list after an app restart automatically resumes it.
            const bool tokenPending=qEnvironmentVariableIsSet("AMNEZIA_TEST_EXPECT_TOKEN_PENDING");
            const bool ackPending=qEnvironmentVariableIsSet("AMNEZIA_TEST_EXPECT_ACK_PENDING");
            QCOMPARE(users.updateClients(id,container),tokenPending?ErrorCode::ConnectionUpdateTokenRevocationPending
                :ackPending?ErrorCode::InternalError:ErrorCode::NoError);
            QVERIFY(servers.pendingPeerRevocation(id,container,pending));
            QCOMPARE(pending.isEmpty(),!tokenPending && !ackPending);
            if (ackPending) QCOMPARE(pending.value("phase").toString(),QString("done"));
            return;
        }
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
                // Model a crash after intent persistence but before native write.
                const auto intentScript=QString("sudo docker exec %1 python3 -c 'import json,pathlib; p=pathlib.Path(\"%2.amnezia-journal\"); j=json.loads(p.read_bytes()); j[\"nativeWriteIntent\"]=True; p.write_text(json.dumps(j))'").arg(name,configPath);
                QCOMPARE(manager.runScript(credentials,intentScript),ErrorCode::NoError);
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
            QString expected;
            QVERIFY(connectionUpdates::removePeerFromServerConfig(misleading,generated.value("client_pub_key").toString(),expected));
            const auto removalBaseline=expected;
            if (qEnvironmentVariable("AMNEZIA_PEER_TRANSACTIONS") == "enabled") {
                const auto name=ContainerUtils::containerToString(container);
                QCOMPARE(ssh.runScript(credentials,QString("sudo docker exec %1 touch /opt/amnezia/revocation-stop").arg(name)),ErrorCode::NoError);
                QVERIFY(users.revokeClient(id,targetRow,container)!=ErrorCode::NoError);
                QJsonObject pending;
                QVERIFY(servers.pendingPeerRevocation(id,container,pending)); QVERIFY(!pending.isEmpty());
                QCOMPARE(pending.value("version").toInt(),2); QCOMPARE(pending.value("phase").toString(),QString("active"));
                QVERIFY(QRegularExpression("^[a-f0-9]{64}$").match(pending.value("receipt").toString()).hasMatch());
                auto wrong=pending; wrong["binding"]=QString(64,'0');
                QVERIFY(servers.compareAndSetPendingPeerRevocation(id,container,pending,wrong));
                QVERIFY(users.resumePendingPeerRevocation(id,container)!=ErrorCode::NoError);
                QJsonObject retained; QVERIFY(servers.pendingPeerRevocation(id,container,retained)); QVERIFY(retained==wrong);
                QVERIFY(servers.compareAndSetPendingPeerRevocation(id,container,wrong,pending));
                // Preserve an independent metadata addition during interruption.
                auto parallel=table; parallel.append(QJsonObject{{"clientId","independent-metadata"},{"userData",QJsonObject{{"clientName","preserve"}}}});
                QCOMPARE(ssh.uploadTextFileToContainer(container,credentials,QString::fromUtf8(QJsonDocument(parallel).toJson()),tablePath),ErrorCode::NoError);
                QCOMPARE(ssh.runScript(credentials,QString("sudo docker exec %1 rm -f /opt/amnezia/revocation-stop /opt/amnezia/revocation-armed /opt/amnezia/revocation-blocked").arg(name)),ErrorCode::NoError);
                // A later native peer edit must survive receipt-based recovery.
                auto changed=expected.split("[Peer]"); QVERIFY(changed.size()>1);
                changed[1].remove(QRegularExpression("(?m)^PersistentKeepalive[^\n]*\n?"));
                changed[1]="\n"+changed[1].trimmed()+"\nPersistentKeepalive = 17\n";
                expected=changed.join("[Peer]");
                bool handled=false;
                QCOMPARE(ssh.replaceLiveProtocolConfig(container,credentials,removalBaseline,expected,handled),ErrorCode::NoError); QVERIFY(handled);
                QCOMPARE(ssh.runScript(credentials,QString("sudo docker exec %1 touch /opt/amnezia/receipt-recovery-deny-writer").arg(name)),ErrorCode::NoError);
                QCOMPARE(ssh.runScript(credentials,QString("touch /tmp/revocation-reply-arm-%1").arg(name)),ErrorCode::NoError);
                QProcess child; auto environment=QProcessEnvironment::systemEnvironment();
                environment.insert("AMNEZIA_TEST_EXPECT_TOKEN_PENDING","1");
                environment.insert("AMNEZIA_TEST_RESUME_REVOCATION",organization);
                environment.insert("AMNEZIA_TEST_REVOCATION_SERVER",id);
                environment.insert("AMNEZIA_TEST_REVOCATION_CONTAINER",QString::number(static_cast<int>(container)));
                child.setProcessEnvironment(environment); child.start(QCoreApplication::applicationFilePath(),{"realAdminNewIPv6ProfileExport"});
                QVERIFY(child.waitForFinished(30000)); QCOMPARE(child.exitStatus(),QProcess::NormalExit); QVERIFY2(child.exitCode()==0,child.readAllStandardOutput().right(6000).constData());
                QString tokenLoss;
                QCOMPARE(ssh.runScript(credentials,QString("cat /tmp/revocation-reply-lost-%1").arg(name),
                    [&](const QString &data,libssh::Client &){tokenLoss+=data;return ErrorCode::NoError;}),ErrorCode::NoError);
                QCOMPARE(tokenLoss,QString("1"));
                updates.refresh(userId); QTRY_COMPARE_WITH_TIMEOUT(finished.count(),3,10000); QVERIFY(!finished[2][0].toBool());
                environment.remove("AMNEZIA_TEST_EXPECT_TOKEN_PENDING"); environment.insert("AMNEZIA_TEST_EXPECT_ACK_PENDING","1");
                child.setProcessEnvironment(environment);
                child.start(QCoreApplication::applicationFilePath(),{"realAdminNewIPv6ProfileExport"});
                QVERIFY(child.waitForFinished(30000)); QCOMPARE(child.exitStatus(),QProcess::NormalExit); QVERIFY2(child.exitCode()==0,child.readAllStandardOutput().right(6000).constData());
                QCOMPARE(ssh.getTextFileFromContainer(container,credentials,"/opt/amnezia/protocol-loss-receipt-ack",readError),QByteArray("1"));
                QCOMPARE(readError,ErrorCode::NoError);
                QCOMPARE(ssh.runScript(credentials,QString("sudo docker exec %1 rm /opt/amnezia/receipt-recovery-deny-writer").arg(name)),ErrorCode::NoError);
                const auto beforeAckEdit=expected;
                expected.replace("PersistentKeepalive = 17","PersistentKeepalive = 23");
                handled=false;
                // Use the exact pre-edit bytes; the receipt itself is gone now.
                QCOMPARE(ssh.replaceLiveProtocolConfig(container,credentials,beforeAckEdit,expected,handled),ErrorCode::NoError); QVERIFY(handled);
                QCOMPARE(ssh.runScript(credentials,QString("sudo docker exec %1 touch /opt/amnezia/receipt-recovery-deny-writer").arg(name)),ErrorCode::NoError);
                environment.remove("AMNEZIA_TEST_EXPECT_ACK_PENDING"); child.setProcessEnvironment(environment);
                child.start(QCoreApplication::applicationFilePath(),{"realAdminNewIPv6ProfileExport"});
                QVERIFY(child.waitForFinished(30000)); QCOMPARE(child.exitStatus(),QProcess::NormalExit); QVERIFY2(child.exitCode()==0,child.readAllStandardOutput().right(6000).constData());
                QString forbidden;
                QCOMPARE(ssh.runScript(credentials,QString("sudo docker exec %1 sh -c 'test ! -e /opt/amnezia/receipt-recovery-forbidden-writer && printf clean'").arg(name),
                    [&](const QString &data,libssh::Client &){forbidden+=data;return ErrorCode::NoError;}),ErrorCode::NoError);
                QCOMPARE(forbidden,QString("clean"));
                QCOMPARE(ssh.runScript(credentials,QString("sudo docker exec %1 rm /opt/amnezia/receipt-recovery-deny-writer").arg(name)),ErrorCode::NoError);
                SecureQSettings refreshedSettings(organization,"test",nullptr,false);
                SecureServersRepository refreshed(&refreshedSettings);
                QVERIFY(refreshed.pendingPeerRevocation(id,container,retained)); QVERIFY(retained.isEmpty());
                const auto saved=QJsonDocument::fromJson(ssh.getTextFileFromContainer(container,credentials,tablePath,readError)).array();
                QCOMPARE(readError,ErrorCode::NoError); QCOMPARE(saved.size(),1);
                QVERIFY(saved.first()==parallel.last());
            } else {
                QCOMPARE(users.revokeClient(id,targetRow,container),ErrorCode::NoError);
            }
            if (qEnvironmentVariable("AMNEZIA_PEER_TRANSACTIONS") == "enabled") {
                SshSession proof; ErrorCode observedTable=ErrorCode::NoError;
                QCOMPARE(proof.getTextFileFromContainer(container,credentials,"/opt/amnezia/protocol-loss-client-table",observedTable),QByteArray("1"));
                QCOMPARE(observedTable,ErrorCode::NoError);
            }
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
            if (actual!=removalBaseline) {
                bool handled=false;
                QCOMPARE(ssh.replaceLiveProtocolConfig(container,credentials,actual,removalBaseline,handled),ErrorCode::NoError); QVERIFY(handled);
            }
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
