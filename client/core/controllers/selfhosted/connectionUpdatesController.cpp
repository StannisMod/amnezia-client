#include "connectionUpdatesController.h"
#include "core/utils/selfhosted/connectionUpdatesCommand.h"

#include <QDateTime>
#include <QElapsedTimer>
#include <QFile>
#include <QFutureWatcher>
#include <QJsonDocument>
#include <QJsonArray>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QSslConfiguration>
#include <QTimer>
#include <QRegularExpression>
#include <QUuid>
#include <QtConcurrent>

#include "core/controllers/connectionController.h"
#include "core/utils/connectionUpdates.h"
#include "core/utils/selfhosted/sshSession.h"
#include "core/utils/vpnEndpoint.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/constants/protocolConstants.h"

using namespace amnezia;
namespace {
constexpr auto labelCheck = "test \"$(sudo docker inspect -f '{{index .Config.Labels \"org.amnezia.connection-updates\"}}' amnezia-connection-updates)\" = 1";
QByteArray resource(const QString &name) { QFile f(":/server_scripts/connection_updates/" + name); if (!f.open(QIODevice::ReadOnly)) return {}; return f.readAll().replace("\r\n", "\n"); }
struct AdminResult { ErrorCode error = ErrorCode::InternalError; QJsonObject metadata; QString outcome; QString reason; };
ErrorCode flushPendingRevocations(const ServerCredentials &credentials, const QJsonObject &metadata)
{
    for (const auto &entry : metadata.value("pendingRevocations").toArray()) {
        QJsonObject response;
        const auto error = ConnectionUpdatesController::command(credentials, "revoke", entry.toObject(), response);
        if (error != ErrorCode::NoError) return error;
    }
    return ErrorCode::NoError;
}

}
ConnectionUpdatesController::ConnectionUpdatesController(SecureServersRepository *servers, ConnectionController *connection, QObject *parent)
    : QObject(parent), m_servers(servers), m_connection(connection)
{
    m_adminPool.setMaxThreadCount(1);
    connect(servers, &SecureServersRepository::serverAdded, this, &ConnectionUpdatesController::configurationChanged);
    connect(servers, &SecureServersRepository::serverEdited, this, &ConnectionUpdatesController::configurationChanged);
    connect(servers, &SecureServersRepository::serverRemoved, this, &ConnectionUpdatesController::configurationChanged);
}
ConnectionUpdatesController::~ConnectionUpdatesController() { m_adminPool.waitForDone(); }
void ConnectionUpdatesController::setBusy(bool busy) { m_busy = busy; emit busyChanged(); }
QStringList ConnectionUpdatesController::enabledServers() const
{
    QStringList ids;
    for (const auto &id : m_servers->orderedServerIds()) if (enabled(id)) ids << id;
    return ids;
}
QStringList ConnectionUpdatesController::updatableServers() const
{
    QStringList ids;
    for (const auto &id : m_servers->orderedServerIds()) if (available(id)) ids << id;
    return ids;
}
QStringList ConnectionUpdatesController::protectionServers() const
{
    QStringList ids;
    for (const auto &id : m_servers->orderedServerIds()) if (canEnableHeaderProtection(id, static_cast<int>(DockerContainer::Awg2))) ids << id;
    return ids;
}
bool ConnectionUpdatesController::canEnableHeaderProtection(const QString &id, int index) const
{
    if (static_cast<DockerContainer>(index) != DockerContainer::Awg2 || !enabled(id)) return false;
    const auto admin = m_servers->selfHostedAdminConfig(id);
    if (!admin || !admin->containers.contains(DockerContainer::Awg2)) return false;
    const auto cc = admin->containerConfig(DockerContainer::Awg2);
    const auto *awg = cc.getAwgProtocolConfig();
    return awg && awg->serverConfig.headerProtectionKey.isEmpty();
}
void ConnectionUpdatesController::enableHeaderProtection(const QString &id, int container) { administer(id, "activate-awg3", container); }
ErrorCode ConnectionUpdatesController::fetchPathMtuProbeAddress(const ServerCredentials &credentials, DockerContainer container, QString &address)
{
    if (container != DockerContainer::WireGuard && container != DockerContainer::Awg2) return ErrorCode::InternalError;
    const auto name = ContainerUtils::containerToString(container);
    const QString iface = container == DockerContainer::Awg2 ? "awg0" : "wg0";
    SshSession ssh; QString output;
    const auto error = ssh.runScript(credentials, QString("sudo docker exec %1 ip -o addr show dev %2 scope global && printf '\\namnezia_interface_addresses=ok\\n'").arg(name, iface),
        [&](const QString &data, libssh::Client &) { if (output.size() + data.size() > 65536) return ErrorCode::InternalError; output += data; return ErrorCode::NoError; });
    if (error != ErrorCode::NoError) return error;
    return connectionUpdates::parsePathProbeAddress(output, iface, address) ? ErrorCode::NoError : ErrorCode::InternalError;
}
ErrorCode ConnectionUpdatesController::fetchPublicSettings(const ServerCredentials &credentials, DockerContainer container,
                                                           const QString &host, QJsonObject &settings, QStringList *peers, QString *pathMtuProbe)
{
    if (container != DockerContainer::WireGuard && container != DockerContainer::Awg2) return ErrorCode::InternalError;
    SshSession ssh;
    const bool awg = container == DockerContainer::Awg2;
    const QString binary = awg ? "awg" : "wg", iface = awg ? "awg0" : "wg0";
    const auto name = ContainerUtils::containerToString(container);
    QString output;
    auto error = ssh.runScript(credentials, QString("sudo docker exec %1 %2 show %3 public-key && sudo docker exec %1 %2 show %3 listen-port").arg(name, binary, iface),
        [&](const QString &data, libssh::Client &) { output += data; return ErrorCode::NoError; });
    if (error != ErrorCode::NoError) return error;
    const auto lines = output.trimmed().split('\n', Qt::SkipEmptyParts);
    if (lines.size() != 2) return ErrorCode::InternalError;
    QJsonObject candidate { { "hostName", host }, { "server_pub_key", lines[0].trimmed() }, { "port", lines[1].trimmed().toInt() } };
    if (awg) {
        QString live;
        const auto pattern = configKey::awgProtocolKeys().join('|');
        error = ssh.runScript(credentials, QString("sudo docker exec %1 awg showconf awg0 | awk '/^\\[Peer\\]/{exit} /^[ \t]*(%2)[ \t]*=/{print}'").arg(name, pattern),
            [&](const QString &data, libssh::Client &) { live += data; return ErrorCode::NoError; });
        if (error != ErrorCode::NoError) return error;
        for (const auto &line : live.split('\n', Qt::SkipEmptyParts)) {
            const auto at = line.indexOf('='); if (at <= 0) return ErrorCode::InternalError;
            const auto key = line.left(at).trimmed(); if (!configKey::awgProtocolKeys().contains(key)) return ErrorCode::InternalError;
            candidate[key] = line.mid(at + 1).trimmed();
        }
        if (!candidate.contains("H1")) return ErrorCode::InternalError;
    }
    if (peers) {
        output.clear();
        error = ssh.runScript(credentials, QString("sudo docker exec %1 %2 show %3 peers && printf '\\namnezia_peers=ok\\n'").arg(name, binary, iface),
            [&](const QString &data, libssh::Client &) { output += data; return ErrorCode::NoError; });
        if (error != ErrorCode::NoError) return error;
        if (!connectionUpdates::parsePeerList(output, *peers)) return ErrorCode::InternalError;
    }
    QString probe;
    if (pathMtuProbe) {
        error = fetchPathMtuProbeAddress(credentials, container, probe);
        if (error != ErrorCode::NoError) return error;
    }
    settings = candidate;
    if (pathMtuProbe) *pathMtuProbe = probe;
    return ErrorCode::NoError;
}
bool ConnectionUpdatesController::available(const QString &id) const
{
    const auto p = m_servers->serverJsonById(id);
    return p && m_servers->serverKind(id) == serverConfigUtils::SelfHostedUser && connectionUpdates::validateProfile(*p);
}
bool ConnectionUpdatesController::enabled(const QString &id) const
{
    const auto admin = m_servers->selfHostedAdminConfig(id);
    return admin && admin->connectionUpdates.value("version").toInt() == 1;
}
ErrorCode ConnectionUpdatesController::command(const ServerCredentials &credentials, const QString &action, const QJsonObject &request, QJsonObject &response)
{
    if (action != "issue" && action != "publish" && action != "publish-live" && action != "revoke" && action != "info") return ErrorCode::InternalError;
    SshSession ssh;
    const auto path = "/tmp/amnezia-update-request-" + QUuid::createUuid().toString(QUuid::Id128);
    auto error = ssh.runScript(credentials, "umask 077 && mkdir '" + path + "'");
    if (error != ErrorCode::NoError) return error;
    error = ssh.uploadFileToHost(credentials, QJsonDocument(request).toJson(QJsonDocument::Compact), path + "/request.json");
    if (error != ErrorCode::NoError) {
        ssh.runScript(credentials, "rm -rf -- '" + path + "'"); return error;
    }
    QString output;
    const auto script = connectionUpdates::adminCommandScript(action, path);
    error = ssh.runScript(credentials, script, [&](const QString &data, libssh::Client &) { output += data; return ErrorCode::NoError; });
    ssh.runScript(credentials, "rm -rf -- '" + path + "'");
    if (error != ErrorCode::NoError) return error;
    const auto result = QJsonDocument::fromJson(output.toUtf8()).object();
    if (result.value("version").toInt() != 1 || (action != "info" && !result.value("ok").toBool())) return ErrorCode::InternalError;
    response = result; return ErrorCode::NoError;
}
void ConnectionUpdatesController::install(const QString &id) { administer(id, "install"); }
void ConnectionUpdatesController::publish(const QString &id, int container) { administer(id, "publish", container); }
void ConnectionUpdatesController::revoke(const QString &id, int container, const QString &key) { administer(id, "revoke", container, key); }
void ConnectionUpdatesController::administer(const QString &id, const QString &action, int containerIndex, const QString &clientKey)
{
    if (m_busy || !m_connection->isDisconnected()) { emit finished(false, tr("Disconnect the VPN before managing connection updates.")); return; }
    const auto admin = m_servers->selfHostedAdminConfig(id); const auto original = m_servers->serverJsonById(id);
    if (!admin || !original || !admin->credentials().isValid()) { emit finished(false, tr("Server access is unavailable.")); return; }
    const auto container = static_cast<DockerContainer>(containerIndex);
    if (action != "install" && (!enabled(id) || !admin->containers.contains(container)
        || (container != DockerContainer::WireGuard && container != DockerContainer::Awg2))) {
        emit finished(false, tr("Connection updates support WireGuard and AWG 2/3 profiles.")); return;
    }
    if (action == "activate-awg3" && container != DockerContainer::Awg2) { emit finished(false, tr("Header protection requires an AWG 2/3 container.")); return; }
    const auto host = vpnEndpoint::normalizeHost(admin->vpnHostName.isEmpty() ? admin->hostName : admin->vpnHostName);
    if (host.isEmpty()) { emit finished(false, tr("Set a valid VPN server address first.")); return; }
    const auto previousUpdateHost = vpnEndpoint::normalizeHost(QUrl(admin->connectionUpdates.value("url").toString()).host());
    const auto updateHost = previousUpdateHost.isEmpty() ? host : previousUpdateHost;
    setBusy(true);
    auto *watcher = new QFutureWatcher<AdminResult>(this);
    connect(watcher, &QFutureWatcher<AdminResult>::finished, this, [this, watcher, id, action, original] {
        const auto result = watcher->result(); watcher->deleteLater(); setBusy(false);
        if (result.error != ErrorCode::NoError) { emit finished(false, tr("Connection update operation failed. The existing VPN profile was kept.")); return; }
        if (result.outcome == "upgrade_required") {
            emit finished(false, tr("Run Set up connection updates again to upgrade the delivery service without changing issued tokens.")); return;
        }
        if (action == "activate-awg3") {
            if (result.outcome != "applied") {
                QString message;
                if (result.outcome == "rolled_back") message = tr("Header protection was not enabled. The previous VPN settings were restored and republished.");
                else if (result.outcome == "rollback_failed") message = tr("Header protection failed and automatic recovery is incomplete. Check the server over SSH before retrying.");
                else if (result.outcome == "unknown") message = tr("The SSH connection ended without a confirmed result. Check the server before retrying.");
                else if (result.reason == "clients_not_ready") message = tr("Some users have not confirmed the current settings and AWG 3 support. Ask every user to update their connection from the compatible app before retrying.");
                else if (result.reason == "configuration_changed") message = tr("The VPN configuration changed while preparing protection. Retry after other server edits finish.");
                else if (result.reason == "delivery_identity_changed") message = tr("The delivery service identity changed. Check its restored keys before enabling protection.");
                else if (result.reason == "clients_without_updates") message = tr("Some VPN users have no active update token. Share connection updates with every user before enabling header protection.");
                else if (result.reason == "delivery_service_upgrade_required") message = tr("Run Set up connection updates again to upgrade the delivery service without changing issued tokens.");
                else message = tr("The server does not meet the header protection requirements. Upgrade the protocol software first and check for unsaved configuration changes.");
                emit finished(false, message); return;
            }
            QJsonObject updated;
            if (!m_connection->isDisconnected() || m_servers->serverJsonById(id) != original
                || !connectionUpdates::mergeServerSettings(*original, "amnezia-awg2", result.metadata, true, updated)) {
                emit finished(false, tr("The server switched successfully, but the local profile changed during the operation. Retry to synchronize its settings without replacing the device key.")); return;
            }
            auto metadata = updated.value(connectionUpdates::metadataKey).toObject(); metadata.remove("pendingRevocations"); updated[connectionUpdates::metadataKey] = metadata;
            m_servers->editServer(id, updated, serverConfigUtils::SelfHostedAdmin);
            emit finished(true, tr("AWG 3 header protection enabled. Users must reconnect from the app to receive the signed settings.")); return;
        }
        if (action == "install") {
            if (m_servers->serverJsonById(id) != original) { emit finished(false, tr("The profile changed during installation. Run setup again to load the server keys.")); return; }
            auto profile = *original; profile[connectionUpdates::metadataKey] = result.metadata;
            m_servers->editServer(id, profile, serverConfigUtils::SelfHostedAdmin);
        } else if (m_servers->serverJsonById(id) == original) {
            auto profile = *original;
            auto metadata = profile.value(connectionUpdates::metadataKey).toObject();
            metadata.remove("pendingRevocations");
            profile[connectionUpdates::metadataKey] = metadata;
            m_servers->editServer(id, profile, serverConfigUtils::SelfHostedAdmin);
        }
        emit finished(true, action == "install" ? tr("Connection updates enabled on TCP port 8443. Allow this port in your VPS firewall.")
                                               : action == "publish" ? tr("Connection settings published.") : tr("Update token revoked. Use Revoke access to also disable the VPN peer."));
    });
    watcher->setFuture(QtConcurrent::run(&m_adminPool, [admin, action, container, host, updateHost, clientKey] {
        AdminResult result; SshSession ssh; const auto credentials = admin->credentials();
        if (action == "install") {
            const auto dir = "/tmp/amnezia-connection-updates-" + QUuid::createUuid().toString(QUuid::Id128);
            auto error = ssh.runScript(credentials, "umask 077 && mkdir '" + dir + "'");
            if (error != ErrorCode::NoError) { result.error = error; return result; }
            for (const auto &name : { "Dockerfile", "service.go", "rollout.go", "readiness.go", "go.mod", "install.sh" }) {
                const auto data = resource(name);
                if (data.isEmpty()) { error = ErrorCode::InternalError; break; }
                error = ssh.uploadFileToHost(credentials, data, dir + "/" + name);
                if (error != ErrorCode::NoError) break;
            }
            QString output;
            if (error == ErrorCode::NoError) error = ssh.runScript(credentials, QString("sudo sh '%1/install.sh' '%1' '%2'").arg(dir, updateHost),
                [&](const QString &data, libssh::Client &) { output += data; return ErrorCode::NoError; });
            ssh.runScript(credentials, "rm -rf -- '" + dir + "'");
            if (error != ErrorCode::NoError) { result.error = error; return result; }
            result.metadata = QJsonDocument::fromJson(output.toUtf8()).object();
            if (result.metadata.value("version").toInt() != 1 || result.metadata.value("host").toString() != updateHost || QSslCertificate(QByteArray::fromBase64(result.metadata.value("certificate").toString().toLatin1()), QSsl::Der).isNull()
                || QByteArray::fromBase64(result.metadata.value("publicKey").toString().toLatin1()).size() != 32) return result;
            QUrl url; url.setScheme("https"); url.setHost(updateHost); url.setPort(8443);
            result.metadata["url"] = url.toString();
            result.error = flushPendingRevocations(credentials, admin->connectionUpdates);
            return result;
        }
        result.error = flushPendingRevocations(credentials, admin->connectionUpdates);
        if (result.error != ErrorCode::NoError) return result;
        if (action == "publish") {
            QJsonObject info; result.error = command(credentials, "info", {}, info);
            if (result.error != ErrorCode::NoError) return result;
            if (info.value("publicKey") != admin->connectionUpdates.value("publicKey") || info.value("certificate") != admin->connectionUpdates.value("certificate")) {
                result.error = ErrorCode::InternalError; return result;
            }
            if (!info.value("features").toArray().contains("live-publication-v1")) {
                result.outcome = "upgrade_required"; return result;
            }
        }
        if (action == "activate-awg3") {
            result.error = ErrorCode::NoError; result.outcome = "rejected";
            QJsonObject info;
            const auto infoError = command(credentials, "info", {}, info);
            if (infoError != ErrorCode::NoError) { result.error = infoError; return result; }
            if (!info.value("features").toArray().contains("awg3-header-protection-v1")
                || !info.value("features").toArray().contains("rollout-readiness-v1")
                || !info.value("features").toArray().contains("live-publication-v1")) {
                result.reason = "delivery_service_upgrade_required"; return result;
            }
            const auto client = admin->containerConfig(container).protocolConfig.getClientConfigJson();
            QString clientPublicKey;
            if (!client.isEmpty()) {
                if (!connectionUpdates::clientIdentityMatches(client)) { result.reason = "invalid_cached_identity"; return result; }
                clientPublicKey = client.value(configKey::clientPubKey).toString();
            }
            const QJsonObject request { { "host", host }, { "adminPublicKey", clientPublicKey },
                { "expectedPublicKey", admin->connectionUpdates.value("publicKey") }, { "expectedCertificate", admin->connectionUpdates.value("certificate") } };
            const auto stage = "/tmp/amnezia-protection-" + QUuid::createUuid().toString(QUuid::Id128);
            auto error = ssh.runScript(credentials, "umask 077 && mkdir '" + stage + "'");
            if (error != ErrorCode::NoError) return result;
            error = ssh.uploadFileToHost(credentials, QJsonDocument(request).toJson(QJsonDocument::Compact), stage + "/request.json");
            QString output;
            if (error == ErrorCode::NoError) {
                result.outcome = "unknown";
                error = ssh.runScript(credentials, QString("chmod 600 '%1/request.json' && %2 && sudo docker cp amnezia-connection-updates:/updates '%1/updates' && sudo chmod 700 '%1/updates' && sudo '%1/updates' activate-awg3 < '%1/request.json'").arg(stage, labelCheck),
                    [&](const QString &data, libssh::Client &) { output += data; return ErrorCode::NoError; });
            }
            ssh.runScript(credentials, "rm -rf -- '" + stage + "'");
            const auto response = QJsonDocument::fromJson(output.toUtf8()).object();
            const auto outcome = response.value("result").toString();
            if (response.value("version").toInt() == 1 && QStringList { "applied", "rejected", "rolled_back", "rollback_failed" }.contains(outcome)) {
                result.outcome = outcome; result.reason = response.value("reason").toString(); result.metadata = response.value("settings").toObject();
            }
            return result;
        }
        QJsonObject request { { "container", ContainerUtils::containerToString(container) } };
        if (action == "revoke") request["clientPublicKey"] = clientKey;
        else {
            QJsonObject settings; QStringList peers; QString probe;
            result.error = fetchPublicSettings(credentials, container, host, settings, &peers, &probe);
            if (result.error != ErrorCode::NoError) return result;
            request["settings"] = settings;
            request["pathMtuProbe"] = probe;
            request["clientPublicKeys"] = QJsonArray::fromStringList(peers);
        }
        const auto remoteAction = action == "publish" ? QString("publish-live") : action;
        result.error = command(credentials, remoteAction, request, result.metadata); return result;
    }));
}
void ConnectionUpdatesController::refresh(const QString &id) { fetch(id, true); }
bool ConnectionUpdatesController::needsRefreshBeforeConnect(const QString &id) const
{
    if (available(id)) return true;
    const auto admin = m_servers->selfHostedAdminConfig(id);
    if (!admin || !admin->credentials().isValid()
        || (admin->defaultContainer != DockerContainer::WireGuard && admin->defaultContainer != DockerContainer::Awg2)) return false;
    const auto cached = admin->containerConfig(admin->defaultContainer).protocolConfig.getClientConfigJson();
    return !cached.isEmpty() && cached.value("path_mtu_probe").toString().isEmpty();
}
void ConnectionUpdatesController::refreshBeforeConnect(const QString &id, const std::function<void()> &done)
{
    if (available(id)) { fetch(id, false, done); return; }
    const auto admin = m_servers->selfHostedAdminConfig(id); const auto original = m_servers->serverJsonById(id);
    if (m_busy || !m_connection->isDisconnected() || !admin || !original || !admin->credentials().isValid()
        || (admin->defaultContainer != DockerContainer::WireGuard && admin->defaultContainer != DockerContainer::Awg2)) { done(); return; }
    const auto container = admin->defaultContainer;
    const auto cached = admin->containerConfig(container).protocolConfig.getClientConfigJson();
    if (cached.isEmpty() || !cached.value("path_mtu_probe").toString().isEmpty()) { done(); return; }
    setBusy(true); auto *watcher = new QFutureWatcher<AdminResult>(this);
    connect(watcher, &QFutureWatcher<AdminResult>::finished, this, [this, watcher, id, original, container, done] {
        const auto result = watcher->result(); watcher->deleteLater(); setBusy(false);
        QJsonObject updated;
        if (result.error == ErrorCode::NoError && m_connection->isDisconnected() && m_servers->serverJsonById(id) == original
            && connectionUpdates::mergePathProbe(*original, ContainerUtils::containerToString(container), result.metadata.value("pathMtuProbe"), updated)) {
            m_servers->editServer(id, updated, serverConfigUtils::SelfHostedAdmin);
        }
        done();
    });
    watcher->setFuture(QtConcurrent::run(&m_adminPool, [credentials = admin->credentials(), container] {
        AdminResult result; QString target;
        result.error = fetchPathMtuProbeAddress(credentials, container, target);
        if (result.error == ErrorCode::NoError) result.metadata["pathMtuProbe"] = target;
        return result;
    }));
}
void ConnectionUpdatesController::fetch(const QString &id, bool report, std::function<void()> done)
{
    if (m_busy || !m_connection->isDisconnected() || !available(id)) {
        if (report) emit finished(false, tr("Disconnect the VPN before updating this connection."));
        if (done) done(); return;
    }
    const auto original = *m_servers->serverJsonById(id); const auto m = original.value(connectionUpdates::metadataKey).toObject();
    QNetworkRequest request(QUrl(m.value("url").toString()));
    auto ssl = QSslConfiguration::defaultConfiguration();
    ssl.setCaCertificates({ QSslCertificate(QByteArray::fromBase64(m.value("certificate").toString().toLatin1()), QSsl::Der) });
    ssl.setPeerVerifyMode(QSslSocket::VerifyPeer); request.setSslConfiguration(ssl);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    request.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    request.setAttribute(QNetworkRequest::CookieLoadControlAttribute, QNetworkRequest::Manual);
    request.setAttribute(QNetworkRequest::CookieSaveControlAttribute, QNetworkRequest::Manual);
    request.setTransferTimeout(10000);
    request.setRawHeader("Authorization", "Bearer " + m.value("token").toString().toLatin1());
    request.setRawHeader("Connection", "close");
    request.setAttribute(QNetworkRequest::Http2AllowedAttribute, false);
    m_network.clearConnectionCache();
    QElapsedTimer elapsed; elapsed.start();
    setBusy(true); auto *reply = m_network.get(request); reply->setReadBufferSize(65537);
    const auto pinned = QByteArray::fromBase64(m.value("certificate").toString().toLatin1());
    connect(reply, &QNetworkReply::encrypted, reply, [reply, pinned] {
        if (reply->sslConfiguration().peerCertificate().toDer() != pinned) reply->abort();
    });
    connect(reply, &QNetworkReply::readyRead, reply, [reply] { if (reply->bytesAvailable() > 65536) reply->abort(); });
    QTimer::singleShot(10000, reply, [reply] { if (reply->isRunning()) reply->abort(); });
    connect(reply, &QNetworkReply::finished, this, [this, reply, id, original, report, request, elapsed, done = std::move(done)] {
        const auto body = reply->readAll(); QJsonObject updated;
        const bool success = reply->error() == QNetworkReply::NoError && reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt() == 200
            && reply->sslConfiguration().peerCertificate().toDer() == QByteArray::fromBase64(original.value(connectionUpdates::metadataKey).toObject().value("certificate").toString().toLatin1())
            && m_connection->isDisconnected() && m_servers->serverJsonById(id) == std::optional<QJsonObject>(original)
            && connectionUpdates::apply(original, body, QDateTime::currentSecsSinceEpoch(), updated);
        const bool needsAcknowledgement = success && reply->rawHeader("X-Amnezia-Update-Features").split(',').contains("ack-v1");
        reply->deleteLater();
        if (success) m_servers->editServer(id, updated, serverConfigUtils::SelfHostedUser);
        const auto complete = [this, report, success, done](bool required, bool acknowledged) {
            setBusy(false);
            if (report) emit finished(success, !success ? tr("Could not verify the connection update. The existing profile was kept.")
                : required && !acknowledged ? tr("Connection updated, but readiness was not confirmed. Refresh again before the server enables AWG 3 protection.")
                : tr("Connection updated. Your device key and local routing settings were kept."));
            if (done) done();
        };
        if (!needsAcknowledgement) { complete(false, false); return; }
        const int remaining = static_cast<int>(qMax<qint64>(0, 10000 - elapsed.elapsed()));
        if (remaining == 0) { complete(true, false); return; }
        auto acknowledgement = request;
        auto url = acknowledgement.url(); url.setPath(url.path() + "/ack"); acknowledgement.setUrl(url);
        acknowledgement.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
        const int timeout = qMin(remaining, 3000); acknowledgement.setTransferTimeout(timeout);
        const auto proof = connectionUpdates::readinessProof(original, body, QDateTime::currentSecsSinceEpoch());
        if (proof.isEmpty()) { complete(true, false); return; }
        const auto envelope = QJsonDocument::fromJson(body).object();
        const QJsonObject receipt { { "payload", envelope.value("payload") }, { "signature", envelope.value("signature") },
            { "features", QJsonArray { "awg3-header-protection-v1" } }, { "proof", QString::fromLatin1(proof.toBase64()) } };
        m_network.clearConnectionCache();
        auto *ack = m_network.post(acknowledgement, QJsonDocument(receipt).toJson(QJsonDocument::Compact));
        ack->setReadBufferSize(4097);
        const auto pinned = QByteArray::fromBase64(original.value(connectionUpdates::metadataKey).toObject().value("certificate").toString().toLatin1());
        connect(ack, &QNetworkReply::encrypted, ack, [ack, pinned] { if (ack->sslConfiguration().peerCertificate().toDer() != pinned) ack->abort(); });
        connect(ack, &QNetworkReply::readyRead, ack, [ack] { if (ack->bytesAvailable() > 4096) ack->abort(); });
        QTimer::singleShot(timeout, ack, [ack] { if (ack->isRunning()) ack->abort(); });
        connect(ack, &QNetworkReply::finished, this, [ack, pinned, complete] {
            const bool acknowledged = ack->error() == QNetworkReply::NoError && ack->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt() == 204
                && ack->sslConfiguration().peerCertificate().toDer() == pinned;
            ack->deleteLater(); complete(true, acknowledged);
        });
    });
}
