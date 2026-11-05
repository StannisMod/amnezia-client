#include "connectionUpdatesController.h"

#include <QDateTime>
#include <QFile>
#include <QFutureWatcher>
#include <QJsonDocument>
#include <QJsonArray>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QSslConfiguration>
#include <QTimer>
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
struct AdminResult { ErrorCode error = ErrorCode::InternalError; QJsonObject metadata; };
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
    if (action != "issue" && action != "publish" && action != "revoke" && action != "info") return ErrorCode::InternalError;
    SshSession ssh;
    const auto path = "/tmp/amnezia-update-request-" + QUuid::createUuid().toString(QUuid::Id128);
    auto error = ssh.runScript(credentials, "umask 077 && mkdir '" + path + "'");
    if (error != ErrorCode::NoError) return error;
    error = ssh.uploadFileToHost(credentials, QJsonDocument(request).toJson(QJsonDocument::Compact), path + "/request.json");
    if (error != ErrorCode::NoError) {
        ssh.runScript(credentials, "rm -rf -- '" + path + "'"); return error;
    }
    QString output;
    const auto script = QString("chmod 600 '%3/request.json' && %1 && sudo docker run --rm -i --network none --read-only --cap-drop ALL --security-opt no-new-privileges --mount type=volume,source=amnezia-connection-updates-state,target=/data amnezia-connection-updates:1 %2 < '%3/request.json'").arg(labelCheck, action, path);
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
    const auto host = vpnEndpoint::normalizeHost(admin->vpnHostName.isEmpty() ? admin->hostName : admin->vpnHostName);
    if (host.isEmpty()) { emit finished(false, tr("Set a valid VPN server address first.")); return; }
    setBusy(true);
    auto *watcher = new QFutureWatcher<AdminResult>(this);
    connect(watcher, &QFutureWatcher<AdminResult>::finished, this, [this, watcher, id, action, original] {
        const auto result = watcher->result(); watcher->deleteLater(); setBusy(false);
        if (result.error != ErrorCode::NoError) { emit finished(false, tr("Connection update operation failed. The existing VPN profile was kept.")); return; }
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
    watcher->setFuture(QtConcurrent::run(&m_adminPool, [admin, action, container, host, clientKey] {
        AdminResult result; SshSession ssh; const auto credentials = admin->credentials();
        if (action == "install") {
            const auto dir = "/tmp/amnezia-connection-updates-" + QUuid::createUuid().toString(QUuid::Id128);
            auto error = ssh.runScript(credentials, "umask 077 && mkdir '" + dir + "'");
            if (error != ErrorCode::NoError) { result.error = error; return result; }
            for (const auto &name : { "Dockerfile", "service.go", "go.mod", "install.sh" }) {
                const auto data = resource(name);
                if (data.isEmpty()) { error = ErrorCode::InternalError; break; }
                error = ssh.uploadFileToHost(credentials, data, dir + "/" + name);
                if (error != ErrorCode::NoError) break;
            }
            QString output;
            if (error == ErrorCode::NoError) error = ssh.runScript(credentials, QString("sudo sh '%1/install.sh' '%1' '%2'").arg(dir, host),
                [&](const QString &data, libssh::Client &) { output += data; return ErrorCode::NoError; });
            ssh.runScript(credentials, "rm -rf -- '" + dir + "'");
            if (error != ErrorCode::NoError) { result.error = error; return result; }
            result.metadata = QJsonDocument::fromJson(output.toUtf8()).object();
            if (result.metadata.value("version").toInt() != 1 || result.metadata.value("host").toString() != host || QSslCertificate(QByteArray::fromBase64(result.metadata.value("certificate").toString().toLatin1()), QSsl::Der).isNull()
                || QByteArray::fromBase64(result.metadata.value("publicKey").toString().toLatin1()).size() != 32) return result;
            QUrl url; url.setScheme("https"); url.setHost(host); url.setPort(8443);
            result.metadata["url"] = url.toString();
            result.error = flushPendingRevocations(credentials, admin->connectionUpdates);
            return result;
        }
        result.error = flushPendingRevocations(credentials, admin->connectionUpdates);
        if (result.error != ErrorCode::NoError) return result;
        QJsonObject request { { "container", ContainerUtils::containerToString(container) } };
        if (action == "revoke") request["clientPublicKey"] = clientKey;
        else {
            // Read effective public settings, rather than publishing stale cache.
            const bool awg = container == DockerContainer::Awg2; QString output;
            const auto binary = awg ? "awg" : "wg"; const auto iface = awg ? "awg0" : "wg0";
            const auto error = ssh.runScript(credentials, QString("sudo docker exec %1 %2 show %3 public-key && sudo docker exec %1 %2 show %3 listen-port").arg(ContainerUtils::containerToString(container), binary, iface),
                [&](const QString &data, libssh::Client &) { output += data; return ErrorCode::NoError; });
            if (error != ErrorCode::NoError) { result.error = error; return result; }
            const auto lines = output.trimmed().split('\n', Qt::SkipEmptyParts);
            if (lines.size() != 2) return result;
            QJsonObject settings { { "hostName", host }, { "server_pub_key", lines[0].trimmed() }, { "port", lines[1].trimmed().toInt() } };
            if (awg) {
                QString live;
                const auto pattern = configKey::awgProtocolKeys().join('|');
                const auto read = ssh.runScript(credentials,
                    QString("sudo docker exec %1 awg showconf awg0 | awk '/^\\[Peer\\]/{exit} /^[ \t]*(%2)[ \t]*=/{print}'").arg(ContainerUtils::containerToString(container), pattern),
                    [&](const QString &data, libssh::Client &) { live += data; return ErrorCode::NoError; });
                if (read != ErrorCode::NoError) { result.error = read; return result; }
                for (const auto &line : live.split('\n', Qt::SkipEmptyParts)) {
                    const auto at = line.indexOf('=');
                    if (at <= 0) return result;
                    const auto key = line.left(at).trimmed();
                    if (!configKey::awgProtocolKeys().contains(key)) return result;
                    settings[key] = line.mid(at + 1).trimmed();
                }
                if (!settings.contains("H1")) return result;
            }
            request["settings"] = settings;
        }
        result.error = command(credentials, action, request, result.metadata); return result;
    }));
}
void ConnectionUpdatesController::refresh(const QString &id) { fetch(id, true); }
void ConnectionUpdatesController::refreshBeforeConnect(const QString &id, const std::function<void()> &done)
{
    if (!available(id)) { done(); return; }
    fetch(id, false, done);
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
    setBusy(true); auto *reply = m_network.get(request); reply->setReadBufferSize(65537);
    const auto pinned = QByteArray::fromBase64(m.value("certificate").toString().toLatin1());
    connect(reply, &QNetworkReply::encrypted, reply, [reply, pinned] {
        if (reply->sslConfiguration().peerCertificate().toDer() != pinned) reply->abort();
    });
    connect(reply, &QNetworkReply::readyRead, reply, [reply] { if (reply->bytesAvailable() > 65536) reply->abort(); });
    QTimer::singleShot(10000, reply, [reply] { if (reply->isRunning()) reply->abort(); });
    connect(reply, &QNetworkReply::finished, this, [this, reply, id, original, report, done = std::move(done)] {
        const auto body = reply->readAll(); QJsonObject updated;
        const bool success = reply->error() == QNetworkReply::NoError && reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt() == 200
            && reply->sslConfiguration().peerCertificate().toDer() == QByteArray::fromBase64(original.value(connectionUpdates::metadataKey).toObject().value("certificate").toString().toLatin1())
            && m_connection->isDisconnected() && m_servers->serverJsonById(id) == std::optional<QJsonObject>(original)
            && connectionUpdates::apply(original, body, QDateTime::currentSecsSinceEpoch(), updated);
        reply->deleteLater(); setBusy(false);
        if (success) m_servers->editServer(id, updated, serverConfigUtils::SelfHostedUser);
        if (report) emit finished(success, success ? tr("Connection updated. Your device key and local routing settings were kept.")
                                                 : tr("Could not verify the connection update. The existing profile was kept."));
        if (done) done();
    });
}
