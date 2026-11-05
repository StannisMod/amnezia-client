#include "serverMigrationController.h"
#include "core/controllers/connectionController.h"
#include "core/utils/selfhosted/pinnedSshSession.h"
#include "core/utils/vpnEndpoint.h"
#include <QBuffer>
#include <QCryptographicHash>
#include <QFile>
#include <QFutureWatcher>
#include <QHostInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QTemporaryFile>
#include <QUuid>
#include <QtConcurrent>
#include <stdexcept>

using namespace amnezia;
namespace {
const QString storage = "Conf/serverMigration";
QString quote(QString s) { return "'" + s.replace("'", "'\\''") + "'"; }
void check(const QString &error) { if (!error.isEmpty()) throw std::runtime_error(error.toStdString()); }
QJsonObject identity(const SshIdentity &i) { return {{"address", i.address}, {"fingerprint", i.fingerprint}, {"algorithm", i.algorithm}}; }
SshIdentity identity(const QJsonObject &j) { return {j["address"].toString(), j["fingerprint"].toString(), j["algorithm"].toString(), {}}; }
ServerCredentials credentials(const QJsonObject &j) { return {j["host"].toString(), j["user"].toString(), j["secret"].toString(), j["port"].toInt()}; }
QJsonObject credentials(const ServerCredentials &c) { return {{"host", c.hostName}, {"port", c.port}, {"user", c.userName}, {"secret", c.secretData}}; }
QString execute(PinnedSshSession &ssh, const QString &cmd, int timeout = 120000) {
    const auto r = ssh.execute(cmd, timeout, 1024 * 1024);
    check(r.error);
    if (r.exitCode != 0) throw std::runtime_error("remote_command_failed_check_status");
    return QString::fromUtf8(r.output);
}
QString stagePath(const QJsonObject &j) { return "/tmp/amnezia-migration-"+j["operation"].toString(); }
void openSession(PinnedSshSession &ssh, const QJsonObject &j, const QString &side) {
    check(ssh.connect(credentials(j[side].toObject()), identity(j[side+"Identity"].toObject())));
}
void install(PinnedSshSession &ssh, const QJsonObject &j) {
    const QString dir = stagePath(j);
    execute(ssh, "umask 077; mkdir -p -- "+quote(dir)+"; test ! -L "+quote(dir)+
            " && test \"$(stat -c '%a:%u' -- "+quote(dir)+")\" = \"700:$(id -u)\"");
    QFile script(":/server_scripts/migration/agent.py");
    if (!script.open(QIODevice::ReadOnly)) throw std::runtime_error("missing_migration_agent");
    const auto hash = QCryptographicHash::hash(script.readAll(), QCryptographicHash::Sha256).toHex();
    script.seek(0);
    const auto path = quote(dir+"/agent.py");
    const auto present = execute(ssh, "if test -e "+path+"; then test ! -L "+path+" && sha256sum -- "+path+"; fi").trimmed();
    if (present.isEmpty()) check(ssh.upload(script, dir+"/agent.py", script.size()));
    else if (!present.startsWith(QString::fromLatin1(hash)+" ")) throw std::runtime_error("migration_agent_changed");
}
QJsonObject agent(PinnedSshSession &ssh, const QJsonObject &j, const QString &action, QJsonObject req = {}) {
    req["operation"] = j["operation"]; req["action"] = action;
    const auto encoded = QJsonDocument(req).toJson(QJsonDocument::Compact).toBase64();
    const auto r = ssh.execute("sudo -n python3 "+quote(stagePath(j)+"/agent.py")+" "+quote(QString::fromLatin1(encoded)), 1800000, 65536);
    check(r.error);
    QJsonParseError parse;
    const auto out = QJsonDocument::fromJson(r.output, &parse).object();
    if (parse.error != QJsonParseError::NoError || out["version"].toInt() != 1) throw std::runtime_error("unknown_result_check_status");
    if (!out["ok"].toBool() || r.exitCode != 0) throw std::runtime_error(out["reason"].toString("remote_failure_check_status").toStdString());
    return out;
}
struct TransferCleanup {
    PinnedSshSession &ssh;
    QString path;
    ~TransferCleanup() { ssh.execute("rm -f -- "+quote(path), 5000); }
};
void dns(const QString &host, const QString &target) {
    const auto result = QHostInfo::fromName(host);
    if (result.error() != QHostInfo::NoError || result.addresses().isEmpty()) throw std::runtime_error("domain_not_resolved");
    // Every locally returned A/AAAA must select this target; stale AAAA is unsafe.
    for (const auto &ip : result.addresses()) if (ip != QHostAddress(target)) throw std::runtime_error("domain_still_points_elsewhere");
}
}

ServerMigrationController::ServerMigrationController(SecureServersRepository *servers, SecureQSettings *settings,
                                                   ConnectionController *connection, QObject *parent)
    : QObject(parent), m_servers(servers), m_settings(settings), m_connection(connection) {
    m_pool.setMaxThreadCount(1);
    m_journal = QJsonDocument::fromJson(settings->value(storage).toByteArray()).object();
    if (!m_journal.isEmpty()) m_details = tr("An unfinished migration is saved. Check its status before continuing.");
}
ServerMigrationController::~ServerMigrationController() { m_pool.waitForDone(); }
void ServerMigrationController::persist() { if (m_journal.isEmpty()) m_settings->remove(storage); else m_settings->setValue(storage, QJsonDocument(m_journal).toJson(QJsonDocument::Compact)); emit changed(); }
void ServerMigrationController::work(const std::function<QJsonObject(QJsonObject)> &fn) {
    if (m_busy) return;
    m_busy = true; emit changed();
    auto *watcher = new QFutureWatcher<QJsonObject>(this);
    connect(watcher, &QFutureWatcher<QJsonObject>::finished, this, [this, watcher] {
        m_journal = watcher->result(); watcher->deleteLater();
        m_details = m_journal.take("message").toString();
        if (phase() == "active" || phase() == "rolled-back") {
            auto admin = m_servers->selfHostedAdminConfig(serverId());
            if (admin) {
                const auto c = credentials(m_journal[phase() == "active" ? "target" : "source"].toObject());
                admin->hostName = phase() == "active" ? m_journal["targetIdentity"].toObject()["address"].toString() : c.hostName;
                admin->userName = c.userName; admin->password = c.secretData; admin->port = c.port;
                admin->vpnHostName = m_journal["domain"].toString();
                m_servers->editServer(serverId(), admin->toJson(), serverConfigUtils::SelfHostedAdmin);
            }
        }
        m_busy = false; persist();
    });
    const auto copy = m_journal;
    watcher->setFuture(QtConcurrent::run(&m_pool, [copy, fn] {
        try { return fn(copy); }
        catch (const std::exception &e) { auto out = copy; out["message"] = QString::fromUtf8(e.what()); return out; }
    }));
}
void ServerMigrationController::discover(const QString &id, const QString &host, int port, const QString &user, const QString &secret) {
    if (m_busy || !m_journal.isEmpty()) return;
    const auto admin = m_servers->selfHostedAdminConfig(id);
    if (!admin || m_connection->isConnected()) { m_details = tr("Disconnect VPN and select a server you administer."); emit changed(); return; }
    const QString domain = vpnEndpoint::normalizeHost(admin->vpnHostName.isEmpty() ? admin->hostName : admin->vpnHostName);
    if (domain.isEmpty() || !QHostAddress(domain).isNull()) { m_details = tr("Set a DNS name as the VPN endpoint before migrating."); emit changed(); return; }
    const auto target = ServerCredentials{vpnEndpoint::normalizeHost(host), user.trimmed(), secret, port};
    if (!target.isValid() || port > 65535) { m_details = tr("Enter the target SSH address, login and credentials."); emit changed(); return; }
    m_journal = {{"serverId", id}, {"phase", "discovering"}, {"domain", domain}, {"original", admin->toJson()},
                 {"source", credentials(admin->credentials())}, {"target", credentials(target)},
                 {"operation", QUuid::createUuid().toString(QUuid::Id128)}};
    persist();
    work([](QJsonObject j) {
        const auto old = credentials(j["source"].toObject()), next = credentials(j["target"].toObject());
        const auto a = PinnedSshSession::discover(old.hostName, old.port), b = PinnedSshSession::discover(next.hostName, next.port);
        check(a.error); check(b.error);
        if (QHostAddress(b.address).protocol() != QAbstractSocket::IPv4Protocol) throw std::runtime_error("first_version_requires_ipv4_target");
        if (a.address == b.address) throw std::runtime_error("source_and_target_are_the_same_host");
        j["sourceIdentity"] = identity(a); j["targetIdentity"] = identity(b); j["phase"] = "fingerprints";
        j["message"] = QString("Source: %1\n%2\n\nTarget: %3\n%4").arg(a.address, a.fingerprint, b.address, b.fingerprint);
        return j;
    });
}
void ServerMigrationController::stage() {
    if (phase() != "fingerprints") return;
    m_journal["phase"] = "copying"; persist();
    work([](QJsonObject j) {
        PinnedSshSession source, target; openSession(source, j, "source"); openSession(target, j, "target");
        install(source, j); install(target, j);
        const auto snapshot = agent(source, j, "export");
        const auto dir = stagePath(j);
        TransferCleanup sourceCleanup{source, dir+"/bundle.tar"}, targetCleanup{target, dir+"/incoming.tar"};
        execute(source, "umask 077; sudo -n cat -- "+quote(snapshot["file"].toString())+" > "+quote(dir+"/bundle.tar"), 1800000);
        QTemporaryFile local;
        if (!local.open()) throw std::runtime_error("private_temporary_file_failed");
        local.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
        check(source.download(dir+"/bundle.tar", local, snapshot["bytes"].toVariant().toLongLong(), QByteArray::fromHex(snapshot["sha256"].toString().toLatin1())));
        if (!local.flush() || !local.seek(0)) throw std::runtime_error("temporary_file_write_failed");
        check(target.upload(local, dir+"/incoming.tar", local.size()));
        agent(target, j, "receive");
        const auto verified = agent(target, j, "import", {{"sha256", snapshot["sha256"]}});
        if (verified["state"] != snapshot["state"]) throw std::runtime_error("target_state_mismatch");
        agent(source, j, "source-check");
        try {
            const auto probes = agent(target, j, "probe-create", {{"address", j["targetIdentity"].toObject()["address"]}});
            agent(source, j, "probe-run", {{"configs", probes["configs"]}, {"address", j["targetIdentity"].toObject()["address"]}});
            agent(target, j, "probe-remove");
            agent(target, j, "probe-confirm");
        } catch (...) {
            try { agent(target, j, "probe-remove"); } catch (...) {}
            throw;
        }
        agent(target, j, "verify");
        j["snapshot"] = snapshot; j["phase"] = "staged";
        j["message"] = QObject::tr("Copy and external VPN path verified. The old server is still running. Change the domain A/AAAA records to the target, then switch servers.");
        return j;
    });
}
void ServerMigrationController::cutover() {
    if (phase() != "staged" && phase() != "switching") return;
    const auto current = m_servers->selfHostedAdminConfig(serverId());
    if (!current || current->toJson() != m_journal["original"].toObject()) {
        m_details = tr("The local server profile changed during migration. Restore it or restart the migration."); emit changed(); return;
    }
    if (m_connection->isConnected()) { m_details = tr("Disconnect VPN before switching servers."); emit changed(); return; }
    // Journal the intent BEFORE either server is stopped. On SSH loss the only
    // permitted next action is reconciliation/rollback using pinned addresses.
    m_journal["phase"] = "switching"; persist();
    work([](QJsonObject j) {
        const auto address = j["targetIdentity"].toObject()["address"].toString();
        dns(j["domain"].toString(), address);
        const auto deliveryHost = j["snapshot"].toObject()["deliveryHost"].toString();
        if (!deliveryHost.isEmpty()) dns(deliveryHost, address);
        PinnedSshSession source, target; openSession(source, j, "source"); openSession(target, j, "target");
        agent(target, j, "verify");
        const auto status = agent(source, j, "status");
        if (status["phase"] == "exported") agent(source, j, "source-check");
        agent(source, j, "source-stop"); agent(target, j, "activate");
        j["phase"] = "active"; j["message"] = QObject::tr("The target is active. Source containers are retained and stopped.");
        return j;
    });
    // Credentials are updated in the completion/reconciliation path, never from a worker.
}
void ServerMigrationController::recover() {
    if (m_journal.isEmpty()) return;
    work([](QJsonObject j) {
        PinnedSshSession source, target; openSession(source, j, "source"); openSession(target, j, "target");
        install(source, j); install(target, j);
        const auto a = agent(source, j, "status"), b = agent(target, j, "status");
        const auto ap = a["phase"].toString(), bp = b["phase"].toString();
        const auto running = b["running"].toObject();
        bool targetRunning = !running.isEmpty() && running.size() == b["containers"].toArray().size();
        for (const auto value : running) targetRunning = targetRunning && value.toBool();
        bool sourceStopped = !a["running"].toObject().isEmpty();
        for (const auto value : a["running"].toObject()) sourceStopped = sourceStopped && !value.toBool();
        if (ap == "stopped" && bp == "active" && targetRunning && sourceStopped) j["phase"] = "active";
        else if ((ap == "stopped" || ap == "stopping") && bp == "ready") { j["phase"] = "switching"; j["snapshot"] = a; }
        else if (ap == "absent" && bp == "absent") j["phase"] = "aborted";
        else if (ap == "exported" && bp == "ready") { j["phase"] = "staged"; j["snapshot"] = a; }
        if (ap == "exported" && (bp == "validated" || bp == "staged")) {
            agent(target, j, "verify");
            agent(target, j, "probe-remove");
            const auto probes = agent(target, j, "probe-create", {{"address", j["targetIdentity"].toObject()["address"]}});
            try {
                agent(source, j, "probe-run", {{"configs", probes["configs"]}, {"address", j["targetIdentity"].toObject()["address"]}});
                agent(target, j, "probe-remove"); agent(target, j, "probe-confirm");
            } catch (...) {
                try { agent(target, j, "probe-remove"); } catch (...) {}
                throw;
            }
            j["snapshot"] = a; j["phase"] = "staged";
        }
        j["message"] = "Source: "+ap+"; target: "+bp;
        return j;
    });
}
void ServerMigrationController::rollback() {
    if (m_journal.isEmpty() || phase() == "fingerprints" || phase() == "discovering") return;
    m_journal["phase"] = "rolling-back"; persist();
    work([](QJsonObject j) {
        PinnedSshSession source, target; openSession(source, j, "source"); openSession(target, j, "target");
        install(source, j); install(target, j);
        const auto a = agent(source, j, "status"), b = agent(target, j, "status");
        if (b["phase"] == "active" || b["phase"] == "rollback-exported" || (b["phase"] == "stopped" && a["phase"] == "stopped")) {
            const auto latest = agent(target, j, "rollback-export");
            if (latest.contains("file")) {
                const auto dir = stagePath(j);
                TransferCleanup targetCleanup{target, dir+"/rollback.tar"}, sourceCleanup{source, dir+"/rollback.tar"};
                execute(target, "umask 077; sudo -n cat -- "+quote(latest["file"].toString())+" > "+quote(dir+"/rollback.tar"));
                QTemporaryFile local;
                if (!local.open()) throw std::runtime_error("private_temporary_file_failed");
                local.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
                check(target.download(dir+"/rollback.tar", local, latest["bytes"].toVariant().toLongLong(), QByteArray::fromHex(latest["sha256"].toString().toLatin1())));
                if (!local.flush() || !local.seek(0)) throw std::runtime_error("temporary_file_write_failed");
                check(source.upload(local, dir+"/rollback.tar", local.size()));
                agent(source, j, "rollback-import", {{"sha256", latest["sha256"]}});
            }
        } else {
            agent(target, j, "abort");
        }
        if (a["phase"] != "absent") agent(source, j, "abort");
        j["phase"] = "rolled-back";
        j["message"] = QObject::tr("Source restarted. Restore its DNS records before reconnecting. Target containers are retained and stopped.");
        return j;
    });
}
void ServerMigrationController::dismiss() {
    if (m_journal.isEmpty()) return;
    if (m_busy || (!m_journal.isEmpty() && phase() != "fingerprints" && phase() != "discovering" && phase() != "rolled-back" && phase() != "active" && phase() != "aborted" && phase() != "finalizing")) return;
    if (phase() == "fingerprints" || phase() == "discovering") {
        m_journal = {}; m_details.clear(); m_settings->remove(storage); emit changed(); return;
    }
    m_journal["phase"] = "finalizing"; persist();
    work([](QJsonObject j) {
        PinnedSshSession source, target; openSession(source, j, "source"); openSession(target, j, "target");
        install(source, j); install(target, j);
        agent(source, j, "finalize"); agent(target, j, "finalize");
        const auto dir = stagePath(j);
        execute(source, "rm -f -- "+quote(dir+"/agent.py")+" "+quote(dir+"/bundle.tar")+" "+quote(dir+"/rollback.tar")+"; if test -d "+quote(dir)+"; then rmdir -- "+quote(dir)+"; fi");
        execute(target, "rm -f -- "+quote(dir+"/agent.py")+" "+quote(dir+"/incoming.tar")+" "+quote(dir+"/rollback.tar")+"; if test -d "+quote(dir)+"; then rmdir -- "+quote(dir)+"; fi");
        return QJsonObject{};
    });
}
