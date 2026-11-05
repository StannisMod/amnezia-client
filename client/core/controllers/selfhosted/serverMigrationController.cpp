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
#include <QThread>
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
    for (const auto &name : {"agent.py", "relay.py"}) {
        QFile script(":/server_scripts/migration/"+QString::fromLatin1(name));
        if (!script.open(QIODevice::ReadOnly)) throw std::runtime_error("missing_migration_agent");
        const auto hash = QCryptographicHash::hash(script.readAll(), QCryptographicHash::Sha256).toHex();
        script.seek(0);
        const auto path = quote(dir+"/"+name);
        const auto present = execute(ssh, "if test -e "+path+"; then test ! -L "+path+" && sha256sum -- "+path+"; fi").trimmed();
        if (present.isEmpty()) check(ssh.upload(script, dir+"/"+name, script.size()));
        else if (!present.startsWith(QString::fromLatin1(hash)+" ")) throw std::runtime_error("migration_agent_changed");
    }
}
QString privileged(const QString &command) {
    return "if test \"$(id -u)\" = 0; then "+command+"; else sudo -n "+command+"; fi";
}
QJsonObject agent(PinnedSshSession &ssh, const QJsonObject &j, const QString &action, QJsonObject req = {}) {
    req["operation"] = j["operation"]; req["action"] = action;
    const auto encoded = QJsonDocument(req).toJson(QJsonDocument::Compact).toBase64();
    const auto r = ssh.execute(privileged("python3 "+quote(stagePath(j)+"/agent.py")+" "+quote(QString::fromLatin1(encoded))), 1800000, 65536);
    check(r.error);
    QJsonParseError parse;
    const auto out = QJsonDocument::fromJson(r.output, &parse).object();
    if (parse.error != QJsonParseError::NoError || out["version"].toInt() != 1) throw std::runtime_error("unknown_result_check_status");
    if (!out["ok"].toBool() || r.exitCode != 0) throw std::runtime_error(out["reason"].toString("remote_failure_check_status").toStdString());
    return out;
}
QString explain(const QString &code) {
    if (code == "domain_still_points_elsewhere" || code == "domain_not_resolved")
        return ServerMigrationController::tr("DNS has not switched completely. Check all VPN and subscription A/AAAA records, wait for their caches to expire and retry.");
    if (code == "host_key_changed")
        return ServerMigrationController::tr("The SSH identity changed. Check the server console before trusting a new key.");
    if (code == "authentication_failed" || code == "connection_failed")
        return ServerMigrationController::tr("Cannot connect to SSH. Check the address, port and login credentials, then check the saved operation.");
    if (code == "private_key_needs_decryption")
        return ServerMigrationController::tr("This SSH key is encrypted. Unlock it before using server migration.");
    if (code == "source_changed" || code == "source_stack_changed" || code == "source_changed_during_snapshot")
        return ServerMigrationController::tr("The source changed while copying. Restore the source operation and start a fresh copy before switching DNS.");
    if (code == "target_vpn_or_dns_changed_manual_recovery_required")
        return ServerMigrationController::tr("Automatic rollback stopped because the target VPN or DNS configuration changed. Reconcile those changes before restarting the source.");
    if (code.contains("collision"))
        return ServerMigrationController::tr("The target already uses a required name, port or network. Choose an empty target; existing resources will be kept.");
    return ServerMigrationController::tr("The migration stopped. Check the saved operation before retrying or restoring the source. Details: %1").arg(code);
}
QJsonObject relay(PinnedSshSession &target, const QJsonObject &j, const QString &action, QJsonObject req = {}, bool authorizeSource = true) {
    req["action"] = action; req["operation"] = j["operation"];
    if (authorizeSource) {
        if (j["transport"].toString() != "server-pull-v1") throw std::runtime_error("unsupported_legacy_migration_transport");
        req["source"] = j["source"]; req["sourceIdentity"] = j["sourceIdentity"];
    }
    const auto path = stagePath(j)+"/request-"+QUuid::createUuid().toString(QUuid::Id128)+".json";
    QBuffer input; input.setData(QJsonDocument(req).toJson(QJsonDocument::Compact)); input.open(QIODevice::ReadOnly);
    struct Cleanup { PinnedSshSession &ssh; QString path; ~Cleanup() { ssh.execute("rm -f -- "+quote(path), 5000); } } cleanup{target, path};
    check(target.upload(input, path, input.size()));
    const auto r = target.execute(privileged("python3 "+quote(stagePath(j)+"/relay.py")+" "+quote(path)), 1800000, 65536);
    check(r.error);
    QJsonParseError error;
    const auto result = QJsonDocument::fromJson(r.output, &error).object();
    if (error.error != QJsonParseError::NoError || result["version"].toInt() != 1) throw std::runtime_error("unknown_relay_result_check_status");
    if (!result["ok"].toBool() || r.exitCode != 0) throw std::runtime_error(result["reason"].toString("relay_failed_check_status").toStdString());
    return result;
}
QJsonObject sourceCommand(PinnedSshSession &target, const QJsonObject &j, const QString &command) {
    return relay(target, j, "source-command", {{"command", command}});
}
QJsonObject waitForCopy(PinnedSshSession &target, const QJsonObject &j, const std::shared_ptr<std::atomic_bool> &stopping) {
    for (int attempt = 0; attempt < 1800; ++attempt) {
        if (stopping->load()) throw std::runtime_error("pull_still_running_on_target_check_status");
        const auto result = relay(target, j, "poll-stage", {}, false);
        if (result["phase"] == "interrupted") throw std::runtime_error("pull_job_interrupted_check_status");
        if (result["phase"] != "running") return result;
        QThread::sleep(1);
    }
    throw std::runtime_error("pull_still_running_on_target_check_status");
}
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
ServerMigrationController::~ServerMigrationController() { m_stopping->store(true); m_pool.waitForDone(); }
void ServerMigrationController::persist() { if (m_journal.isEmpty()) m_settings->remove(storage); else m_settings->setValue(storage, QJsonDocument(m_journal).toJson(QJsonDocument::Compact)); emit changed(); }
void ServerMigrationController::work(const std::function<QJsonObject(QJsonObject)> &fn) {
    if (m_busy) return;
    m_busy = true; emit changed();
    auto *watcher = new QFutureWatcher<QJsonObject>(this);
    connect(watcher, &QFutureWatcher<QJsonObject>::finished, this, [this, watcher] {
        m_journal = watcher->result(); watcher->deleteLater();
        m_details = m_journal.take("message").toString();
        const auto failure = m_journal.take("failure").toString();
        if (!failure.isEmpty()) m_details = explain(failure);
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
        catch (const std::exception &e) { auto out = copy; out["failure"] = QString::fromUtf8(e.what()); return out; }
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
                 {"transport", "server-pull-v1"}, {"operation", QUuid::createUuid().toString(QUuid::Id128)}};
    persist();
    work([](QJsonObject j) {
        const auto next = credentials(j["target"].toObject());
        const auto b = PinnedSshSession::discover(next.hostName, next.port);
        check(b.error);
        if (QHostAddress(b.address).protocol() != QAbstractSocket::IPv4Protocol) throw std::runtime_error("first_version_requires_ipv4_target");
        j["targetIdentity"] = identity(b); j["phase"] = "target-fingerprint";
        j["message"] = QString("Target: %1\n%2").arg(b.address, b.fingerprint);
        return j;
    });
}
void ServerMigrationController::stage() {
    if (phase() == "target-fingerprint") {
        work([stopping = m_stopping](QJsonObject j) {
            PinnedSshSession target; openSession(target, j, "target"); install(target, j);
            const auto old = credentials(j["source"].toObject());
            const auto a = relay(target, j, "discover-source", {{"host", old.hostName}, {"port", old.port}}, false)["identity"].toObject();
            if (a["address"] == j["targetIdentity"].toObject()["address"]) throw std::runtime_error("source_and_target_are_the_same_host");
            j["sourceIdentity"] = a; j["phase"] = "fingerprints";
            j["message"] = QString("Source: %1\n%2\n\nTarget: %3\n%4").arg(a["address"].toString(), a["fingerprint"].toString(),
                j["targetIdentity"].toObject()["address"].toString(), j["targetIdentity"].toObject()["fingerprint"].toString());
            return j;
        });
        return;
    }
    if (phase() != "fingerprints") return;
    m_journal["phase"] = "copying"; persist();
    work([stopping = m_stopping](QJsonObject j) {
        PinnedSshSession target; openSession(target, j, "target"); install(target, j);
        relay(target, j, "start-stage", {{"targetAddress", j["targetIdentity"].toObject()["address"]}});
        const auto result = waitForCopy(target, j, stopping);
        j["snapshot"] = result["source"]; j["phase"] = "staged";
        j["message"] = ServerMigrationController::tr("Copy and external VPN path verified. The old server is still running. Change the domain A/AAAA records to the target, then switch servers.");
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
        PinnedSshSession target; openSession(target, j, "target");
        agent(target, j, "verify");
        const auto status = sourceCommand(target, j, "status");
        if (status["phase"] == "exported") sourceCommand(target, j, "source-check");
        sourceCommand(target, j, "source-stop"); agent(target, j, "activate");
        j["phase"] = "active"; j["message"] = ServerMigrationController::tr("The target is active. Source containers are retained and stopped.");
        return j;
    });
    // Credentials are updated in the completion/reconciliation path, never from a worker.
}
void ServerMigrationController::recover() {
    if (m_journal.isEmpty()) return;
    work([stopping = m_stopping](QJsonObject j) {
        PinnedSshSession target; openSession(target, j, "target");
        install(target, j);
        if (j["phase"] == "copying") {
            const auto job = relay(target, j, "poll-stage", {}, false);
            if (job["phase"] == "running" || job.contains("source")) {
                const auto result = job["phase"] == "running" ? waitForCopy(target, j, stopping) : job;
                j["snapshot"] = result["source"]; j["phase"] = "staged";
                j["message"] = ServerMigrationController::tr("The server-to-server copy has completed. You can now update DNS and switch servers.");
                return j;
            }
        }
        const auto a = sourceCommand(target, j, "status"), b = agent(target, j, "status");
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
            relay(target, j, "start-stage", {{"targetAddress", j["targetIdentity"].toObject()["address"]}});
            const auto result = waitForCopy(target, j, stopping);
            j["snapshot"] = result["source"]; j["phase"] = "staged";
        }
        j["message"] = "Source: "+ap+"; target: "+bp;
        return j;
    });
}
void ServerMigrationController::rollback() {
    if (m_journal.isEmpty() || phase() == "fingerprints" || phase() == "discovering") return;
    m_journal["phase"] = "rolling-back"; persist();
    work([](QJsonObject j) {
        PinnedSshSession target; openSession(target, j, "target");
        install(target, j);
        relay(target, j, "rollback");
        j["phase"] = "rolled-back";
        j["message"] = ServerMigrationController::tr("Source restarted. Restore its DNS records before reconnecting. Target containers are retained and stopped.");
        return j;
    });
}
void ServerMigrationController::dismiss() {
    if (m_journal.isEmpty()) return;
    if (m_busy || (!m_journal.isEmpty() && phase() != "fingerprints" && phase() != "target-fingerprint" && phase() != "discovering" && phase() != "rolled-back" && phase() != "active" && phase() != "aborted" && phase() != "finalizing")) return;
    if (phase() == "fingerprints" || phase() == "target-fingerprint" || phase() == "discovering") {
        m_journal = {}; m_details.clear(); m_settings->remove(storage); emit changed(); return;
    }
    m_journal["phase"] = "finalizing"; persist();
    work([](QJsonObject j) {
        PinnedSshSession target; openSession(target, j, "target");
        install(target, j);
        sourceCommand(target, j, "finalize"); agent(target, j, "finalize");
        const auto dir = stagePath(j);
        execute(target, "rm -f -- "+quote(dir+"/agent.py")+" "+quote(dir+"/relay.py")+"; if test -d "+quote(dir)+"; then rmdir -- "+quote(dir)+"; fi");
        return QJsonObject{};
    });
}
