#include <QCoreApplication>
#include <QBuffer>
#include <QCryptographicHash>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <libssh/libssh.h>
#include "core/utils/selfhosted/pinnedSshSession.h"
#include "core/utils/selfhosted/connectionUpdatesCommand.h"
#include <QUuid>

using namespace amnezia;
int adminCommands(const QString &config)
{
    QFile input(config); if (!input.open(QIODevice::ReadOnly)) return 20;
    const auto c = QJsonDocument::fromJson(input.readAll()).object();
    ServerCredentials credentials{c["host"].toString(), "root", c["key"].toString(), c["port"].toInt()};
    SshIdentity approved{c["host"].toString(), c["fingerprint"].toString(), "ssh-ed25519", {}};
    PinnedSshSession ssh; if (!ssh.connect(credentials, approved).isEmpty()) return 21;
    const QString path = "/tmp/amnezia-admin-test-"+QUuid::createUuid().toString(QUuid::Id128);
    if (!ssh.execute("umask 077; mkdir '"+path+"'").succeeded()) return 22;
    const auto settings = c["settings"].toObject();
    const auto peer = QString::fromLatin1(QByteArray(32, 'N').toBase64());
    QJsonObject info;
    for (const auto &action : {"info", "issue", "publish", "revoke"}) {
        QJsonObject request;
        if (QString(action) != "info") request = {{"container", "amnezia-awg2"}, {"clientPublicKey", peer}, {"settings", settings}};
        QBuffer body; body.setData(QJsonDocument(request).toJson(QJsonDocument::Compact)); body.open(QIODevice::ReadOnly);
        if (!ssh.upload(body, path+"/request.json", body.size()).isEmpty()) return 23;
        const auto result = ssh.execute(connectionUpdates::adminCommandScript(action, path));
        ssh.execute("rm -f -- '"+path+"/request.json'");
        if (!result.succeeded()) return 24;
        const auto reply = QJsonDocument::fromJson(result.output).object();
        if (reply["version"].toInt() != 1 || (QString(action) != "info" && !reply["ok"].toBool())) return 25;
        if (QString(action) == "info") info = reply;
    }
    ssh.execute("rmdir -- '"+path+"'");
    if (info["publicKey"] != c["publicKey"] || info["certificate"] != c["certificate"]) return 26;
    return 0;
}
int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv); const auto args = app.arguments();
    if (ssh_init() != SSH_OK) return 2;
    if (args.size() == 3 && args[1] == "admin") return adminCommands(args[2]);
    if (args.size() != 6) return 2;
    int result = 0;
    {
        QFile key(args[4]); if (!key.open(QIODevice::ReadOnly)) return 3;
        const auto identity = PinnedSshSession::discover(args[1], args[2].toInt());
        if (!identity.valid() || identity.fingerprint.size() < 45 || identity.address != "127.0.0.1") return 4;
        ServerCredentials credentials { args[1], args[3], QString::fromUtf8(key.readAll()), args[2].toInt() };
        PinnedSshSession connection; auto wrong = identity; wrong.fingerprint = "SHA256:wrong";
        if (connection.connect(credentials, wrong) != "host_key_changed") return 5;
        auto password = credentials; password.secretData = "synthetic-password";
        if (connection.connect(password, wrong) != "host_key_changed") return 14;
        if (!connection.connect(credentials, identity).isEmpty()) return 6;
        std::atomic_bool canceled { true };
        const auto stopped = connection.execute("touch '" + args[5] + "/must-not-exist'", 5000, 65536, &canceled);
        if (stopped.error != "canceled_before_start") return 15;
        const auto command = connection.execute("printf 'verified'; exit 7");
        if (!command.error.isEmpty() || command.exitCode != 7 || command.output != "verified") return 7;
        QByteArray expected(196731, 'D'); expected.replace(42, 8, "snapshot");
        QBuffer input(&expected); input.open(QIODevice::ReadOnly);
        const auto remote = args[5] + "/snapshot.bin";
        if (!connection.upload(input, remote, expected.size()).isEmpty()) return 8;
        input.seek(0); if (connection.upload(input, remote, expected.size()).isEmpty()) return 9;
        QByteArray downloaded; QBuffer destination(&downloaded); destination.open(QIODevice::WriteOnly);
        const auto digest = QCryptographicHash::hash(expected, QCryptographicHash::Sha256);
        if (!connection.download(remote, destination, expected.size(), digest).isEmpty() || downloaded != expected) return 10;
        QByteArray wrongBytes; QBuffer wrongDestination(&wrongBytes); wrongDestination.open(QIODevice::WriteOnly);
        if (connection.download(remote, wrongDestination, expected.size() + 1, digest) != "remote_size_changed") return 11;
        if (connection.download(remote, wrongDestination, expected.size(), QByteArray(32, 'X')) != "snapshot_digest_mismatch") return 12;
        const auto failed = connection.execute("true", 0); if (failed.succeeded()) return 13;
        const QJsonObject output { { "hostKeyVerifiedBeforeAuth", true }, { "exitStatusPreserved", true },
            { "exclusiveUpload", true }, { "snapshotHashVerified", true } };
        const auto bytes = QJsonDocument(output).toJson(QJsonDocument::Compact);
        fprintf(stdout, "%s\n", bytes.constData());
    }
    ssh_finalize(); return result;
}
