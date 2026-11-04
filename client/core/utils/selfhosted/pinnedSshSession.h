#ifndef PINNEDSSHSESSION_H
#define PINNEDSSHSESSION_H

#include <QByteArray>
#include <QIODevice>
#include <QString>
#include <atomic>
#include <memory>
#include "core/utils/commonStructs.h"

namespace amnezia {
// Migration uses a reviewed fingerprint and a literal address after discovery;
// DNS cutover must never redirect a subsequent management connection.
struct SshIdentity {
    QString address;
    QString fingerprint;
    QString algorithm;
    QString error;
    bool valid() const { return error.isEmpty() && !address.isEmpty() && !fingerprint.isEmpty(); }
};
struct SshCommandResult {
    QByteArray output;
    int exitCode = -1;
    QString error;
    bool succeeded() const { return error.isEmpty() && exitCode == 0; }
};
class PinnedSshSession {
public:
    PinnedSshSession();
    ~PinnedSshSession();
    PinnedSshSession(const PinnedSshSession &) = delete;
    PinnedSshSession &operator=(const PinnedSshSession &) = delete;
    static SshIdentity discover(const QString &host, int port);
    QString connect(const ServerCredentials &credentials, const SshIdentity &approved);
    SshCommandResult execute(const QString &command, int timeoutMs = 120000, qsizetype outputLimit = 65536,
                             const std::atomic_bool *cancel = nullptr);
    QString download(const QString &remoteFile, QIODevice &destination, qint64 expectedBytes,
                     const QByteArray &expectedSha256, const std::atomic_bool *cancel = nullptr);
    QString upload(QIODevice &source, const QString &remoteFile, qint64 expectedBytes,
                   const std::atomic_bool *cancel = nullptr);
private:
    struct State;
    std::unique_ptr<State> m_state;
};
}
#endif
