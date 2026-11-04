#include "pinnedSshSession.h"

#include <QCryptographicHash>
#include <QElapsedTimer>
#include <QHostAddress>
#include <QThread>
#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <fcntl.h>
#include <cstring>
#ifdef Q_OS_WINDOWS
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#endif

namespace amnezia {
namespace {
constexpr qint64 archiveLimit = qint64(2) * 1024 * 1024 * 1024;
struct SessionDeleter { void operator()(ssh_session s) const { if (s) { ssh_disconnect(s); ssh_free(s); } } };
using Session = std::unique_ptr<ssh_session_struct, SessionDeleter>;
struct SftpDeleter { void operator()(sftp_session s) const { if (s) sftp_free(s); } };
using Sftp = std::unique_ptr<sftp_session_struct, SftpDeleter>;
struct FileDeleter { void operator()(sftp_file f) const { if (f) sftp_close(f); } };
using RemoteFile = std::unique_ptr<sftp_file_struct, FileDeleter>;
struct ChannelDeleter { void operator()(ssh_channel c) const { if (c) { ssh_channel_close(c); ssh_channel_free(c); } } };
using Channel = std::unique_ptr<ssh_channel_struct, ChannelDeleter>;
Session transport(const QString &host, int port)
{
    if (host.isEmpty() || port < 1 || port > 65535) return {};
    Session session(ssh_new()); if (!session) return {};
    const auto address = host.toUtf8(); long timeout = 15;
    if (ssh_options_set(session.get(), SSH_OPTIONS_HOST, address.constData()) != SSH_OK
        || ssh_options_set(session.get(), SSH_OPTIONS_PORT, &port) != SSH_OK
        || ssh_options_set(session.get(), SSH_OPTIONS_TIMEOUT, &timeout) != SSH_OK
        || ssh_connect(session.get()) != SSH_OK) return {};
    return session;
}
SshIdentity identity(ssh_session session)
{
    SshIdentity result; ssh_key key = nullptr; unsigned char *hash = nullptr; size_t hashSize = 0;
    if (ssh_get_server_publickey(session, &key) != SSH_OK) { result.error = "host_key_unavailable"; return result; }
    result.algorithm = QString::fromLatin1(ssh_key_type_to_char(ssh_key_type(key)));
    if (ssh_get_publickey_hash(key, SSH_PUBLICKEY_HASH_SHA256, &hash, &hashSize) == SSH_OK) {
        result.fingerprint = "SHA256:" + QString::fromLatin1(QByteArray(reinterpret_cast<char *>(hash), hashSize).toBase64(QByteArray::OmitTrailingEquals));
    }
    ssh_clean_pubkey_hash(&hash); ssh_key_free(key);
    sockaddr_storage peer{};
#ifdef Q_OS_WINDOWS
    int length = sizeof(peer);
#else
    socklen_t length = sizeof(peer);
#endif
    if (getpeername(ssh_get_fd(session), reinterpret_cast<sockaddr *>(&peer), &length) == 0) {
        QHostAddress address; address.setAddress(reinterpret_cast<sockaddr *>(&peer)); result.address = address.toString();
    }
    if (result.address.isEmpty() || result.fingerprint.isEmpty()) result.error = "host_identity_unavailable";
    return result;
}
bool canceled(const std::atomic_bool *flag) { return flag && flag->load(); }
bool validSize(qint64 value) { return value >= 0 && value <= archiveLimit; }
}
struct PinnedSshSession::State { Session session; };
PinnedSshSession::PinnedSshSession() : m_state(std::make_unique<State>()) {}
PinnedSshSession::~PinnedSshSession() = default;
SshIdentity PinnedSshSession::discover(const QString &host, int port)
{
    auto session = transport(host, port);
    if (!session) return { {}, {}, {}, "connection_failed" };
    // No username, password, private key or authentication attempt is sent here.
    return identity(session.get());
}
QString PinnedSshSession::connect(const ServerCredentials &credentials, const SshIdentity &approved)
{
    m_state->session.reset();
    if (!credentials.isValid() || !approved.valid() || QHostAddress(approved.address).isNull()) return "invalid_approved_identity";
    auto session = transport(approved.address, credentials.port); if (!session) return "connection_failed";
    const auto actual = identity(session.get());
    if (!actual.valid() || actual.address != approved.address || actual.fingerprint != approved.fingerprint) return "host_key_changed";
    // Authenticate only after the reviewed server key has matched.
    const auto user = credentials.userName.toUtf8(); const auto secret = credentials.secretData.toUtf8();
    int status = SSH_ERROR;
    if (secret.contains("BEGIN") && secret.contains("PRIVATE KEY")) {
        ssh_key key = nullptr;
        if (ssh_pki_import_privkey_base64(secret.constData(), nullptr, nullptr, nullptr, &key) != SSH_OK) return "private_key_needs_decryption";
        status = ssh_userauth_publickey(session.get(), user.constData(), key); ssh_key_free(key);
    } else status = ssh_userauth_password(session.get(), user.constData(), secret.constData());
    if (status != SSH_AUTH_SUCCESS) return "authentication_failed";
    m_state->session = std::move(session); return {};
}
SshCommandResult PinnedSshSession::execute(const QString &command, int timeoutMs, qsizetype outputLimit, const std::atomic_bool *cancel)
{
    SshCommandResult result;
    if (!m_state->session || timeoutMs <= 0 || timeoutMs > 1800000 || outputLimit < 0 || outputLimit > 4 * 1024 * 1024) { result.error = "invalid_request"; return result; }
    if (canceled(cancel)) { result.error = "canceled_before_start"; return result; }
    Channel channel(ssh_channel_new(m_state->session.get()));
    if (!channel || ssh_channel_open_session(channel.get()) != SSH_OK) { result.error = "command_start_failed"; return result; }
    if (canceled(cancel)) { result.error = "canceled_before_start"; return result; }
    if (ssh_channel_request_exec(channel.get(), command.toUtf8().constData()) != SSH_OK) { result.error = "command_start_failed"; return result; }
    QElapsedTimer elapsed; elapsed.start(); char buffer[16384]; qint64 diagnosticBytes = 0;
    while (!ssh_channel_is_eof(channel.get())) {
        if (canceled(cancel) || elapsed.elapsed() > timeoutMs) { result.error = canceled(cancel) ? "canceled_unknown_result" : "command_timeout_unknown_result"; return result; }
        for (int stream = 0; stream < 2; ++stream) {
            const int size = ssh_channel_read_timeout(channel.get(), buffer, sizeof(buffer), stream, 100);
            if (size == SSH_ERROR) { result.error = "connection_lost_unknown_result"; return result; }
            if (size <= 0) continue;
            if (stream == 0) {
                if (result.output.size() + size > outputLimit) { result.error = "output_limit"; return result; }
                result.output.append(buffer, size);
            } else {
                // Drain stderr concurrently without retaining/logging server secrets.
                diagnosticBytes += size; if (diagnosticBytes > 4 * 1024 * 1024) { result.error = "diagnostic_limit"; return result; }
            }
        }
    }
    result.exitCode = ssh_channel_get_exit_status(channel.get());
    if (result.exitCode < 0) result.error = "missing_exit_status_unknown_result";
    return result;
}
QString PinnedSshSession::download(const QString &remoteFile, QIODevice &destination, qint64 expectedBytes,
                                  const QByteArray &expectedSha256, const std::atomic_bool *cancel)
{
    if (!m_state->session || !validSize(expectedBytes) || expectedSha256.size() != 32 || !destination.isWritable()) return "invalid_transfer";
    Sftp sftp(sftp_new(m_state->session.get())); if (!sftp || sftp_init(sftp.get()) != SSH_OK) return "sftp_unavailable";
    RemoteFile file(sftp_open(sftp.get(), remoteFile.toUtf8().constData(), O_RDONLY, 0)); if (!file) return "remote_file_unavailable";
    sftp_attributes attributes = sftp_fstat(file.get());
    const bool sizeOK = attributes && attributes->type == SSH_FILEXFER_TYPE_REGULAR && attributes->size == static_cast<uint64_t>(expectedBytes);
    if (attributes) sftp_attributes_free(attributes); if (!sizeOK) return "remote_size_changed";
    QCryptographicHash hash(QCryptographicHash::Sha256); qint64 total = 0; char buffer[65536];
    while (true) {
        if (canceled(cancel)) return "transfer_canceled";
        const auto size = sftp_read(file.get(), buffer, sizeof(buffer)); if (size < 0) return "download_failed"; if (size == 0) break;
        total += size; if (total > expectedBytes) return "remote_size_changed";
        if (destination.write(buffer, size) != size) return "local_write_failed";
        hash.addData(QByteArrayView(buffer, size));
    }
    if (total != expectedBytes || hash.result() != expectedSha256) return "snapshot_digest_mismatch";
    return {};
}
QString PinnedSshSession::upload(QIODevice &source, const QString &remoteFile, qint64 expectedBytes, const std::atomic_bool *cancel)
{
    if (!m_state->session || !validSize(expectedBytes) || !source.isReadable()) return "invalid_transfer";
    if (canceled(cancel)) return "transfer_canceled";
    Sftp sftp(sftp_new(m_state->session.get())); if (!sftp || sftp_init(sftp.get()) != SSH_OK) return "sftp_unavailable";
    RemoteFile file(sftp_open(sftp.get(), remoteFile.toUtf8().constData(), O_WRONLY | O_CREAT | O_EXCL, 0600)); if (!file) return "remote_file_exists_or_unavailable";
    qint64 total = 0; char buffer[65536];
    while (true) {
        if (canceled(cancel)) return "transfer_canceled";
        const auto size = source.read(buffer, sizeof(buffer)); if (size < 0) return "local_read_failed"; if (!size) break;
        total += size; if (total > expectedBytes) return "local_size_changed";
        qint64 written = 0; while (written < size) { const auto bytes = sftp_write(file.get(), buffer + written, size - written); if (bytes <= 0) return "upload_failed"; written += bytes; }
    }
    if (total != expectedBytes || sftp_fsync(file.get()) != SSH_OK) return "upload_incomplete";
    return {};
}
}
