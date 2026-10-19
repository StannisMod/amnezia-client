#ifndef LINUXDNSCACHE_H
#define LINUXDNSCACHE_H

#include <QDebug>
#include <QProcess>
#include <QStringList>

namespace LinuxDnsCache {

// A cache flush must never restart the resolver: the daemon may still have
// asynchronous SetLink* requests in flight against that same service.
inline bool runCommand(const QString &program, const QStringList &arguments,
                       int timeoutMs, bool quiet = false)
{
    QProcess process;
    process.setProcessChannelMode(QProcess::MergedChannels);
    process.start(program, arguments);
    if (!process.waitForStarted(timeoutMs)) {
        if (!quiet)
            qWarning() << "DNS cache command failed to start:" << program << process.errorString();
        return false;
    }
    if (!process.waitForFinished(timeoutMs)) {
        process.kill();
        process.waitForFinished(1000);
        qWarning() << "DNS cache command timed out:" << program << arguments;
        return false;
    }
    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
        if (!quiet)
            qWarning() << "DNS cache command failed:" << program << arguments
                       << process.exitCode() << process.readAll();
        return false;
    }
    return true;
}

inline bool flush(int timeoutMs = 5000)
{
    // Prefer resolved when both services are installed: it owns the per-link
    // VPN DNS configuration. A failed flush must not fall back to a restart.
    if (runCommand(QStringLiteral("systemctl"),
                   {QStringLiteral("is-active"), QStringLiteral("--quiet"),
                    QStringLiteral("systemd-resolved.service")}, timeoutMs, true)) {
        if (!runCommand(QStringLiteral("resolvectl"), {QStringLiteral("flush-caches")}, timeoutMs))
            return false;
    } else if (runCommand(QStringLiteral("systemctl"),
                          {QStringLiteral("is-active"), QStringLiteral("--quiet"),
                           QStringLiteral("nscd.service")}, timeoutMs, true)) {
        if (!runCommand(QStringLiteral("nscd"),
                        {QStringLiteral("-i"), QStringLiteral("hosts")}, timeoutMs))
            return false;
    } else {
        qWarning() << "No suitable DNS manager found.";
        return false;
    }
    qDebug() << "Flush dns completed";
    return true;
}

} // namespace LinuxDnsCache

#endif // LINUXDNSCACHE_H
