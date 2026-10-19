#include "desktoproutingprocess.h"

#include <QCoreApplication>
#include <QDir>
#include <QJsonDocument>
#include <QTimer>

namespace {
QString executablePath()
{
#ifdef Q_OS_WIN
    return QDir(QCoreApplication::applicationDirPath()).filePath("amnezia-routing.exe");
#else
    return QDir(QCoreApplication::applicationDirPath()).filePath("amnezia-routing");
#endif
}
}

DesktopRoutingProcess *DesktopRoutingProcess::instance()
{
    static auto instance = new DesktopRoutingProcess(qApp);
    return instance;
}

DesktopRoutingProcess::DesktopRoutingProcess(QObject *parent) : QObject(parent)
{
    m_status.insert("connected", false);
    // Native diagnostics are intentionally not forwarded to application logs:
    // the child emits only counters/status and sanitized configuration errors.
    m_process.setStandardErrorFile(QProcess::nullDevice());
    connect(&m_process, &QProcess::readyReadStandardOutput, this, &DesktopRoutingProcess::readOutput);
    connect(&m_process, &QProcess::finished, this, [this](int exitCode, QProcess::ExitStatus exitStatus) {
        m_status.insert("connected", false);
        if (!m_stopping && (exitCode != 0 || exitStatus != QProcess::NormalExit)) emit failed();
        if (!m_stopping) emit disconnected();
    });
    connect(qApp, &QCoreApplication::aboutToQuit, this, [this] { stop(false); });
}

bool DesktopRoutingProcess::isActive() const { return m_owned || m_process.state() != QProcess::NotRunning; }
QJsonObject DesktopRoutingProcess::status() const { return m_status; }

bool DesktopRoutingProcess::start(const QJsonObject &profile, bool strictKillSwitch)
{
    // Until the existing firewall/app filters are integrated, fail explicitly
    // rather than silently weaken a selected OS kill-switch or per-app policy.
    if (strictKillSwitch
            || profile.value("appSplitTunnelType").toInt() != 0
            || profile.value("killSwitchOption").toString() == "true") return false;
    stop(false);
    if (isActive()) return false;
    m_status = {{"connected", false}, {"deviceIpv4Address", "172.19.0.1"},
                {"serverIpv4Gateway", "172.19.0.2"}, {"rxBytes", 0}, {"txBytes", 0}};
    m_buffer.clear();
    m_process.start(executablePath(), {});
    if (!m_process.waitForStarted(5000)) return false;
    m_owned = true;
    const auto bytes = QJsonDocument(profile).toJson(QJsonDocument::Compact) + '\n';
    if (m_process.write(bytes) != bytes.size()) { stop(false); return false; }
    return true;
}

void DesktopRoutingProcess::stop(bool notify)
{
    m_stopping = true;
    if (m_process.state() != QProcess::NotRunning) {
        m_process.write("stop\n");
        m_process.closeWriteChannel();
        // Graceful shutdown reverts the resolver, closes the engine/TUN, then
        // removes only owned policy state. Killing retains the fail-closed
        // blackhole and is reported as a cleanup failure by the next start.
        if (!m_process.waitForFinished(8000)) {
            m_process.kill(); m_process.waitForFinished(2000);
        }
    }
    if (m_owned) {
        QProcess recovery;
        recovery.setStandardErrorFile(QProcess::nullDevice());
        recovery.start(executablePath(), {"--recover"});
        if (recovery.waitForStarted(3000) && recovery.waitForFinished(8000)
                && recovery.exitStatus() == QProcess::NormalExit && recovery.exitCode() == 0) m_owned = false;
    }
    m_status.insert("connected", false);
    m_stopping = false;
    if (notify) emit disconnected();
}

void DesktopRoutingProcess::readOutput()
{
    m_buffer += m_process.readAllStandardOutput();
    if (m_buffer.size() > 65536) { stop(false); emit failed(); emit disconnected(); return; }
    int newline;
    while ((newline = m_buffer.indexOf('\n')) >= 0) {
        const auto row = QJsonDocument::fromJson(m_buffer.left(newline)).object();
        m_buffer.remove(0, newline + 1);
        const auto type = row.value("type").toString();
        if (type == "status") {
            m_status = row;
            m_status.insert("date", QDateTime::currentDateTime().toString());
        } else if (type == "connected") {
            m_status.insert("connected", true);
            m_status.insert("date", QDateTime::currentDateTime().toString());
            emit connected(row.value("pubkey").toString());
        } else if (type == "error") {
            // Do not substitute the legacy backend after a routed failure.
            emit failed();
        }
    }
}
