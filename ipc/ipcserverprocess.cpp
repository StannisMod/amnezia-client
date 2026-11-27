#include "ipcserverprocess.h"
#include "ipc.h"
#include <QProcess>
#include <QPointer>
#include <QEventLoop>
#include <QTimer>
#include "../service/server/openvpndnssession.h"
#include "../service/server/router.h"

namespace {
// Include legacy ON processes: they still own a native DNS publisher and must
// finish before an OFF service transaction may start on a different descriptor.
QPointer<IpcServerProcess> nativeOpenVpnOwner;
}

#ifndef Q_OS_IOS

IpcServerProcess::IpcServerProcess(QObject *parent) :
    IpcProcessInterfaceSource(parent),
    m_process(QSharedPointer<QProcess>(new QProcess()))
{
    connect(m_process.data(), &QProcess::errorOccurred, this, &IpcServerProcess::errorOccurred);
    connect(m_process.data(), QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &IpcServerProcess::finishNativeProcess);
    connect(m_process.data(), &QProcess::readyRead, this, &IpcServerProcess::readyRead);
    connect(m_process.data(), &QProcess::readyReadStandardError, this, &IpcServerProcess::readyReadStandardError);
    connect(m_process.data(), &QProcess::readyReadStandardOutput, this, &IpcServerProcess::readyReadStandardOutput);
    connect(m_process.data(), &QProcess::started, this, &IpcServerProcess::started);
    connect(m_process.data(), &QProcess::stateChanged, this, &IpcServerProcess::stateChanged);

    connect(m_process.data(), &QProcess::errorOccurred, this, [this](QProcess::ProcessError error){
        qDebug() << "IpcServerProcess errorOccurred " << error;
        if (error == QProcess::FailedToStart) {
            finishNativeProcess(-1, QProcess::CrashExit);
        }
    });

}

IpcServerProcess::~IpcServerProcess()
{
    m_tearingDown = true;
    m_process->disconnect(this);
    if (m_dnsSession) {
        // No timeout grants permission to discard uncertain DNS ownership.
        // A forced service/OS kill uses the durable recovery journal instead.
        while (!m_dnsSession->requestStop()) {
            QEventLoop wait;
            QTimer::singleShot(250, &wait, &QEventLoop::quit);
            wait.exec();
        }
        if (m_process->state() != QProcess::NotRunning) {
            QEventLoop wait;
            connect(m_process.data(), QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
                    &wait, &QEventLoop::quit);
            QTimer::singleShot(3000, &wait, &QEventLoop::quit);
            wait.exec();
            if (m_process->state() != QProcess::NotRunning) {
                m_process->kill(); // OS DNS/aliases are already confirmed restored.
                m_process->waitForFinished(3000);
            }
        }
        m_dnsSession->nativeFinished();
        if (nativeOpenVpnOwner == this) nativeOpenVpnOwner.clear();
    }
#ifdef Q_OS_WIN
    if (m_windowsIpv6Routes) {
        m_process->kill();
        if (m_process->state() != QProcess::NotRunning) m_process->waitForFinished(3000);
        m_windowsIpv6Routes.reset();
    }
#endif
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
    if (m_openVpnDevice) {
        m_process->kill();
        if (m_process->state() != QProcess::NotRunning) m_process->waitForFinished(3000);
        m_ipv6Routes.reset();
        m_openVpnDevice.reset();
    }
#endif
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    if (m_macIpv6Routes) {
        m_process->kill();
        if (m_process->state() != QProcess::NotRunning) m_process->waitForFinished(3000);
        m_macIpv6Routes.reset();
    }
#endif
    qDebug() << "IpcServerProcess::~IpcServerProcess";
}

void IpcServerProcess::start()
{
    if (m_shutdownRequested || m_tearingDown || m_exitPending || m_process->state() != QProcess::NotRunning) return;
    m_hasProcessResult = false;
    if (m_dnsSession && m_dnsSession->finished()) {
        emit errorOccurred(QProcess::FailedToStart);
        return;
    }
    if (m_program == amnezia::PermittedProcess::OpenVPN
        && nativeOpenVpnOwner && nativeOpenVpnOwner != this) {
        emit errorOccurred(QProcess::FailedToStart);
        return;
    }
    if (m_program == amnezia::PermittedProcess::OpenVPN) nativeOpenVpnOwner = this;
    m_process->setArguments(m_arguments);
    QStringList arguments = m_arguments;
    if (m_dnsSession) {
        // No caller-provided management endpoint, native script, or native DNS
        // publisher is allowed to race the service's own transaction.
        if (arguments.size() != 2 || arguments[0] != "--config") {
            finishNativeProcess(-1, QProcess::CrashExit);
            return;
        }
        arguments << "--management" << "127.0.0.1" << QString::number(m_dnsSession->port())
                  << "--management-client" << "--management-external-dns";
        m_process->setArguments(arguments);
    }
#ifdef Q_OS_WIN
    m_windowsIpv6Routes.reset();
#endif
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
    m_ipv6Routes.reset();
    m_openVpnDevice.reset();
    if (m_program == amnezia::PermittedProcess::OpenVPN) {
        m_openVpnDevice = std::make_unique<LinuxOpenVpnDevice>();
        m_process->setArguments(arguments + m_openVpnDevice->arguments());
    }
#endif
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    m_macIpv6Routes.reset();
    if (m_program == amnezia::PermittedProcess::OpenVPN)
        m_macIpv6Routes = std::make_unique<MacOpenVpnIpv6Routes>();
#endif
    if (m_process->program().isEmpty()) {
        qDebug() << "IpcServerProcess failed to start, program is empty";
    }

    if (!m_dnsSession) Utils::killProcessByName(m_process->program());
    m_process->start();
    if (m_program == amnezia::PermittedProcess::CertUtil
            || m_program == amnezia::PermittedProcess::Tun2Socks)
        qDebug() << "IpcServerProcess started," << m_process->program() << "[arguments redacted]";
    else
        qDebug() << "IpcServerProcess started," << m_process->program() << m_process->arguments();

    m_process->waitForStarted();
}

void IpcServerProcess::terminate() {
    if (m_dnsSession) { stopManaged(); return; }
    m_process->terminate();
}

void IpcServerProcess::kill() {
    if (m_dnsSession) { stopManaged(); return; }
    m_process->kill();
}

void IpcServerProcess::close()
{
    if (m_dnsSession) { stopManaged(); return; }
    m_process->close();
}

bool IpcServerProcess::configureManagedOpenVpn()
{
    if (m_tearingDown || m_exitPending || m_program != amnezia::PermittedProcess::OpenVPN
        || m_process->state() != QProcess::NotRunning) return false;
    if (nativeOpenVpnOwner && nativeOpenVpnOwner != this) {
        auto *previous = nativeOpenVpnOwner.data();
        // A GUI can disappear between configure and start. Replacing an
        // unstarted, untouched reservation cannot break an existing connection.
        if (previous->m_process->state() == QProcess::NotRunning && !previous->m_exitPending
            && previous->m_dnsSession && previous->m_dnsSession->cleanupConfirmed())
            previous->stopManaged();
    }
    if (nativeOpenVpnOwner && nativeOpenVpnOwner != this) return false;
#ifdef Q_OS_WIN
    if (!m_process->nativeArguments().isEmpty()) return false;
#endif
    if (m_dnsSession && !managedOpenVpnStopped()) return false;
    m_dnsSession = std::make_unique<OpenVpnDnsSession>(OpenVpnDnsSession::Operations{
        [this](const QString &owner, const QJsonObject &metadata) {
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
            if (!m_openVpnDevice || metadata.value("dev").toString() != m_openVpnDevice->arguments().value(1))
                return false;
#endif
            return !m_tearingDown && m_process->state() == QProcess::Running
                && m_program == amnezia::PermittedProcess::OpenVPN && nativeOpenVpnOwner == this
                && Router::publishOpenVpnDns(owner, metadata);
        },
        [](const QString &owner) { return Router::restoreResolvers(owner); }
    });
    if (!m_dnsSession->start()) { m_dnsSession.reset(); return false; }
    m_managedFailureReported = false;
    nativeOpenVpnOwner = this;
    connect(m_dnsSession.get(), &OpenVpnDnsSession::managementLine, this, &IpcServerProcess::managedOpenVpnLine);
    connect(m_dnsSession.get(), &OpenVpnDnsSession::failed, this, &IpcServerProcess::reportManagedFailure);
    connect(m_dnsSession.get(), &OpenVpnDnsSession::cleanupFinished, this,
        &IpcServerProcess::finishPending, Qt::QueuedConnection);
    const auto terminateAfterGrace = [this] {
        // Native closes management just before normal process exit. Do not turn
        // that orderly socket close into a QProcess crash by killing immediately.
        // Unexpected control loss uses the same bounded, restore-gated deadline.
        const auto owner = m_dnsSession->owner();
        QTimer::singleShot(3000, m_dnsSession.get(), [this, owner] {
            if (m_dnsSession && m_dnsSession->owner() == owner && m_dnsSession->cleanupConfirmed()
                && m_process->state() != QProcess::NotRunning)
                m_process->kill(); // Grace expired, but only after verified DNS/alias cleanup.
        });
    };
    connect(m_dnsSession.get(), &OpenVpnDnsSession::disconnectedAfterRestore, this, terminateAfterGrace);
    connect(m_dnsSession.get(), &OpenVpnDnsSession::stopRestored, this, terminateAfterGrace);
    const auto owner = m_dnsSession->owner();
    Router::connectNativeDnsFailure(m_dnsSession.get(), [this, owner](const QString &failedOwner) {
        if (m_dnsSession && owner == m_dnsSession->owner() && failedOwner == owner)
            m_dnsSession->guardFailed();
    });
    return true;
}

bool IpcServerProcess::managedOpenVpnCommand(const QString &command)
{
    return !m_tearingDown && m_dnsSession && m_dnsSession->command(command);
}

bool IpcServerProcess::managedOpenVpnStopped()
{
    return m_process->state() == QProcess::NotRunning && !m_exitPending
        && (!m_dnsSession || m_dnsSession->cleanupConfirmed())
        && nativeOpenVpnOwner != this;
}

bool IpcServerProcess::processStopped()
{
    return m_process->state() == QProcess::NotRunning && !m_exitPending;
}

int IpcServerProcess::confirmedExitCode()
{
    return m_hasProcessResult && processStopped() && m_exitStatus == QProcess::NormalExit
        ? m_exitCode : -1;
}

void IpcServerProcess::stopManaged()
{
    if (m_tearingDown) return;
    m_dnsSession->requestStop();
    if (m_process->state() == QProcess::NotRunning) {
        m_dnsSession->nativeFinished();
        if (!m_exitPending && m_dnsSession->cleanupConfirmed() && nativeOpenVpnOwner == this)
            nativeOpenVpnOwner.clear();
    }
}

bool IpcServerProcess::cleanupNativeResources()
{
#ifdef Q_OS_WIN
    m_windowsIpv6Routes.reset();
#endif
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
    m_ipv6Routes.reset();
    if (m_openVpnDevice && !m_openVpnDevice->cleanup()) return false;
    m_openVpnDevice.reset();
#endif
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    m_macIpv6Routes.reset();
#endif
    return true;
}

void IpcServerProcess::finishNativeProcess(int code, QProcess::ExitStatus status)
{
    m_hasProcessResult = true;
    m_exitPending = true;
    m_exitCode = code;
    m_exitStatus = status;
    if (m_dnsSession && (code != 0 || status != QProcess::NormalExit)) reportManagedFailure();
    if (m_dnsSession && !m_dnsSession->nativeFinished()) return;
    finishPending();
}

void IpcServerProcess::reportManagedFailure()
{
    if (m_managedFailureReported) return;
    m_managedFailureReported = true;
    emit managedOpenVpnFailed();
}

void IpcServerProcess::finishPending()
{
    if (!m_exitPending || m_tearingDown || (m_dnsSession && !m_dnsSession->cleanupConfirmed())) return;
    if (!cleanupNativeResources()) {
        QTimer::singleShot(250, this, &IpcServerProcess::finishPending);
        return;
    }
    m_exitPending = false;
    if (nativeOpenVpnOwner == this) nativeOpenVpnOwner.clear();
    emit finished(m_exitCode, m_exitStatus);
}

bool IpcServerProcess::addOpenVpnIpv6Hosts(const QString &localIpv4, const QStringList &hosts, bool throughVpn)
{
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
    if (m_program != amnezia::PermittedProcess::OpenVPN || m_process->state() != QProcess::Running) return false;
    if (!m_ipv6Routes) m_ipv6Routes = std::make_unique<LinuxOpenVpnIpv6Routes>();
    return m_ipv6Routes->add(localIpv4, hosts, throughVpn);
#elif defined(Q_OS_WIN)
    if (m_program != amnezia::PermittedProcess::OpenVPN || m_process->state() != QProcess::Running) return false;
    if (!m_windowsIpv6Routes) m_windowsIpv6Routes = std::make_unique<WindowsOpenVpnIpv6Routes>(
        amnezia::windowsOpenVpnIpv6::nativeApi());
    return m_windowsIpv6Routes->add(localIpv4, hosts, throughVpn);
#elif defined(Q_OS_MACOS) && !defined(MACOS_NE)
    if (m_program != amnezia::PermittedProcess::OpenVPN || m_process->state() != QProcess::Running
        || !m_macIpv6Routes) return false;
    return m_macIpv6Routes->add(localIpv4, hosts, throughVpn);
#else
    Q_UNUSED(localIpv4)
    Q_UNUSED(hosts)
    Q_UNUSED(throughVpn)
    return false;
#endif
}

void IpcServerProcess::setArguments(const QStringList &arguments)
{
    if (m_tearingDown || m_exitPending || m_process->state() != QProcess::NotRunning) return;
    m_arguments = amnezia::sanitizeArguments(m_program, arguments);
    m_process->setArguments(m_arguments);
}

void IpcServerProcess::setInputChannelMode(QProcess::InputChannelMode mode)
{
     m_process->setInputChannelMode(mode);
}

void IpcServerProcess::setNativeArguments(const QString &arguments)
{
    if (m_tearingDown || m_dnsSession || m_process->state() != QProcess::NotRunning) return;
#ifdef Q_OS_WIN
    m_process->setNativeArguments(arguments);
#endif
}

void IpcServerProcess::setProcessChannelMode(QProcess::ProcessChannelMode mode)
{
    m_process->setProcessChannelMode(mode);
}

void IpcServerProcess::setProgram(int programId)
{
    if (m_tearingDown || m_exitPending || m_process->state() != QProcess::NotRunning
        || (m_dnsSession && !managedOpenVpnStopped())) return;
    m_dnsSession.reset();
    Q_ASSERT(programId > static_cast<int>(amnezia::PermittedProcess::Invalid) &&
             programId < static_cast<int>(amnezia::PermittedProcess::PermittedProcessCount));
    m_program = static_cast<amnezia::PermittedProcess>(programId);
    m_process->setProgram(amnezia::permittedProcessPath(m_program));
    m_arguments.clear();
    m_process->setArguments({});
}

void IpcServerProcess::setWorkingDirectory(const QString &dir)
{
    m_process->setWorkingDirectory(dir);
}

QByteArray IpcServerProcess::readAll()
{
    return m_process->readAll();
}

QByteArray IpcServerProcess::readAllStandardError()
{
    return m_process->readAllStandardError();
}

QByteArray IpcServerProcess::readAllStandardOutput()
{
    return m_process->readAllStandardOutput();
}

bool IpcServerProcess::waitForStarted() {
    return m_process->waitForStarted();
}

bool IpcServerProcess::waitForStarted(int msecs) {
    return m_process->waitForStarted(msecs);
}

bool IpcServerProcess::waitForFinished() {
    return m_process->waitForFinished();
}

bool IpcServerProcess::waitForFinished(int msecs) {
    return m_process->waitForFinished(msecs);
}

#endif
