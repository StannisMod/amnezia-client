#include "ipcserverprocess.h"
#include "ipc.h"
#include <QProcess>

#ifndef Q_OS_IOS

IpcServerProcess::IpcServerProcess(QObject *parent) :
    IpcProcessInterfaceSource(parent),
    m_process(QSharedPointer<QProcess>(new QProcess()))
{
    connect(m_process.data(), &QProcess::errorOccurred, this, &IpcServerProcess::errorOccurred);
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
    // Restore routing before notifying clients, which may immediately restart.
    connect(m_process.data(), QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this,
            [this] {
                m_ipv6Routes.reset();
                if (m_openVpnDevice && !m_openVpnDevice->cleanup())
                    qWarning() << "Failed to remove owned OpenVPN DCO device";
                m_openVpnDevice.reset();
            });
#endif
#ifdef Q_OS_WIN
    connect(m_process.data(), QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this,
            [this] { m_windowsIpv6Routes.reset(); });
#endif
    connect(m_process.data(), QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this, &IpcServerProcess::finished);
    connect(m_process.data(), &QProcess::readyRead, this, &IpcServerProcess::readyRead);
    connect(m_process.data(), &QProcess::readyReadStandardError, this, &IpcServerProcess::readyReadStandardError);
    connect(m_process.data(), &QProcess::readyReadStandardOutput, this, &IpcServerProcess::readyReadStandardOutput);
    connect(m_process.data(), &QProcess::started, this, &IpcServerProcess::started);
    connect(m_process.data(), &QProcess::stateChanged, this, &IpcServerProcess::stateChanged);

    connect(m_process.data(), &QProcess::errorOccurred, [&](QProcess::ProcessError error){
        qDebug() << "IpcServerProcess errorOccurred " << error;
    });

}

IpcServerProcess::~IpcServerProcess()
{
    m_process->disconnect(this);
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
    qDebug() << "IpcServerProcess::~IpcServerProcess";
}

void IpcServerProcess::start()
{
    if (m_process->state() != QProcess::NotRunning) return;
    m_process->setArguments(m_arguments);
#ifdef Q_OS_WIN
    m_windowsIpv6Routes.reset();
#endif
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
    m_ipv6Routes.reset();
    m_openVpnDevice.reset();
    if (m_program == amnezia::PermittedProcess::OpenVPN) {
        m_openVpnDevice = std::make_unique<LinuxOpenVpnDevice>();
        m_process->setArguments(m_arguments + m_openVpnDevice->arguments());
    }
#endif
    if (m_process->program().isEmpty()) {
        qDebug() << "IpcServerProcess failed to start, program is empty";
    }

    Utils::killProcessByName(m_process->program());
    m_process->start();
    qDebug() << "IpcServerProcess started, " << m_process->program() << m_process->arguments();

    m_process->waitForStarted();
}

void IpcServerProcess::terminate() {
    m_process->terminate();
}

void IpcServerProcess::kill() {
    m_process->kill();
}

void IpcServerProcess::close()
{
    m_process->close();
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
#else
    Q_UNUSED(localIpv4)
    Q_UNUSED(hosts)
    Q_UNUSED(throughVpn)
    return false;
#endif
}

void IpcServerProcess::setArguments(const QStringList &arguments)
{
    m_arguments = amnezia::sanitizeArguments(m_program, arguments);
    m_process->setArguments(m_arguments);
}

void IpcServerProcess::setInputChannelMode(QProcess::InputChannelMode mode)
{
     m_process->setInputChannelMode(mode);
}

void IpcServerProcess::setNativeArguments(const QString &arguments)
{
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
