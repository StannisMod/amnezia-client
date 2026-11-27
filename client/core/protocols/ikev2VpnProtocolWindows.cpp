#include <QCoreApplication>
#include <QFileInfo>
#include <QFile>
#include <QProcess>

#include <QThread>
#include <QHostInfo>
#include <QUuid>
#include <QScopedValueRollback>
#include <vector>
#include "ikev2CredentialFile.h"
#include <QElapsedTimer>

#include <chrono>

#include "ipc.h"
#include "logger.h"
#include "ikev2VpnProtocolWindows.h"
#include "core/utils/utilities.h"
#include "core/protocols/protocolUtils.h"


static Ikev2Protocol* self = nullptr;
static std::mutex rasDialFuncMutex;

extern "C" {
static void WINAPI RasDialFuncCallback(UINT unMsg,
                                       RASCONNSTATE rasconnstate,
                                       DWORD dwError );
}

Ikev2Protocol::Ikev2Protocol(const QJsonObject &configuration, QObject* parent) :
    VpnProtocol(configuration, parent)
{
    self = this;
    readIkev2Configuration(configuration);
    m_dnsWatch.setParent(this);
    m_dnsWatch.setInterval(250);
    connect(&m_dnsWatch, &QTimer::timeout, this, &Ikev2Protocol::pollManagedDns);
    connect(this, &VpnProtocol::connectionStateChanged, this, [this](Vpn::ConnectionState state) {
        if (state != Vpn::ConnectionState::Disconnected || connectionState() != state
            || !m_nativeIpv6PolicyApplied) return;
        if (setNativeIpv6Blocked(false)) m_nativeIpv6PolicyApplied = false;
        else emit protocolError(ErrorCode::AmneziaServiceConnectionFailed);
    }, Qt::QueuedConnection);
}

Ikev2Protocol::~Ikev2Protocol()
{
    qDebug() << "IpsecProtocol::~IpsecProtocol()";
    Ikev2Protocol::stop();
    std::lock_guard<std::mutex> guard(rasDialFuncMutex);
    if (self == this) self = nullptr;
}

void Ikev2Protocol::stop()
{
    setConnectionState(Vpn::ConnectionState::Disconnecting);
    if (!m_dnsOwner.isEmpty()) {
        m_managedStopRequested = true;
        m_dnsWatch.start();
        pollManagedDns();
        return;
    }
    {
        if (!disconnect_vpn()){
            qDebug()<<"We don't disconnect";
            setConnectionState(Vpn::ConnectionState::Error);
        }
        else {
            if (m_nativeIpv6PolicyApplied && !setNativeIpv6Blocked(false)) {
                setLastError(ErrorCode::AmneziaServiceConnectionFailed);
                setConnectionState(Vpn::ConnectionState::Error);
                return;
            }
            m_nativeIpv6PolicyApplied = false;
            setConnectionState(Vpn::ConnectionState::Disconnected);
        }
    }
}

void Ikev2Protocol::newConnectionStateEventReceived(UINT unMsg, tagRASCONNSTATE rasconnstate, DWORD dwError)
{
    Q_UNUSED(unMsg);
    qDebug()<<"Receive the new event "<<static_cast<int>(rasconnstate);
    switch (rasconnstate)
    {
    case RASCS_OpenPort:
        //qDebug()<<__FUNCTION__ << __LINE__;
        setConnectionState(Vpn::ConnectionState::Preparing);
        break;
    case RASCS_PortOpened:
        //qDebug()<<__FUNCTION__ << __LINE__;
        setConnectionState(Vpn::ConnectionState::Preparing);
        break;
    case RASCS_ConnectDevice:
        //qDebug()<<__FUNCTION__ << __LINE__;
        setConnectionState(Vpn::ConnectionState::Preparing);
        break;
    case RASCS_DeviceConnected:
        //qDebug()<<__FUNCTION__ << __LINE__;
        setConnectionState(Vpn::ConnectionState::Preparing);
        break;
    case RASCS_AllDevicesConnected:
        //qDebug()<<__FUNCTION__ << __LINE__;
        setConnectionState(Vpn::ConnectionState::Preparing);
        break;
    case RASCS_Authenticate:
        //qDebug()<<__FUNCTION__ << __LINE__;
        setConnectionState(Vpn::ConnectionState::Preparing);
        break;
    case RASCS_AuthNotify:
        //qDebug()<<__FUNCTION__ << __LINE__;
        if (dwError != 0) {
            qDebug() << "have error" << dwError;
            setConnectionState(Vpn::ConnectionState::Disconnected);
        } else {
            qDebug() << "RASCS_AuthNotify but no error" << dwError;
        }
        break;
    case RASCS_AuthRetry:
        //qDebug()<<__FUNCTION__ << __LINE__;
        setConnectionState(Vpn::ConnectionState::Preparing);
        break;
    case RASCS_AuthCallback:
        qDebug()<<__FUNCTION__ << __LINE__;
        break;
    case RASCS_AuthChangePassword:
        qDebug()<<__FUNCTION__ << __LINE__;
        break;
    case RASCS_AuthProject:
        qDebug()<<__FUNCTION__ << __LINE__;
        break;
    case RASCS_AuthLinkSpeed:
        qDebug()<<__FUNCTION__ << __LINE__;
        break;
    case RASCS_AuthAck:
        qDebug()<<__FUNCTION__ << __LINE__;
        break;
    case RASCS_ReAuthenticate:
        //qDebug()<<__FUNCTION__ << __LINE__;
        break;
    case RASCS_Authenticated:
        //qDebug()<<__FUNCTION__ << __LINE__;
        break;
    case RASCS_PrepareForCallback:
        qDebug()<<__FUNCTION__ << __LINE__;
        break;
    case RASCS_WaitForModemReset:
        qDebug()<<__FUNCTION__ << __LINE__;
        break;
    case RASCS_WaitForCallback:
        qDebug()<<__FUNCTION__ << __LINE__;
        break;
    case RASCS_Projected:
        qDebug()<<__FUNCTION__ << __LINE__;
        break;
#if (WINVER >= 0x400)
    case RASCS_StartAuthentication:    // Windows 95 only
        qDebug()<<__FUNCTION__ << __LINE__;
        break;
    case RASCS_CallbackComplete:       // Windows 95 only
        qDebug()<<__FUNCTION__ << __LINE__;
        break;
    case RASCS_LogonNetwork:           // Windows 95 only
        qDebug()<<__FUNCTION__ << __LINE__;
        break;
#endif
    case RASCS_SubEntryConnected:
        qDebug()<<__FUNCTION__ << __LINE__;
        break;
    case RASCS_SubEntryDisconnected:
        qDebug()<<__FUNCTION__ << __LINE__;
        break;
        //PAUSED STATES:
    case RASCS_Interactive:
        qDebug()<<__FUNCTION__ << __LINE__;
        break;
    case RASCS_RetryAuthentication:
        qDebug()<<__FUNCTION__ << __LINE__;
        break;
    case RASCS_CallbackSetByCaller:
        qDebug()<<__FUNCTION__ << __LINE__;
        break;
    case RASCS_PasswordExpired:
        setConnectionState(Vpn::ConnectionState::Error);
        qDebug()<<__FUNCTION__ << __LINE__;
        break;

    case RASCS_Connected: // = RASCS_DONE:
        setConnectionState(Vpn::ConnectionState::Connected);
        //qDebug()<<__FUNCTION__ << __LINE__;
        break;
    case RASCS_Disconnected:
        setConnectionState(Vpn::ConnectionState::Disconnected);
        //qDebug()<<__FUNCTION__ << __LINE__;
        break;
    default:
        //qDebug()<<__FUNCTION__ << __LINE__;
        break;
    }
}

void Ikev2Protocol::readIkev2Configuration(const QJsonObject &configuration)
{
    m_config = configuration.value(ProtocolUtils::key_proto_config_data(Proto::Ikev2)).toObject();
    m_ipv6Enabled = configuration.value("ipv6_enabled").toBool(true);
}

bool Ikev2Protocol::setNativeIpv6Blocked(bool blocked)
{
    QStringList endpoints;
    if (blocked) {
        const auto host = QHostInfo::fromName(m_config.value(configKey::hostName).toString());
        if (host.error() != QHostInfo::NoError || host.addresses().isEmpty()) return false;
        for (const auto &address : host.addresses()) endpoints << address.toString();
        endpoints.removeDuplicates();
    }
    auto service = IpcClient::Interface();
    if (!service || !service->isInitialized()) return false;
    auto reply = service->setNativeIpv6Blocked(blocked, endpoints);
    return reply.waitForFinished() && reply.returnValue();
}

ErrorCode Ikev2Protocol::start()
{
    if (!m_dnsOwner.isEmpty()) return ErrorCode::AmneziaServiceConnectionFailed;
    QByteArray cert = QByteArray::fromBase64(m_config[configKey::cert].toString().toUtf8());
    setConnectionState(Vpn::ConnectionState::Connecting);

    Ikev2CredentialFile certFile(cert);
    if (!certFile.isValid()) {
        setLastError(ErrorCode::InternalError);
        return ErrorCode::InternalError;
    }
    const QString m_filename = certFile.path();

    {
        auto certInstallProcess = IpcClient::CreatePrivilegedProcess();

        if (!certInstallProcess) {
            setLastError(ErrorCode::AmneziaServiceConnectionFailed);
            return ErrorCode::AmneziaServiceConnectionFailed;
        }

        certInstallProcess->waitForSource();
        if (!certInstallProcess->isInitialized()) {
            qWarning() << "IpcProcess replica is not connected!";
            setLastError(ErrorCode::AmneziaServiceConnectionFailed);
            return ErrorCode::AmneziaServiceConnectionFailed;
        }
        certInstallProcess->setProgram(PermittedProcess::CertUtil);

        QStringList arguments({"-f", "-importpfx", "-p", m_config[configKey::password].toString(),
            QDir::toNativeSeparators(m_filename), "NoExport"
        });

        certInstallProcess->setArguments(arguments);
        certInstallProcess->start();
        // Import and native dial use the same existing service/machine store.
        // An enqueued start or a fast-finished QProcess wait is not an import
        // success proof; ask for its confirmed normal exit code explicitly.
        auto waited = certInstallProcess->waitForFinished(15000);
        if (!waited.waitForFinished()) {
            setLastError(ErrorCode::AmneziaServiceConnectionFailed);
            return ErrorCode::AmneziaServiceConnectionFailed;
        }
        auto imported = certInstallProcess->confirmedExitCode();
        if (!imported.waitForFinished() || imported.returnValue() != 0) {
            auto output = certInstallProcess->readAllStandardOutput();
            auto error = certInstallProcess->readAllStandardError();
            QString diagnostic;
            if (output.waitForFinished(1000)) diagnostic += QString::fromLocal8Bit(output.returnValue());
            if (error.waitForFinished(1000)) diagnostic += QString::fromLocal8Bit(error.returnValue());
            const auto password = m_config[configKey::password].toString();
            if (!password.isEmpty()) diagnostic.replace(password, "[redacted]");
            qWarning() << "Native IKEv2 certificate import failed:" << diagnostic;
            certInstallProcess->terminate();
            setLastError(ErrorCode::AmneziaServiceConnectionFailed);
            return ErrorCode::AmneziaServiceConnectionFailed;
        }
    }
    // /*
    {
        if ( disconnect_vpn()){
            qDebug()<<"VPN was disconnected";
        }
        if ( delete_vpn_connection (tunnelName())){
            qDebug()<<"VPN was deleted";
        }
    }

    {
     {
       // OFF protection belongs to the service-owned RAS/DNS lifecycle. The
       // GUI must not release it before that service confirms native join.
       if (m_ipv6Enabled && !setNativeIpv6Blocked(false)) {
           setLastError(ErrorCode::AmneziaServiceConnectionFailed);
           return ErrorCode::AmneziaServiceConnectionFailed;
       }
       m_nativeIpv6PolicyApplied = false;
       if ( !create_new_vpn(tunnelName(), m_config[configKey::hostName].toString())){
           stop();
           return ErrorCode::InternalError;
}
}
}

{
    QProcess adapterConfigProcess;
    adapterConfigProcess.setProgram("powershell");
    QString command = QString("$ErrorActionPreference='Stop'; Set-VpnConnectionIPsecConfiguration "
                                "-ConnectionName '%1' "
                                "-AuthenticationTransformConstants GCMAES128 "
                                "-CipherTransformConstants GCMAES128 "
                                "-EncryptionMethod AES256 "
                                "-IntegrityCheckMethod SHA256 "
                                "-PfsGroup PFS2048 "
                                "-DHGroup Group14 "
                                 "-PassThru -Force")
                            .arg(tunnelName());

    adapterConfigProcess.setArguments({"-NoProfile", "-NonInteractive", "-Command", command});
    adapterConfigProcess.start();
    if (!adapterConfigProcess.waitForFinished(10000)
            || adapterConfigProcess.exitStatus() != QProcess::NormalExit
            || adapterConfigProcess.exitCode() != 0) {
        qWarning() << "Native IKEv2 IPsec profile configuration failed"
                   << adapterConfigProcess.readAllStandardError();
        stop();
        setLastError(ErrorCode::InternalError);
        return ErrorCode::InternalError;
    }
}
//*/
{
    if (!connect_to_vpn(tunnelName())) {
        qDebug()<<"We can't connect to VPN";
        stop();
        return ErrorCode::InternalError;
    }
}
//setConnectionState(Connecting);
return ErrorCode::NoError;
}
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
bool Ikev2Protocol::create_new_vpn(const QString & vpn_name,
                                   const QString & serv_addr){

    if ( RasValidateEntryName(nullptr, vpn_name.toStdWString().c_str()) != ERROR_SUCCESS)
        return false;
    DWORD size = 0;
    ::RasGetEntryProperties(nullptr, L"", nullptr, &size, nullptr, nullptr);
    LPRASENTRY pras = static_cast<LPRASENTRY>(malloc(size));
    memset(pras, 0, size);
    pras->dwSize = size;
    pras->dwType = RASET_Vpn;
    pras->dwRedialCount = 1;
    pras->dwRedialPause = 60;
    pras->dwfNetProtocols = RASNP_Ip | (m_ipv6Enabled ? RASNP_Ipv6 : 0);
    pras->dwEncryptionType = ET_RequireMax;
    wcscpy_s(pras->szLocalPhoneNumber, serv_addr.toStdWString().c_str());
    wcscpy_s(pras->szDeviceType, RASDT_Vpn);
    pras->dwfOptions = RASEO_RemoteDefaultGateway;
    pras->dwfOptions |= RASEO_RequireDataEncryption;
    pras->dwfOptions2 |= RASEO2_RequireMachineCertificates;
    if (m_ipv6Enabled) pras->dwfOptions2 |= RASEO2_IPv6RemoteDefaultGateway;
    pras->dwVpnStrategy = VS_Ikev2Only;
    const auto nRet = ::RasSetEntryProperties(nullptr, vpn_name.toStdWString().c_str(), pras, pras->dwSize, NULL, 0);
    free(pras);
    if (nRet == ERROR_SUCCESS)
        return true;
    return false;
}
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
bool Ikev2Protocol::delete_vpn_connection(const QString &vpn_name){

    if ( RasDeleteEntry(nullptr, vpn_name.toStdWString().c_str()) == ERROR_SUCCESS){
        return true;
    }
    return false;
}
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
bool Ikev2Protocol::connect_to_vpn(const QString & vpn_name){
    if (!m_ipv6Enabled) return startManagedDns();
    RASDIALPARAMS RasDialParams;
    memset(&RasDialParams, 0x0, sizeof(RASDIALPARAMS));
    RasDialParams.dwSize = sizeof(RASDIALPARAMS);
    wcscpy_s(RasDialParams.szEntryName, vpn_name.toStdWString().c_str());
    auto ret = RasDial(NULL, NULL, &RasDialParams, 0,
                       &RasDialFuncCallback,
                       &hRasConn);

    if (ret == ERROR_SUCCESS){
        return true;
    }
    return false;
}

bool Ikev2Protocol::startManagedDns()
{
    // Ask RAS for the actual user's PBK path; never guess a system/default
    // phonebook or let the service silently select a different profile.
    DWORD size = sizeof(RASENTRYNAMEW), count = 0;
    std::vector<RASENTRYNAMEW> entries(1);
    entries[0].dwSize = sizeof(RASENTRYNAMEW);
    auto result = RasEnumEntriesW(nullptr, nullptr, entries.data(), &size, &count);
    if (result == ERROR_BUFFER_TOO_SMALL && size <= 1024 * 1024) {
        entries.assign((size + sizeof(RASENTRYNAMEW) - 1) / sizeof(RASENTRYNAMEW), {});
        entries[0].dwSize = sizeof(RASENTRYNAMEW);
        result = RasEnumEntriesW(nullptr, nullptr, entries.data(), &size, &count);
    }
    if (result != ERROR_SUCCESS || count > entries.size()) return false;
    QString phonebook;
    for (DWORD i = 0; i < count; ++i) {
        if (QString::fromWCharArray(entries[i].szEntryName) != tunnelName()) continue;
        const auto path = QString::fromWCharArray(entries[i].szPhonebookPath);
        if (!phonebook.isEmpty() || !QFileInfo(path).isFile()) return false;
        phonebook = path;
    }
    if (phonebook.isEmpty()) return false;
    QFile profile(phonebook);
    if (!profile.open(QIODevice::ReadOnly) || profile.size() > 1024 * 1024) return false;
    const auto bytes = profile.readAll();
    if (bytes.isEmpty() || profile.error() != QFileDevice::NoError) return false;
    const auto host = QHostInfo::fromName(m_config.value(configKey::hostName).toString());
    if (host.error() != QHostInfo::NoError || host.addresses().isEmpty()) return false;
    QStringList endpoints;
    for (const auto &ip : host.addresses()) endpoints.append(ip.toString());
    endpoints.removeDuplicates();
    auto service = IpcClient::Interface();
    if (!service || !service->isInitialized()) return false;
    m_dnsOwner = QUuid::createUuid().toString(QUuid::WithoutBraces);
    m_managedStopRequested = m_managedAdmissionRefused = m_managedFailureReported = false;
    m_dnsWatch.start();
    auto reply = service->startIkev2Dns(m_dnsOwner, bytes, endpoints);
    const bool received = reply.waitForFinished();
    qInfo() << "Native IKEv2 admission reply received:" << received
            << "accepted:" << (received && reply.returnValue())
            << "stop already requested:" << m_managedStopRequested;
    if (received && !reply.returnValue()) m_managedAdmissionRefused = true;
    if (!received || !reply.returnValue()) {
        // Lost reply may have started native RAS. Preserve the generation and
        // retry service cleanup, never issue a GUI-side RasHangUp/IPv6 reset.
        m_managedStopRequested = true;
        setLastError(ErrorCode::AmneziaServiceConnectionFailed);
        return false;
    }
    return true;
}

void Ikev2Protocol::pollManagedDns()
{
    if (m_dnsOwner.isEmpty() || m_managedPollInProgress) return;
    QScopedValueRollback<bool> inProgress(m_managedPollInProgress, true);
    const auto owner = m_dnsOwner;
    auto service = IpcClient::Interface();
    if (!service || !service->isInitialized()) return;
    if (m_managedStopRequested) {
        auto stopped = service->stopIkev2Dns(owner);
        if (!stopped.waitForFinished() || owner != m_dnsOwner) return;
        // Only the state query below authorizes Connected/Disconnected.
    }
    auto reply = service->ikev2DnsState(owner);
    if (!reply.waitForFinished() || owner != m_dnsOwner) return;
    const auto state = reply.returnValue();
    if (state == "stopped" || (state == "unknown" && m_managedAdmissionRefused)) {
        if (state == "stopped") service->acknowledgeIkev2DnsStopped(owner);
        m_dnsWatch.stop();
        m_dnsOwner.clear();
        setConnectionState(Vpn::ConnectionState::Disconnected);
    } else if (state == "connected" && !m_managedStopRequested) {
        setConnectionState(Vpn::ConnectionState::Connected);
    } else if (state == "stopping" || state == "unknown") {
        qWarning() << "Native IKEv2 poll requires cleanup; state:" << state
                   << "stop already requested:" << m_managedStopRequested;
        const bool unexpected = !m_managedStopRequested || state == "unknown";
        m_managedStopRequested = true;
        setConnectionState(Vpn::ConnectionState::Disconnecting);
        if (unexpected && !m_managedFailureReported) {
            m_managedFailureReported = true;
            setLastError(ErrorCode::AmneziaServiceConnectionFailed);
            emit protocolError(ErrorCode::AmneziaServiceConnectionFailed);
        }
    }
}
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
bool Ikev2Protocol::disconnect_vpn(){
    if (!hRasConn) return true;
    RASCONNSTATUSW status{};
    status.dwSize = sizeof(status);
    auto observed = RasGetConnectStatusW(hRasConn, &status);
    if (observed == ERROR_INVALID_HANDLE) {
        hRasConn = nullptr;
        return true;
    }
    if (observed != ERROR_SUCCESS) return false;
    const auto result = RasHangUpW(hRasConn);
    qDebug() << "RasHangUp" << result;
    QElapsedTimer deadline;
    deadline.start();
    while (true) {
        status = {};
        status.dwSize = sizeof(status);
        observed = RasGetConnectStatusW(hRasConn, &status);
        if (observed == ERROR_INVALID_HANDLE) {
            hRasConn = nullptr;
            return true;
        }
        if (result != ERROR_SUCCESS || observed != ERROR_SUCCESS || deadline.elapsed() >= 5000)
            return false;
        QThread::msleep(25);
    }
}

void WINAPI RasDialFuncCallback(UINT unMsg,
                                RASCONNSTATE rasconnstate,
                                DWORD dwError ){
    std::lock_guard<std::mutex> guard(rasDialFuncMutex);
    if (self) {
        self->newConnectionStateEventReceived(unMsg, rasconnstate, dwError);
    }
}
