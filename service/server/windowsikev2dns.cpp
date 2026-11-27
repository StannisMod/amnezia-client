#include "windowsikev2dns.h"
#include <fwpmu.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <raserror.h>
#include <QDir>
#include <QFileInfo>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QSaveFile>
#include <QStandardPaths>
#include <QCryptographicHash>
#include <QElapsedTimer>
#include <QScopeGuard>
#include <QThread>
#include <QMap>
#include <QDebug>
#include <optional>
#include <QUuid>
#include <cstring>
#include <cwchar>
#include <iterator>
#include <vector>
#include "killswitch.h"
#include "nativednsservice.h"
#include "platforms/windows/daemon/nativednsfirewall.h"
#include "platforms/windows/daemon/dnsutilswindows.h"

namespace {
constexpr wchar_t entryName[] = L"AmneziaVPN IKEv2";

bool validProfile(const QString &phonebook, QUuid *entryId = nullptr)
{
    if (!QDir::isAbsolutePath(phonebook) || phonebook.contains(QChar(0))
            || !QFileInfo(phonebook).isFile()) return false;
    DWORD size = sizeof(RASENTRYW);
    std::vector<BYTE> buffer(size);
    reinterpret_cast<RASENTRYW *>(buffer.data())->dwSize = sizeof(RASENTRYW);
    auto result = RasGetEntryPropertiesW(reinterpret_cast<LPCWSTR>(phonebook.utf16()),
        entryName, reinterpret_cast<RASENTRYW *>(buffer.data()), &size, nullptr, nullptr);
    if (result == ERROR_BUFFER_TOO_SMALL && size <= 1024 * 1024 && size >= sizeof(RASENTRYW)) {
        buffer.assign(size, 0);
        reinterpret_cast<RASENTRYW *>(buffer.data())->dwSize = sizeof(RASENTRYW);
        result = RasGetEntryPropertiesW(reinterpret_cast<LPCWSTR>(phonebook.utf16()),
            entryName, reinterpret_cast<RASENTRYW *>(buffer.data()), &size, nullptr, nullptr);
    }
    if (result != ERROR_SUCCESS) return false;
    const auto &entry = *reinterpret_cast<const RASENTRYW *>(buffer.data());
    // Refuse scripts/custom dialers and IPv6 negotiation rather than allowing a
    // second publisher or an undocumented privileged IPv6 path during setup.
    const bool valid = entry.dwType == RASET_Vpn && entry.dwVpnStrategy == VS_Ikev2Only
        && entry.dwfNetProtocols == RASNP_Ip
        && entry.dwEncryptionType == ET_RequireMax
        && (entry.dwfOptions & RASEO_RequireDataEncryption)
        && !(entry.dwfOptions & RASEO_RequireEAP)
        && (entry.dwfOptions2 & RASEO2_RequireMachineCertificates)
        && entry.szScript[0] == L'\0' && entry.szCustomDialDll[0] == L'\0';
    if (!valid || QUuid(entry.guidId).isNull()) return false;
    if (entryId) *entryId = QUuid(entry.guidId);
    return true;
}

QString ownershipRoot()
{
    return QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation) + "/ikev2-owned";
}
std::optional<QMap<QString, QJsonObject>> ownedRecords()
{
    QMap<QString, QJsonObject> result;
    if (!prepareNativeDnsPrivateDirectory(ownershipRoot())) return {};
    const auto names = QDir(ownershipRoot()).entryList(QDir::AllEntries | QDir::NoDotAndDotDot
                                                      | QDir::Hidden | QDir::System);
    for (const auto &name : names) {
        const bool journal = name.endsWith(".json");
        const auto token = journal ? name.chopped(5) : name;
        const QUuid id(token);
        const auto directory = ownershipRoot() + "/" + token;
        if (id.isNull() || id.toString(QUuid::WithoutBraces) != token
                || (!journal && (!QFileInfo(directory).isDir()
                    || !names.contains(token + ".json")))) return {};
        if (!journal) continue;
        if (QFileInfo::exists(directory) && !prepareNativeDnsPrivateDirectory(directory)) return {};
        const auto files = QFileInfo::exists(directory)
            ? QDir(directory).entryList(QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System)
            : QStringList{};
        if (!files.isEmpty() && files != QStringList({"rasphone.pbk"})) return {};
        QFile file(ownershipRoot() + "/" + name);
        QFile profile(directory + "/rasphone.pbk");
        if (QFileInfo(file).isSymLink() || QFileInfo(profile).isSymLink()
                || !file.open(QIODevice::ReadOnly) || file.size() > 32768) return {};
        const auto record = QJsonDocument::fromJson(file.readAll()).object();
        const auto phase = record["phase"].toString();
        bool handleValid = false;
        record["native_handle"].toString().toULongLong(&handleValid);
        if (record["version"].toInt() != 1 || record["owner"].toString().isEmpty()
                || !handleValid || !record["endpoints"].isArray()
                || record["endpoints"].toArray().isEmpty()
                || !QStringList({"prepared", "dial-intent", "dial-returned", "started", "projected",
                                 "hangup-requested", "retired", "completed"}).contains(phase)
                || (phase == "projected" && QUuid(record["correlation_id"].toString()).isNull())
                || (files.isEmpty() && phase != "prepared" && phase != "retired" && phase != "completed")
                || (phase == "completed" && QFileInfo::exists(directory)))
            return {};
        if (!files.isEmpty() && phase != "prepared") {
            if (!profile.open(QIODevice::ReadOnly) || profile.size() > 1024 * 1024
                    || record["profile_sha256"].toString() != QString::fromLatin1(
                        QCryptographicHash::hash(profile.readAll(), QCryptographicHash::Sha256).toHex()))
                return {};
        }
        result.insert(directory, record);
    }
    return result;
}
bool activeConnections(std::vector<RASCONNW> &connections)
{
    DWORD count = 0, size = sizeof(RASCONNW);
    connections.assign(1, {});
    connections[0].dwSize = sizeof(RASCONNW);
    auto result = RasEnumConnectionsW(connections.data(), &size, &count);
    if (result == ERROR_BUFFER_TOO_SMALL && size <= 1024 * 1024) {
        connections.assign((size + sizeof(RASCONNW) - 1) / sizeof(RASCONNW), {});
        connections[0].dwSize = sizeof(RASCONNW);
        result = RasEnumConnectionsW(connections.data(), &size, &count);
    }
    if (result != ERROR_SUCCESS || count > connections.size()) return false;
    connections.resize(count);
    return true;
}

QHostAddress address(const SOCKET_ADDRESS &socket)
{
    if (!socket.lpSockaddr) return {};
    if (socket.lpSockaddr->sa_family == AF_INET && socket.iSockaddrLength >= sizeof(sockaddr_in)) {
        const auto *v4 = reinterpret_cast<const sockaddr_in *>(socket.lpSockaddr);
        return QHostAddress(ntohl(v4->sin_addr.s_addr));
    }
    if (socket.lpSockaddr->sa_family == AF_INET6 && socket.iSockaddrLength >= sizeof(sockaddr_in6)) {
        const auto *v6 = reinterpret_cast<const sockaddr_in6 *>(socket.lpSockaddr);
        Q_IPV6ADDR bytes;
        std::memcpy(bytes.c, &v6->sin6_addr, sizeof(bytes.c));
        QHostAddress result(bytes);
        if (v6->sin6_scope_id) result.setScopeId(QString::number(v6->sin6_scope_id));
        return result;
    }
    return {};
}
}

WindowsIkev2Dns::WindowsIkev2Dns(DnsUtils *dns, QObject *parent)
    : QObject(parent), m_dns(dns), m_session({
        [this](const QString &owner) { return begin(owner); },
        [this] { return inspect(); },
        [this](const QString &owner) { return publish(owner); },
        [this](const QString &owner) { return dnsHealthy(owner); },
        [this](const QString &owner) { return restoreDns(owner); },
        [this] { return hangupAndJoin(); },
        [this] { return releaseFence(); },
        [this] { return releaseProtection(); },
    })
{
    m_timer.setParent(this);
    m_timer.setInterval(100);
    connect(&m_timer, &QTimer::timeout, this, [this] {
        if (m_recoveryBlocked) {
            if (m_recoveryDnsRestored) finishRecovery();
        } else m_session.step();
    });
}

DWORD CALLBACK WindowsIkev2Dns::dialNotification(ULONG_PTR context, DWORD, HRASCONN, UINT,
                                                RASCONNSTATE state, DWORD error, DWORD)
{
    auto *self = reinterpret_cast<WindowsIkev2Dns *>(context);
    qInfo() << "Native IKEv2 dial notification:" << int(state) << "error:" << error;
    if (error || state == RASCS_Disconnected) {
        self->m_dialFailed.store(true);
        self->m_dialSettled.store(true);
    } else if (state == RASCS_Connected) self->m_dialSettled.store(true);
    return 1; // Retain notifications through the terminal native dial boundary.
}

bool WindowsIkev2Dns::start(const QString &owner, const QByteArray &bytes,
                           const QStringList &endpoints)
{
    if (m_recoveryBlocked || QUuid(owner).isNull() || owner.size() > 128 || owner.contains(QChar(0))
            || m_completedOwners.contains(owner) || owner == m_session.owner()
            || endpoints.isEmpty() || endpoints.size() > 64 || bytes.isEmpty() || bytes.size() > 1024 * 1024)
        return false;
    const auto current = m_session.state(m_session.owner());
    if (current != Ikev2DnsSession::State::Idle && current != Ikev2DnsSession::State::Stopped)
        return false;
    if (!prepareNativeDnsPrivateDirectory(ownershipRoot())) return false;
    // Snapshot before validation/dial. The caller cannot swap in a privileged
    // script, custom dialer or different profile after the service checks it.
    m_ownedDirectory = ownershipRoot() + "/" + QUuid::createUuid().toString(QUuid::WithoutBraces);
    m_connection = nullptr;
    m_record = QJsonObject{{"version", 1}, {"owner", owner},
        {"profile_sha256", QString::fromLatin1(QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex())},
        {"endpoints", QJsonArray::fromStringList(endpoints)}};
    // The root journal precedes profile creation and outlives directory removal,
    // so crashes at either boundary do not fabricate an unknown/no-owner state.
    if (!storeRecord("prepared")) return false;
    auto discard = qScopeGuard([this] {
        if (!removeRecord() || !storeRecord("completed")) m_recoveryBlocked = true;
        else {
            m_ownedDirectory.clear();
            m_record = {};
        }
    });
    if (!prepareNativeDnsPrivateDirectory(m_ownedDirectory)) return false;
    m_phonebook = m_ownedDirectory + "/rasphone.pbk";
    QSaveFile profile(m_phonebook);
    if (!profile.open(QIODevice::WriteOnly) || profile.write(bytes) != bytes.size() || !profile.commit())
        return false;
    QUuid entryId;
    if (!validProfile(m_phonebook, &entryId)) return false;
    std::vector<RASCONNW> existing;
    if (!activeConnections(existing)) return false;
    for (const auto &connection : existing) {
        // RasDial can reference an already-connected profile. Never acquire
        // another caller's native handle and mistake it for a fresh owner.
        if (QUuid(connection.guidEntry) == entryId
                || QString::fromWCharArray(connection.szEntryName) == QString::fromWCharArray(entryName))
            return false;
    }
    m_record["entry_id"] = entryId.toString();
    if (!storeRecord("prepared") || !m_dns->reserveNativeOwner(owner)) return false;
    discard.dismiss();
    m_endpoints = endpoints;
    m_hangupRequested = m_policyAttempted = false;
    m_lastNativeError = ERROR_SUCCESS;
    m_connection = nullptr;
    m_timer.start();
    return m_session.begin(owner);
}

bool WindowsIkev2Dns::begin(const QString &owner)
{
    m_dialSettled.store(false);
    m_dialFailed.store(false);
    m_nativeHandleObserved = false;
    m_dialAttempted = false;
    m_policyAttempted = true;
    if (!KillSwitch::instance()->setNativeIpv6Blocked(true, m_endpoints)) return false;
    m_fence = NativeDnsFirewall::openSetupFence();
    if (!m_fence) return false;
    if (!prepareExistingScopes(owner)) return false;
    if (!storeRecord("dial-intent")) return false;
    RASDIALPARAMSW parameters{};
    parameters.dwSize = sizeof(parameters);
    parameters.dwCallbackId = reinterpret_cast<ULONG_PTR>(this);
    std::wmemcpy(parameters.szEntryName, entryName, std::size(entryName));
    // Non-null callback selects native asynchronous dialing. The service keeps
    // the returned handle even on failure, until RasHangUp has actually joined.
    m_dialAttempted = true;
    const auto result = RasDialW(nullptr, reinterpret_cast<LPCWSTR>(m_phonebook.utf16()),
        &parameters, 2, reinterpret_cast<LPVOID>(&dialNotification), &m_connection);
    if (result != ERROR_SUCCESS) qWarning() << "Native IKEv2 RasDial failed:" << result;
    if (result != ERROR_SUCCESS) {
        m_dialFailed.store(true);
        m_dialSettled.store(true);
    }
    return storeRecord("dial-returned") && result == ERROR_SUCCESS;
}

bool WindowsIkev2Dns::prepareExistingScopes(const QString &owner)
{
    // WinDNS performs parallel queries on connected networks even when a VPN
    // has the lower metric. Preserve each existing resolver on its own link;
    // never use an underlay resolver as a substitute for negotiated PPP DNS.
    if (!m_existingScopes.empty()) return false;
    ULONG bytes = 0;
    if (GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, nullptr, &bytes) != ERROR_BUFFER_OVERFLOW
            || bytes > 4 * 1024 * 1024) return false;
    std::vector<BYTE> storage(bytes);
    auto *first = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(storage.data());
    if (GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, first, &bytes) != NO_ERROR) return false;
    for (auto *adapter = first; adapter; adapter = adapter->Next) {
        if (adapter->OperStatus != IfOperStatusUp || adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK
                || !adapter->FirstDnsServerAddress) continue;
        if (!adapter->FriendlyName || !adapter->IfIndex || m_existingScopes.size() >= 64) return false;
        QList<QHostAddress> resolvers;
        QJsonArray original;
        for (auto *dns = adapter->FirstDnsServerAddress; dns; dns = dns->Next) {
            const auto ip = address(dns->Address);
            if (ip.isNull() || ip.isMulticast() || ip == QHostAddress(QHostAddress::AnyIPv4)
                    || ip == QHostAddress(QHostAddress::AnyIPv6) || resolvers.size() >= 16) return false;
            resolvers.append(ip);
            original.append(ip.toString());
        }
        const auto name = QString::fromWCharArray(adapter->FriendlyName);
        const QJsonObject metadata{{"protocol", "ikev2-existing-os-scope"},
            {"interface_index", int(adapter->IfIndex)}, {"interface_name", name},
            {"native_dns", original},
            {"dns_suffix", adapter->DnsSuffix ? QString::fromWCharArray(adapter->DnsSuffix) : QString()}};
        // Retain failed/uncertain publication too, until confirmed restore.
        m_existingScopes.push_back(std::make_unique<DnsUtilsWindows>(nullptr));
        if (!m_existingScopes.back()->updateResolvers(name, resolvers, false, owner, metadata)) return false;
    }
    return true;
}

bool WindowsIkev2Dns::dnsHealthy(const QString &owner) const
{
    if (!m_dns->nativeDnsHealthy(owner)) return false;
    for (const auto &scope : m_existingScopes)
        if (!scope->nativeDnsHealthy(owner)) return false;
    return true;
}

bool WindowsIkev2Dns::restoreDns(const QString &owner)
{
    // An external edit can block the first restoration indefinitely. Stop
    // forwarding on every owned scope before attempting any OS mutation.
    bool quiesced = m_dns->quiesceResolvers(owner);
    for (const auto &scope : m_existingScopes)
        if (!scope->quiesceResolvers(owner)) quiesced = false;
    if (!quiesced) return false;
    if (!m_dns->restoreResolvers(owner)) return false;
    while (!m_existingScopes.empty()) {
        if (!m_existingScopes.back()->restoreResolvers(owner)) return false;
        m_existingScopes.pop_back();
    }
    return true;
}

Ikev2DnsSession::NativeState WindowsIkev2Dns::inspect()
{
    // Measured RAS startup can return ERROR_INVALID_HANDLE after RasDial has
    // returned but before its asynchronous worker registers the connection.
    // It is not a join or failure proof while notifications are still dialing.
    if (!m_dialSettled.load()) return Ikev2DnsSession::NativeState::Pending;
    if (m_dialFailed.load()) return Ikev2DnsSession::NativeState::Gone;
    if (!m_connection) {
        qWarning("Native IKEv2 inspection has no dial handle");
        return Ikev2DnsSession::NativeState::Gone;
    }
    RASCONNSTATUSW status{};
    status.dwSize = sizeof(status);
    const auto result = RasGetConnectStatusW(m_connection, &status);
    if (result == ERROR_INVALID_HANDLE) {
        if (!m_nativeHandleObserved) return Ikev2DnsSession::NativeState::Pending;
        qWarning("Native IKEv2 inspection observed invalid dial handle");
        return Ikev2DnsSession::NativeState::Gone;
    }
    if (result != ERROR_SUCCESS) {
        if (m_lastNativeError != result) qWarning() << "Native IKEv2 status query failed:" << result;
        m_lastNativeError = result;
        return Ikev2DnsSession::NativeState::Uncertain;
    }
    if (!m_nativeHandleObserved) {
        m_nativeHandleObserved = true;
        if (!storeRecord("started")) return Ikev2DnsSession::NativeState::Uncertain;
    }
    if (status.dwError || status.rasconnstate == RASCS_Disconnected) {
        qWarning() << "Native IKEv2 terminal state:" << int(status.rasconnstate)
                   << "error:" << status.dwError;
        if (status.dwError && m_lastNativeError != status.dwError)
            qWarning() << "Native IKEv2 connection failed:" << status.dwError;
        m_lastNativeError = status.dwError;
        return Ikev2DnsSession::NativeState::Gone;
    }
    return status.rasconnstate == RASCS_Connected ? Ikev2DnsSession::NativeState::Connected
                                               : Ikev2DnsSession::NativeState::Pending;
}

bool WindowsIkev2Dns::publish(const QString &owner)
{
    DWORD size = sizeof(RAS_PROJECTION_INFO);
    std::vector<BYTE> projection(size);
    reinterpret_cast<RAS_PROJECTION_INFO *>(projection.data())->version = RASAPIVERSION_601;
    auto result = RasGetProjectionInfoEx(m_connection,
        reinterpret_cast<RAS_PROJECTION_INFO *>(projection.data()), &size);
    if (result == ERROR_BUFFER_TOO_SMALL && size >= sizeof(RAS_PROJECTION_INFO) && size <= 1024 * 1024) {
        projection.assign(size, 0);
        reinterpret_cast<RAS_PROJECTION_INFO *>(projection.data())->version = RASAPIVERSION_601;
        result = RasGetProjectionInfoEx(m_connection,
            reinterpret_cast<RAS_PROJECTION_INFO *>(projection.data()), &size);
    }
    if (result != ERROR_SUCCESS) {
        qWarning() << "Native IKEv2 projection query failed:" << result;
        return false;
    }
    const auto &info = *reinterpret_cast<const RAS_PROJECTION_INFO *>(projection.data());
    if (info.type != PROJECTION_INFO_TYPE_IKEv2 || info.ikev2.dwIPv4NegotiationError
            || info.ikev2.dwAuthenticationProtocol != RASIKEv2_AUTH_MACHINECERTIFICATES) return false;
    static_assert(sizeof(info.ikev2.ipv4Address) == sizeof(IN_ADDR));
    IN_ADDR local{};
    std::memcpy(&local, &info.ikev2.ipv4Address, sizeof(local));
    const QHostAddress projected(ntohl(local.s_addr));
    if (projected.isNull() || projected == QHostAddress(QHostAddress::AnyIPv4)) return false;

    ULONG bytes = 0;
    if (GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, nullptr, &bytes) != ERROR_BUFFER_OVERFLOW
            || bytes > 4 * 1024 * 1024) return false;
    std::vector<BYTE> adapters(bytes);
    auto *first = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(adapters.data());
    if (GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, first, &bytes) != NO_ERROR) return false;
    const IP_ADAPTER_ADDRESSES *selected = nullptr;
    for (auto *adapter = first; adapter; adapter = adapter->Next) {
        if (adapter->IfType != IF_TYPE_PPP || adapter->OperStatus != IfOperStatusUp) continue;
        bool ownsProjection = false;
        for (auto *ip = adapter->FirstUnicastAddress; ip; ip = ip->Next)
            if (address(ip->Address) == projected) ownsProjection = true;
        if (!ownsProjection) continue;
        if (selected) return false; // Ambiguous native identity: never use underlay/default DNS.
        selected = adapter;
    }
    if (!selected || !selected->FriendlyName) {
        qWarning("Native IKEv2 has no unique connected PPP DNS interface");
        return false;
    }
    QList<QHostAddress> resolvers;
    QJsonArray original;
    for (auto *dns = selected->FirstDnsServerAddress; dns; dns = dns->Next) {
        const auto ip = address(dns->Address);
        if (ip.isNull() || ip.isMulticast() || ip == QHostAddress(QHostAddress::AnyIPv4)
                || ip == QHostAddress(QHostAddress::AnyIPv6) || resolvers.size() >= 16) return false;
        resolvers.append(ip); // Preserve order and duplicate resolver occurrences.
        original.append(ip.toString());
    }
    if (resolvers.isEmpty()) {
        qWarning("Native IKEv2 has no selected negotiated DNS servers; refusing fallback");
        return false;
    }
    std::vector<RASCONNW> connections;
    if (!activeConnections(connections)) return false;
    const RASCONNW *owned = nullptr;
    for (const auto &connection : connections) {
        if (connection.hrasconn != m_connection) continue;
        if (owned || QString::fromWCharArray(connection.szEntryName) != QString::fromWCharArray(entryName)
                || QFileInfo(QString::fromWCharArray(connection.szPhonebook)).canonicalFilePath()
                    != QFileInfo(m_phonebook).canonicalFilePath()
                || QUuid(connection.guidCorrelationId).isNull()) return false;
        owned = &connection;
    }
    if (!owned) return false;
    m_record["correlation_id"] = QUuid(owned->guidCorrelationId).toString();
    if (!storeRecord("projected")) return false;
    const QString interfaceName = QString::fromWCharArray(selected->FriendlyName);
    const QJsonObject metadata{
        {"protocol", "ikev2"}, {"projected_ipv4", projected.toString()},
        {"interface_index", int(selected->IfIndex)},
        {"interface_name", interfaceName}, {"native_dns", original},
        {"dns_suffix", selected->DnsSuffix ? QString::fromWCharArray(selected->DnsSuffix) : QString()},
        {"authentication_protocol", int(info.ikev2.dwAuthenticationProtocol)},
        {"encryption_method", int(info.ikev2.dwEncryptionMethod)},
        {"correlation_id", m_record["correlation_id"]},
    };
    const bool published = m_dns->updateResolvers(interfaceName, resolvers, false, owner, metadata);
    if (!published) qWarning("Native IKEv2 DNS publication refused");
    return published;
}

bool WindowsIkev2Dns::hangupAndJoin()
{
    if (!m_connection) return !m_dialAttempted || m_dialSettled.load();
    RASCONNSTATUSW status{};
    status.dwSize = sizeof(status);
    auto result = RasGetConnectStatusW(m_connection, &status);
    if (result == ERROR_INVALID_HANDLE) {
        if (!m_nativeHandleObserved && !m_dialFailed.load()) return false;
        if (!m_hangupRequested) {
            // The terminal failed attempt still gets its required cleanup call.
            // Do not call again after a successful hangup: invalid status is
            // already the documented join proof, and RasHangUp need not accept
            // a handle that the first call has finished retiring.
            RasHangUpW(m_connection);
        }
        m_connection = nullptr;
        return true;
    }
    if (result != ERROR_SUCCESS) return false;
    if (!m_nativeHandleObserved) {
        m_nativeHandleObserved = true;
        if (!storeRecord("started")) return false;
    }
    if (!m_hangupRequested) {
        result = RasHangUpW(m_connection);
        if (result != ERROR_SUCCESS) return false;
        m_hangupRequested = true;
        if (!storeRecord("hangup-requested")) return false;
    }
    // RasHangUp is asynchronous. An elapsed timeout or RASCS_Disconnected is
    // not its documented join condition; subsequent polls await invalid handle.
    return false;
}

bool WindowsIkev2Dns::releaseFence()
{
    if (!m_fence) return true;
    if (FwpmEngineClose0(m_fence) != ERROR_SUCCESS) return false;
    m_fence = nullptr;
    return true;
}
bool WindowsIkev2Dns::releaseProtection()
{
    if (!removeRecord()) return false;
    if (m_policyAttempted && !KillSwitch::instance()->setNativeIpv6Blocked(false, {})) return false;
    m_policyAttempted = false;
    if (m_recoveryBlocked) {
        const auto records = ownedRecords();
        if (!records) return false;
        for (auto it = records->cbegin(); it != records->cend(); ++it) {
            if (it.value()["phase"] == QJsonValue("completed")) continue;
            if (it.value()["phase"] != QJsonValue("retired")) return false;
            m_ownedDirectory = it.key();
            m_record = it.value();
            if (!storeRecord("completed")) return false;
        }
    } else if (!m_ownedDirectory.isEmpty() && !storeRecord("completed")) return false;
    // Durable completion receipts survive a lost final reply plus service
    // restart. Never infer "stopped" merely from an unknown in-memory owner.
    m_ownedDirectory.clear();
    m_record = {};
    if (!m_session.owner().isEmpty()) m_completedOwners.insert(m_session.owner());
    m_completedOwners.unite(m_recoveryCompletedOwners);
    m_recoveryCompletedOwners.clear();
    while (m_completedOwners.size() > 128) m_completedOwners.erase(m_completedOwners.begin());
    m_timer.stop();
    return true;
}
QString WindowsIkev2Dns::state(const QString &owner) const
{
    if (owner != m_session.owner() && m_completedOwners.contains(owner)) return "stopped";
    switch (m_session.state(owner)) {
    case Ikev2DnsSession::State::Starting: return "starting";
    case Ikev2DnsSession::State::Connected: return "connected";
    case Ikev2DnsSession::State::Stopping: return "stopping";
    case Ikev2DnsSession::State::Stopped: return "stopped";
    default: return "unknown";
    }
}
bool WindowsIkev2Dns::stop(const QString &owner)
{
    qInfo() << "Native IKEv2 stop requested; state:" << state(owner);
    return !m_recoveryBlocked && (m_completedOwners.contains(owner) || m_session.stop(owner));
}
bool WindowsIkev2Dns::shutdown() { return !m_recoveryBlocked && m_session.shutdown(); }

bool WindowsIkev2Dns::acknowledgeStopped(const QString &owner)
{
    if (state(owner) != "stopped") return false;
    const auto records = ownedRecords();
    if (!records) return false;
    for (auto it = records->cbegin(); it != records->cend(); ++it) {
        if (it.value()["owner"] != QJsonValue(owner)) continue;
        if (it.value()["phase"] != QJsonValue("completed") || !QFile::remove(it.key() + ".json"))
            return false;
    }
    m_completedOwners.remove(owner);
    return true;
}

bool WindowsIkev2Dns::storeRecord(const QString &phase)
{
    m_record["phase"] = phase;
    m_record["native_handle"] = QString::number(reinterpret_cast<quintptr>(m_connection));
    QSaveFile file(m_ownedDirectory + ".json");
    const auto bytes = QJsonDocument(m_record).toJson(QJsonDocument::Compact);
    return file.open(QIODevice::WriteOnly) && file.write(bytes) == bytes.size() && file.commit();
}

bool WindowsIkev2Dns::removeRecord()
{
    if (m_ownedDirectory.isEmpty()) return true;
    const auto files = QFileInfo::exists(m_ownedDirectory)
        ? QDir(m_ownedDirectory).entryList(QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System)
        : QStringList{};
    for (const auto &name : files)
        if (name != "rasphone.pbk") return false;
    if (!storeRecord("retired")) return false;
    for (const auto &name : files) {
        const auto path = QDir(m_ownedDirectory).filePath(name);
        if (QFileInfo(path).isSymLink() || !QFile::remove(path)) return false;
    }
    if (QFileInfo::exists(m_ownedDirectory) && !QDir().rmdir(m_ownedDirectory)) return false;
    return true;
}

bool WindowsIkev2Dns::prepareRecovery()
{
    m_recoveryBlocked = true;
    const auto records = ownedRecords();
    if (!records) return false;
    bool pending = false;
    for (const auto &record : *records) {
        if (record["phase"] == QJsonValue("completed"))
            m_completedOwners.insert(record["owner"].toString());
        else pending = true;
    }
    if (!pending) {
        m_recoveryBlocked = false;
        return true;
    }
    QStringList endpoints;
    for (const auto &record : *records) {
        if (record["phase"] == QJsonValue("completed")) continue;
        for (const auto &value : record["endpoints"].toArray()) {
            if (!value.isString() || QHostAddress(value.toString()).isNull()) return false;
            endpoints.append(value.toString());
        }
    }
    endpoints.removeDuplicates();
    m_policyAttempted = true;
    if (!KillSwitch::instance()->setNativeIpv6Blocked(true, endpoints)) return false;
    m_fence = NativeDnsFirewall::openSetupFence();
    if (!m_fence) return false;
    m_timer.start();
    return true;
}

bool WindowsIkev2Dns::finishRecovery()
{
    // Called only after durable OS DNS recovery and alias retirement succeeded.
    // Later timer calls retry native join, not an unconfirmed DNS rollback.
    m_recoveryDnsRestored = true;
    if (!m_recoveryBlocked) return true;
    const auto records = ownedRecords();
    if (!records) return false;
    for (auto it = records->cbegin(); it != records->cend(); ++it) {
        const auto &directory = it.key();
        const auto &record = it.value();
        if (record["phase"] == QJsonValue("completed")) {
            m_completedOwners.insert(record["owner"].toString());
            continue;
        }
        m_ownedDirectory = directory;
        m_phonebook = directory + "/rasphone.pbk";
        m_record = record;
        m_connection = nullptr;
        if (record["phase"] != QJsonValue("prepared") && record["phase"] != QJsonValue("retired")) {
            std::vector<RASCONNW> connections;
            if (!activeConnections(connections)) return false;
            for (const auto &connection : connections) {
                if (QFileInfo(QString::fromWCharArray(connection.szPhonebook)).canonicalFilePath()
                        != QFileInfo(m_phonebook).canonicalFilePath()) continue;
                if (m_connection || QString::fromWCharArray(connection.szEntryName)
                        != QString::fromWCharArray(entryName)) return false;
                const auto expected = record["correlation_id"].toString();
                if (!expected.isEmpty() && QUuid(connection.guidCorrelationId) != QUuid(expected))
                    return false;
                if (QUuid(connection.guidCorrelationId).isNull()) return false;
                m_record["correlation_id"] = QUuid(connection.guidCorrelationId).toString();
                m_connection = connection.hrasconn;
            }
            if (m_connection) {
                if (record["phase"] != QJsonValue("hangup-requested")) {
                    if (RasHangUpW(m_connection) != ERROR_SUCCESS || !storeRecord("hangup-requested"))
                        return false;
                }
                QElapsedTimer deadline;
                deadline.start();
                while (true) {
                    RASCONNSTATUSW status{};
                    status.dwSize = sizeof(status);
                    const auto result = RasGetConnectStatusW(m_connection, &status);
                    if (result == ERROR_INVALID_HANDLE) break;
                    if (result != ERROR_SUCCESS || deadline.elapsed() >= 5000) return false;
                    QThread::msleep(50);
                }
            } else {
                const auto saved = record["native_handle"].toString().toULongLong();
                if (record["phase"] == QJsonValue("dial-returned")) return false;
                if (!saved && record["phase"] != QJsonValue("started")) {
                    // Crash in the pre-return RasDial boundary is ambiguous.
                    // Keep its private profile, fence and journal, not a
                    // fabricated "no connection" proof from active-only enum.
                    return false;
                }
                if (saved) {
                    RASCONNSTATUSW status{};
                    status.dwSize = sizeof(status);
                    if (RasGetConnectStatusW(reinterpret_cast<HRASCONN>(quintptr(saved)), &status)
                            != ERROR_INVALID_HANDLE) return false;
                }
            }
        }
        m_connection = nullptr;
        if (!removeRecord()) return false;
        m_recoveryCompletedOwners.insert(record["owner"].toString());
    }
    if (!releaseFence() || !releaseProtection()) return false;
    m_recoveryBlocked = false;
    return true;
}
