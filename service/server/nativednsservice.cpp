#include "nativednsservice.h"

#include <QDir>
#include <QDebug>
#include <QElapsedTimer>
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLockFile>
#include <QNetworkInterface>
#include <QProcess>
#include <QProcessEnvironment>
#include <QSaveFile>
#include <QSet>
#include <QStandardPaths>
#include <QThread>
#include <QUuid>
#include <vector>
#include <amnezia_xray.h>
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
#include "platforms/linux/daemon/linuxdnsrecovery.h"
#elif defined(Q_OS_MACOS)
#include "platforms/macos/daemon/macosdnsrecovery.h"
#elif defined(Q_OS_WIN)
#include "platforms/windows/daemon/windowsdnsrecovery.h"
#endif

#ifdef Q_OS_WIN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <sddl.h>
#include <aclapi.h>
#include <fwpmu.h>
#include "platforms/windows/daemon/nativednsfirewall.h"
#else
#include <unistd.h>
#include <fcntl.h>
#endif
#ifdef Q_OS_MACOS
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_var.h>
#include <netinet/in_var.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#endif

namespace {
// Accessed on the service's QObject thread, including prepare/retire.
QSet<quint32> ownedAddresses;

QNetworkInterface interfaceNamed(const QString &name)
{
    for (const auto &iface : QNetworkInterface::allInterfaces())
        if (iface.name() == name || iface.humanReadableName() == name) return iface;
    return {};
}

QString scopeName(const QNetworkInterface &iface)
{
#ifdef Q_OS_WIN
    return iface.humanReadableName(); // Go's net.Interface uses FriendlyName.
#else
    return iface.name();
#endif
}

QStringList anchors(const QNetworkInterface &iface)
{
    QStringList result;
    for (const auto &entry : iface.addressEntries()) {
        if (entry.ip().protocol() == QAbstractSocket::IPv4Protocol
                && ownedAddresses.contains(entry.ip().toIPv4Address())) continue;
        result.append(entry.ip().toString() + "/" + QString::number(entry.prefixLength()));
    }
    result.sort();
    return result;
}

bool assigned(const QHostAddress &ip, const QNetworkInterface &iface, int prefix = -1)
{
    for (const auto &entry : iface.addressEntries())
        if (entry.ip() == ip && (prefix < 0 || entry.prefixLength() == prefix)) return true;
    return false;
}

bool assignedAnywhere(const QHostAddress &ip)
{
    for (const auto &iface : QNetworkInterface::allInterfaces())
        if (assigned(ip, iface)) return true;
    return false;
}

#if defined(Q_OS_LINUX) || defined(Q_OS_MACOS)
bool command(const QString &program, const QStringList &arguments, QByteArray *output = nullptr)
{
    if (program.isEmpty()) return false;
    QProcess process;
    auto environment = QProcessEnvironment::systemEnvironment();
    environment.insert("LC_ALL", "C");
    process.setProcessEnvironment(environment);
    process.setProgram(program);
    process.setArguments(arguments);
    process.start();
    if (!process.waitForStarted(2000)) return false;
    if (!process.waitForFinished(4000)) {
        process.kill();
        process.waitForFinished(2000);
        return false;
    }
    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) return false;
    if (output) *output = process.readAllStandardOutput();
    return true;
}

#ifdef Q_OS_LINUX
QString ipProgram()
{
    return QStandardPaths::findExecutable("ip", {"/usr/sbin", "/usr/bin", "/sbin", "/bin"});
}
#endif
#endif

using Prefixes = QList<QPair<QHostAddress, int>>;
bool routes(Prefixes &result)
{
#ifdef Q_OS_LINUX
    QByteArray raw;
    if (!command(ipProgram(), {"-j", "-4", "route", "show", "table", "all"}, &raw)) return false;
    QJsonParseError error;
    const auto document = QJsonDocument::fromJson(raw, &error);
    if (error.error != QJsonParseError::NoError || !document.isArray()) return false;
    for (const auto &value : document.array()) {
        const auto destination = value.toObject().value("dst").toString();
        if (destination == "default") continue;
        const auto prefix = QHostAddress::parseSubnet(destination);
        if (prefix.second < 0) return false;
        result.append(prefix);
    }
    return true;
#elif defined(Q_OS_WIN)
    PMIB_IPFORWARD_TABLE2 table = nullptr;
    if (GetIpForwardTable2(AF_INET, &table) != NO_ERROR) return false;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const auto &prefix = table->Table[i].DestinationPrefix;
        result.append({QHostAddress(ntohl(prefix.Prefix.Ipv4.sin_addr.s_addr)), prefix.PrefixLength});
    }
    FreeMibTable(table);
    return true;
#else
    Q_UNUSED(result);
    return true; // Darwin candidates are checked individually with public route(8).
#endif
}

bool candidateFree(const QHostAddress &ip, Prefixes &known, bool &valid)
{
    valid = true;
    if (assignedAnywhere(ip)) return false;
    for (const auto &prefix : known)
        if (prefix.second > 1 && ip.isInSubnet(prefix.first, prefix.second)) return false;
#ifdef Q_OS_MACOS
    QByteArray raw;
    if (!command("/sbin/route", {"-n", "get", "-inet", ip.toString()}, &raw)) {
        valid = false;
        return false;
    }
    QString destination, mask;
    for (const auto &line : QString::fromLocal8Bit(raw).split('\n')) {
        const auto text = line.trimmed();
        if (text.startsWith("destination:")) destination = text.mid(12).trimmed();
        if (text.startsWith("mask:")) mask = text.mid(5).trimmed();
    }
    if (destination == "default") return true;
    const QHostAddress address(destination);
    if (address.isNull()) { valid = false; return false; }
    const auto prefix = QHostAddress::parseSubnet(destination + "/" +
        (mask.isEmpty() ? QString("32") : mask));
    if (prefix.second < 0) { valid = false; return false; }
    known.append(prefix);
    if (prefix.second > 1 && ip.isInSubnet(prefix.first, prefix.second)) return false;
#endif
    return true;
}

QNetworkInterface resolverScope(const QNetworkInterface &native, const QHostAddress &server)
{
    if (server.protocol() == QAbstractSocket::IPv4Protocol && server.isLoopback()) {
        for (const auto &iface : QNetworkInterface::allInterfaces())
            if (iface.flags().testFlag(QNetworkInterface::IsLoopBack)) return iface;
        return {};
    }
#ifdef Q_OS_MACOS
    // The native desktop utility publishes global service DNS, not per-link
    // settings. Preserve the original server's FIB scope, including split routes.
    if (server.protocol() == QAbstractSocket::IPv4Protocol) {
        QByteArray raw;
        if (!command("/sbin/route", {"-n", "get", "-inet", server.toString()}, &raw)) return {};
        for (const auto &line : QString::fromLocal8Bit(raw).split('\n')) {
            const auto text = line.trimmed();
            if (text.startsWith("interface:")) return interfaceNamed(text.mid(10).trimmed());
        }
        return {};
    }
#endif
    return native; // Windows/Linux publish original DNS on this native link.
}

bool alias(const QNetworkInterface &iface, const QHostAddress &ip, bool add)
{
#ifdef Q_OS_LINUX
    QStringList args = {"address", add ? "add" : "del", ip.toString() + "/32",
                        "dev", iface.name()};
    if (add) args << "scope" << "host" << "noprefixroute";
    return command(ipProgram(), args);
#elif defined(Q_OS_WIN)
    MIB_UNICASTIPADDRESS_ROW row;
    InitializeUnicastIpAddressEntry(&row);
    row.InterfaceIndex = iface.index();
    row.Address.Ipv4.sin_family = AF_INET;
    row.Address.Ipv4.sin_addr.s_addr = htonl(ip.toIPv4Address());
    if (!add) return DeleteUnicastIpAddressEntry(&row) == NO_ERROR;
    row.OnLinkPrefixLength = 32;
    row.SkipAsSource = TRUE;
    row.PrefixOrigin = IpPrefixOriginManual;
    row.SuffixOrigin = IpSuffixOriginManual;
    if (CreateUnicastIpAddressEntry(&row) != NO_ERROR) return false;
    return true;
#elif defined(Q_OS_MACOS)
    const int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (fd < 0) return false;
    bool result;
    if (add) {
        struct ifaliasreq request = {};
        const auto name = iface.name().toLocal8Bit();
        qstrncpy(request.ifra_name, name.constData(), sizeof(request.ifra_name));
        auto *address = reinterpret_cast<sockaddr_in *>(&request.ifra_addr);
        auto *mask = reinterpret_cast<sockaddr_in *>(&request.ifra_mask);
        auto *broadcast = reinterpret_cast<sockaddr_in *>(&request.ifra_broadaddr);
        address->sin_family = mask->sin_family = broadcast->sin_family = AF_INET;
        address->sin_len = mask->sin_len = broadcast->sin_len = sizeof(sockaddr_in);
        address->sin_addr.s_addr = broadcast->sin_addr.s_addr = htonl(ip.toIPv4Address());
        mask->sin_addr.s_addr = htonl(0xffffffffu);
        result = ioctl(fd, SIOCAIFADDR, &request) == 0;
    } else {
        struct ifreq request = {};
        const auto name = iface.name().toLocal8Bit();
        qstrncpy(request.ifr_name, name.constData(), sizeof(request.ifr_name));
        auto *address = reinterpret_cast<sockaddr_in *>(&request.ifr_addr);
        address->sin_family = AF_INET;
        address->sin_len = sizeof(sockaddr_in);
        address->sin_addr.s_addr = htonl(ip.toIPv4Address());
        result = ioctl(fd, SIOCDIFADDR, &request) == 0;
    }
    close(fd);
    return result;
#else
    Q_UNUSED(iface); Q_UNUSED(ip); Q_UNUSED(add);
    return false;
#endif
}

bool readyAliases(const QNetworkInterface &iface, const QList<QHostAddress> &addresses)
{
#ifdef Q_OS_WIN
    MIB_IPINTERFACE_ROW policy{};
    InitializeIpInterfaceEntry(&policy);
    policy.Family = AF_INET;
    policy.InterfaceIndex = iface.index();
    if (GetIpInterfaceEntry(&policy) != NO_ERROR) return false;
    // IPv4 normally performs 3 DAD transmissions, not one. Read the native
    // policy; never disable DAD or advertise tentative addresses. A single
    // deadline covers the complete concurrently-created alias set.
    const quint64 requested = (quint64(policy.DadTransmits) + 1) * policy.RetransmitTime + 500;
    if (requested > 10000 || (policy.DadTransmits && !policy.RetransmitTime)) {
        qWarning() << "Native DNS alias DAD policy exceeds bounded startup";
        return false;
    }
    const qint64 budget = qMax<qint64>(2000, requested);
    QElapsedTimer elapsed;
    elapsed.start();
    for (;;) {
        bool ready = true;
        const auto current = QNetworkInterface::interfaceFromIndex(iface.index());
        for (const auto &ip : addresses) {
            MIB_UNICASTIPADDRESS_ROW row{};
            InitializeUnicastIpAddressEntry(&row);
            row.InterfaceIndex = iface.index();
            row.Address.Ipv4.sin_family = AF_INET;
            row.Address.Ipv4.sin_addr.s_addr = htonl(ip.toIPv4Address());
            const auto error = GetUnicastIpAddressEntry(&row);
            if (error != NO_ERROR || row.DadState == IpDadStateDuplicate) {
                qWarning() << "Native DNS alias readiness failed" << ip << error << row.DadState;
                return false;
            }
            if (row.DadState != IpDadStatePreferred || !assigned(ip, current, 32)) ready = false;
        }
        if (ready) return true;
        if (elapsed.elapsed() >= budget) {
            qWarning() << "Native DNS alias set readiness timed out"
                       << "DadTransmits" << policy.DadTransmits
                       << "RetransmitTime" << policy.RetransmitTime;
            return false;
        }
        QThread::msleep(20);
    }
#else
    const auto current = QNetworkInterface::interfaceFromIndex(iface.index());
    for (const auto &ip : addresses) if (!assigned(ip, current, 32)) return false;
    return true;
#endif
}

bool privateDirectory(const QString &path)
{
    if (path.isEmpty() || !QDir::isAbsolutePath(path) || QFileInfo(path).isSymLink()) return false;
    if (!QDir().mkpath(path)) return false;
#ifdef Q_OS_WIN
    if (GetFileAttributesW(reinterpret_cast<LPCWSTR>(path.utf16())) & FILE_ATTRIBUTE_REPARSE_POINT)
        return false;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", SDDL_REVISION_1, &descriptor, nullptr))
        return false;
    PACL dacl = nullptr;
    BOOL present = FALSE, defaulted = FALSE;
    const bool read = GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted);
    const auto result = read && present ? SetNamedSecurityInfoW(
        const_cast<LPWSTR>(reinterpret_cast<LPCWSTR>(path.utf16())), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr, nullptr, dacl, nullptr) : ERROR_ACCESS_DENIED;
    LocalFree(descriptor);
    return result == ERROR_SUCCESS;
#else
    if (QFileInfo(path).ownerId() != geteuid()) return false;
    return QFile::setPermissions(path, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
#endif
}

bool validResolverPolicy(const QJsonArray &policy)
{
    if (policy.size() > 16) return false;
    const QSet<QString> allowed{"server", "port", "transport", "server_name", "https_url"};
    for (const auto &value : policy) {
        if (!value.isObject()) return false;
        const auto entry = value.toObject();
        for (auto it = entry.begin(); it != entry.end(); ++it)
            if (!allowed.contains(it.key())) return false;
        if (!entry["server"].isString() || !entry["port"].isDouble()
                || !entry["transport"].isString()
                || (entry.contains("server_name") && !entry["server_name"].isString())
                || (entry.contains("https_url") && !entry["https_url"].isString())) return false;
        const QHostAddress server(entry["server"].toString());
        const int port = entry["port"].toInt(-1);
        if (server.isNull() || server.isMulticast() || server == QHostAddress::AnyIPv4
                || server == QHostAddress::AnyIPv6 || !server.scopeId().isEmpty()
                || server.toString() != entry["server"].toString()
                || port < 1 || port > 65535 || entry["port"].toDouble() != port) return false;
        const auto transport = entry["transport"].toString();
        const auto name = entry["server_name"].toString(), url = entry["https_url"].toString();
        if (name.size() > 253 || url.size() > 8192 || name.contains(QChar(0)) || url.contains(QChar(0)))
            return false;
        if (transport == "plain") {
            if (!name.isEmpty() || !url.isEmpty()) return false;
        } else if (transport == "tls") {
            if (!url.isEmpty()) return false;
        } else if (transport == "https") {
            if (url.isEmpty()) return false;
        } else return false;
    }
    return true;
}

class ServiceGuard final : public NativeDnsGuard {
public:
    explicit ServiceGuard(QString path) : directory(std::move(path)) {}
    ~ServiceGuard() override {
        // Destruction is not confirmation that OS DNS was restored. Join Go
        // but retain assigned addresses and their journal as fail-closed state.
        if (handle > 0) amnezia_native_dns_stop(handle);
#ifdef Q_OS_WIN
        if (firewallLease) FwpmEngineClose0(firewallLease);
#endif
        for (const auto &ip : installed) ownedAddresses.remove(ip.toIPv4Address());
    }

    bool prepare(const QString &ifname, const QList<QHostAddress> &original,
                 QList<QHostAddress> &endpoints) override {
        if (handle > 0 || original.isEmpty() || original.size() > 16) return false;
        if (!resolverPolicy.isEmpty()) {
            if (resolverPolicy.size() != original.size()) return false;
            for (int i = 0; i < original.size(); ++i)
                if (resolverPolicy[i].toObject()["server"].toString() != original[i].toString()) return false;
        }
        native = interfaceNamed(ifname);
        if (!native.isValid() || !native.flags().testFlag(QNetworkInterface::IsUp)) return false;
        identity = anchors(native);
        servers = original;
        if (directory.isEmpty())
            directory = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation) + "/native-dns";
        if (!privateDirectory(directory)) return false;
        token = QUuid::createUuid().toString(QUuid::WithoutBraces);
        journal = QDir(directory).filePath("owned-" + token + ".json");
        journalLock = std::make_unique<QLockFile>(journal + ".lock");
        journalLock->setStaleLockTime(0);
        if (!journalLock->tryLock()) return false;
        Prefixes prefixes;
        if (!routes(prefixes)) return false;
        QJsonArray bindings;
        for (int index = 0; index < servers.size(); ++index) {
            const auto &server = servers[index];
            const auto policy = resolverPolicy.isEmpty() ? QJsonObject{} : resolverPolicy[index].toObject();
            if (server.isNull() || server.isMulticast() || server == QHostAddress::AnyIPv4
                    || server == QHostAddress::AnyIPv6) return fail();
            const auto scope = resolverScope(native, server);
            if (!scope.isValid() || !scope.flags().testFlag(QNetworkInterface::IsUp)) return fail();
            QHostAddress selected;
            for (int suffix = 1; suffix < 254; ++suffix) {
                const QHostAddress candidate(QString("198.19.255.%1").arg(suffix));
                if (servers.contains(candidate) || planned.contains(candidate))
                    continue;
                bool valid = true;
                const bool available = candidateFree(candidate, prefixes, valid);
                if (!valid) return fail();
                if (!available) continue;
                selected = candidate;
                break;
            }
            if (selected.isNull()) return fail();
            planned.append(selected);
            if (!save()) return fail(); // Journal intent before any privileged mutation.
            if (!alias(native, selected, true)) return fail();
            installed.append(selected);
            ownedAddresses.insert(selected.toIPv4Address());
            if (!save()) return fail("installed-state journal write");
            const auto port = QString::number(policy["port"].toInt(53));
            const QString upstream = server.protocol() == QAbstractSocket::IPv6Protocol
                ? "[" + server.toString() + "]:" + port : server.toString() + ":" + port;
            QJsonObject binding{{"endpoint", selected.toString() + ":53"},
                {"upstream", upstream}, {"interface_name", scopeName(scope)},
                {"interface_index", scope.index()}};
            for (const auto &key : {"transport", "server_name", "https_url"})
                if (policy.contains(key)) binding.insert(key, policy.value(key));
            bindings.append(binding);
            scopes.append(scope.name() + "/" + QString::number(scope.index()));
        }
        if (!readyAliases(native, installed)) return fail("alias readiness");
        const auto config = QJsonDocument(QJsonObject{{"bindings", bindings}}).toJson(QJsonDocument::Compact);
#ifdef Q_OS_WIN
        if (!(firewallLease = NativeDnsFirewall::openLease(planned))) return fail("IPv4 DNS firewall lease");
#endif
        handle = amnezia_native_dns_start(const_cast<char *>(config.constData()));
        if (handle <= 0) return fail("Go DNS listener startup");
        endpoints = planned;
        return true;
    }

    bool healthy() const override {
        if (handle <= 0 || amnezia_native_dns_alive(handle) != 1 || !sameInterface()) return false;
        const auto current = QNetworkInterface::interfaceFromIndex(native.index());
        if (!current.flags().testFlag(QNetworkInterface::IsUp)) return false;
        for (const auto &ip : installed) if (!assigned(ip, current, 32)) return false;
        // The listener socket retains its original scope. A removed/replaced
        // resolver interface must fail the connection, not leave a stale socket
        // alive or silently select another underlay.
        if (scopes.size() != servers.size()) return false;
        for (int i = 0; i < servers.size(); ++i) {
            const auto separator = scopes[i].lastIndexOf('/');
            const auto scope = QNetworkInterface::interfaceFromIndex(
                scopes[i].mid(separator + 1).toInt());
            if (!scope.isValid() || !scope.flags().testFlag(QNetworkInterface::IsUp)
                    || scope.name() + "/" + QString::number(scope.index()) != scopes[i])
                return false;
        }
#ifdef Q_OS_WIN
        if (!dnsRecovery.isEmpty() && (!policyChecked.isValid() || policyChecked.elapsed() >= 250)) {
            policyHealthy = WindowsDnsRecovery::policyUnchanged(dnsRecovery);
            policyChecked.restart();
        }
        if (!policyHealthy) {
            quiesce();
            return false;
        }
#endif
        return true;
    }
    QList<QHostAddress> originalResolvers() const override { return servers; }
    bool quiesce() const override {
        return handle <= 0 || amnezia_native_dns_quiesce(handle) == 1;
    }

    bool matches(const QString &ifname, const QList<QHostAddress> &original) const override {
        if (!healthy() || interfaceNamed(ifname).index() != native.index() || original != servers) return false;
        for (int i = 0; i < servers.size(); ++i) {
            const auto scope = resolverScope(native, servers[i]);
            if (!scope.isValid() || scope.name() + "/" + QString::number(scope.index()) != scopes[i]) return false;
        }
        return true;
    }
    bool storeDnsRecovery(const QJsonObject &snapshot) override {
        if (snapshot.isEmpty() || handle <= 0) return false;
        dnsRecovery = snapshot;
#ifdef Q_OS_WIN
        policyChecked.invalidate();
        policyHealthy = true;
#endif
        if (!protocolMetadata.isEmpty()) dnsRecovery.insert("protocol_metadata", protocolMetadata);
        return save();
    }
    bool setProtocolMetadata(const QJsonObject &metadata) override {
        if (QJsonDocument(metadata).toJson(QJsonDocument::Compact).size() > 32768) return false;
        protocolMetadata = metadata;
        return true;
    }
    bool setResolverPolicy(const QJsonArray &policy) override {
        if (handle > 0 || !journal.isEmpty() || !validResolverPolicy(policy)) return false;
        resolverPolicy = policy;
        return true;
    }
    bool matchesResolverPolicy(const QJsonArray &policy) const override {
        return resolverPolicy == policy;
    }

    bool retire() override {
        if (handle > 0) {
            if (amnezia_native_dns_stop(handle) != 1) return false;
            handle = -1;
        }
#ifdef Q_OS_WIN
        if (firewallLease) {
            if (FwpmEngineClose0(firewallLease) != ERROR_SUCCESS) return false;
            firewallLease = nullptr;
        }
#endif
        if (!lastJournal.isEmpty() && !journalUnchanged()) return false;
        const auto current = QNetworkInterface::interfaceFromIndex(native.index());
        for (const auto &ip : installed) {
            if (!assignedAnywhere(ip)) { ownedAddresses.remove(ip.toIPv4Address()); continue; }
            if (!sameInterface() || !assigned(ip, current, 32) || !alias(current, ip, false)) return false;
            ownedAddresses.remove(ip.toIPv4Address());
        }
        installed.clear();
        planned.clear();
        if (!journal.isEmpty() && !lastJournal.isEmpty() && !QFile::remove(journal)) return false;
        lastJournal.clear();
        return true;
    }
private:
    QJsonObject protocolMetadata;
    QJsonArray resolverPolicy;
    bool sameInterface() const {
        const auto current = QNetworkInterface::interfaceFromIndex(native.index());
        return current.isValid() && current.name() == native.name() && anchors(current) == identity;
    }
    bool journalUnchanged() const {
        if (QFileInfo(journal).isSymLink()) return false;
        QFile file(journal);
        return file.open(QIODevice::ReadOnly) && file.readAll() == lastJournal;
    }
    bool save() {
        if ((!lastJournal.isEmpty() && !journalUnchanged())
                || (lastJournal.isEmpty() && QFileInfo::exists(journal))) return false;
        QJsonArray wanted, present, anchorList;
        for (const auto &ip : planned) wanted.append(ip.toString());
        for (const auto &ip : installed) present.append(ip.toString());
        for (const auto &address : identity) anchorList.append(address);
        QJsonObject record{{"schema", 2}, {"owner", token},
            {"interface_name", native.name()}, {"interface_index", native.index()},
            {"anchors", anchorList}, {"planned", wanted}, {"installed", present}};
        if (!dnsRecovery.isEmpty()) record.insert("dns_recovery", dnsRecovery);
        if (!resolverPolicy.isEmpty()) record.insert("resolver_policy", resolverPolicy);
        record.insert("checksum", QString::fromLatin1(QCryptographicHash::hash(
            QJsonDocument(record).toJson(QJsonDocument::Compact), QCryptographicHash::Sha256).toHex()));
        const auto bytes = QJsonDocument(record).toJson();
        if (bytes.size() > 65536) return false;
        QSaveFile file(journal);
        if (!file.open(QIODevice::WriteOnly)) return false;
        if (!file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner)) return false;
        if (file.write(bytes) != bytes.size() || !file.commit()) return false;
        lastJournal = bytes;
#if defined(Q_OS_LINUX) || defined(Q_OS_MACOS)
        // QSaveFile syncs contents before rename. Also sync the directory entry:
        // an OS DNS mutation must never outrun a newly renamed recovery record.
        const auto encoded = QFile::encodeName(directory);
        const int directoryFd = open(encoded.constData(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (directoryFd < 0) return false;
        const bool synced = fsync(directoryFd) == 0;
        close(directoryFd);
        if (!synced) return false;
#ifdef Q_OS_MACOS
        const auto fileName = QFile::encodeName(journal);
        const int journalFd = open(fileName.constData(), O_RDWR | O_CLOEXEC | O_NOFOLLOW);
        if (journalFd < 0) return false;
        const bool fullySynced = fcntl(journalFd, F_FULLFSYNC) == 0;
        close(journalFd);
        if (!fullySynced) return false;
#endif
#elif defined(Q_OS_WIN)
        const HANDLE journalFile = CreateFileW(reinterpret_cast<LPCWSTR>(journal.utf16()),
            GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH, nullptr);
        if (journalFile == INVALID_HANDLE_VALUE) return false;
        const bool synced = FlushFileBuffers(journalFile);
        CloseHandle(journalFile);
        if (!synced) return false;
#endif
        return true;
    }
    bool fail(const char *reason = "endpoint preparation") {
        qWarning() << "Native DNS preparation failed:" << reason;
        retire();
        return false;
    }
    QString directory, token, journal;
    std::unique_ptr<QLockFile> journalLock;
    QByteArray lastJournal;
    QJsonObject dnsRecovery;
#ifdef Q_OS_WIN
    mutable QElapsedTimer policyChecked;
    mutable bool policyHealthy = true;
#endif
    QNetworkInterface native;
    QStringList identity, scopes;
    QList<QHostAddress> servers, planned, installed;
    qint64 handle = -1;
#ifdef Q_OS_WIN
    HANDLE firewallLease = nullptr;
#endif
};
}

std::unique_ptr<NativeDnsGuard> createNativeDnsServiceGuard(const QString &directory)
{
    return std::make_unique<ServiceGuard>(directory);
}

bool prepareNativeDnsPrivateDirectory(const QString &directory)
{
    return privateDirectory(directory);
}

bool recoverNativeDnsServiceGuards(
    const QString &directory,
    const std::function<bool(const QJsonObject &)> &restoreDns)
{
    if (!restoreDns || !privateDirectory(directory)) return false;
    bool complete = true;
    const auto files = QDir(directory).entryList({"owned-*.json"}, QDir::Files | QDir::System);
    struct Recovery {
        QString path;
        QByteArray bytes;
        QJsonObject record;
        QList<QHostAddress> installed;
    };
    QList<Recovery> records;
    std::vector<std::unique_ptr<QLockFile>> locks;
    QList<QHostAddress> recoveryAliases;
    for (const auto &name : files) {
        const auto path = QDir(directory).filePath(name);
        auto lock = std::make_unique<QLockFile>(path + ".lock");
        lock->setStaleLockTime(0);
        if (!lock->tryLock()) { complete = false; continue; }
        locks.push_back(std::move(lock));
        const QFileInfo info(path);
        // Do not follow unknown links, accept legacy records, or repair corrupt
        // journals into something that could authorize privileged deletion.
        if (info.isSymLink() || !info.isFile() || info.size() > 65536) {
            complete = false; continue;
        }
#ifndef Q_OS_WIN
        if (info.ownerId() != geteuid() ||
            (info.permissions() & (QFileDevice::WriteGroup | QFileDevice::WriteOther))) {
            complete = false; continue;
        }
#endif
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly)) { complete = false; continue; }
        const auto bytes = file.readAll();
        file.close();
        QJsonParseError error;
        const auto document = QJsonDocument::fromJson(bytes, &error);
        auto record = document.object();
        const auto checksum = record.take("checksum").toString().toLatin1();
        const auto digest = QCryptographicHash::hash(
            QJsonDocument(record).toJson(QJsonDocument::Compact), QCryptographicHash::Sha256).toHex();
        const auto owner = record.value("owner").toString();
        QSet<QString> knownKeys{"schema", "owner", "interface_name", "interface_index",
                                     "anchors", "planned", "installed"};
        if (record.contains("dns_recovery")) knownKeys.insert("dns_recovery");
        if (record.contains("resolver_policy")) knownKeys.insert("resolver_policy");
        const auto keys = record.keys();
        const QSet<QString> actualKeys(keys.begin(), keys.end());
        if (error.error != QJsonParseError::NoError || !document.isObject()
                || document.toJson() != bytes
                || record.value("schema").toInt() != 2 || checksum != digest
                || actualKeys != knownKeys
                || QUuid(owner).isNull() || name != "owned-" + owner + ".json"
                || record.value("interface_index").toInt() <= 0
                || record.value("interface_name").toString().isEmpty()
                || !record.value("anchors").isArray() || !record.value("planned").isArray()
                || !record.value("installed").isArray()
                || (record.contains("resolver_policy") && (!record["resolver_policy"].isArray()
                    || !validResolverPolicy(record["resolver_policy"].toArray())))) {
            complete = false; continue;
        }
        QList<QHostAddress> installed, planned;
        bool valid = true;
        for (const auto &value : record.value("planned").toArray()) {
            const QHostAddress ip(value.toString());
            if (ip.protocol() != QAbstractSocket::IPv4Protocol
                    || !ip.isInSubnet(QHostAddress("198.19.255.0"), 24)
                    || ip == QHostAddress("198.19.255.0") || ip == QHostAddress("198.19.255.255")
                    || planned.contains(ip) || ownedAddresses.contains(ip.toIPv4Address())) valid = false;
            planned.append(ip);
        }
        for (const auto &value : record.value("installed").toArray()) {
            const QHostAddress ip(value.toString());
            if (!planned.contains(ip) || installed.contains(ip)) valid = false;
            installed.append(ip);
        }
        if (planned.isEmpty() || planned.size() > 16) valid = false;
        // An add may have completed just before the installed-state write.
        // Such an unconfirmed address is not proven ownership: preserve it.
        for (const auto &ip : planned)
            if (!installed.contains(ip) && assignedAnywhere(ip)) valid = false;
        if (!valid) { complete = false; continue; }
        for (const auto &ip : installed) {
            if (recoveryAliases.contains(ip)) return false; // Conflicting ownership.
            recoveryAliases.append(ip);
        }
        records.append({path, bytes, document.object(), installed});
    }
    for (const auto &entry : records) {
        const auto &record = entry.record;
        const auto &installed = entry.installed;
        const auto &path = entry.path;
        const auto &bytes = entry.bytes;
        bool valid = true;
        const int index = record.value("interface_index").toInt();
        const auto iface = QNetworkInterface::interfaceFromIndex(index);
        QStringList expected, actual;
        for (const auto &value : record.value("anchors").toArray()) {
            if (!value.isString()) valid = false;
            expected.append(value.toString());
        }
        expected.sort();
        if (iface.isValid()) {
            if (iface.name() != record.value("interface_name").toString()) valid = false;
            for (const auto &entry : iface.addressEntries()) {
                if (recoveryAliases.contains(entry.ip()) && entry.prefixLength() == 32) continue;
                actual.append(entry.ip().toString() + "/" + QString::number(entry.prefixLength()));
            }
            actual.sort();
            if (actual != expected) valid = false;
        }
        for (const auto &ip : installed)
            if (assignedAnywhere(ip) && (!iface.isValid() || !assigned(ip, iface, 32))) valid = false;
        if (!valid) { complete = false; continue; }
        // Callback must restore OS DNS first. Re-read the journal afterwards:
        // asynchronous platform work must not authorize deletion of edited state.
        QFile file(path);
        if (!restoreDns(record) || !file.open(QIODevice::ReadOnly)) {
            complete = false; continue;
        }
        const bool unchanged = !QFileInfo(path).isSymLink() && file.readAll() == bytes;
        file.close();
        if (!unchanged) { complete = false; continue; }
        const auto refreshed = QNetworkInterface::interfaceFromIndex(index);
        QStringList refreshedAnchors;
        for (const auto &entry : refreshed.addressEntries()) {
            if (recoveryAliases.contains(entry.ip()) && entry.prefixLength() == 32) continue;
            refreshedAnchors.append(entry.ip().toString() + "/" + QString::number(entry.prefixLength()));
        }
        refreshedAnchors.sort();
        if (refreshed.isValid() != iface.isValid()
                || refreshed.name() != iface.name()
                || (refreshed.isValid() && refreshedAnchors != expected)) {
            complete = false; continue;
        }
        bool retired = true;
        for (const auto &ip : installed) {
            if (assignedAnywhere(ip) &&
                (!assigned(ip, refreshed, 32) || !alias(refreshed, ip, false))) {
                retired = false; break;
            }
        }
        if (!retired || !QFile::remove(path)) complete = false;
    }
    return complete;
}

#if !defined(Q_OS_ANDROID)
bool recoverNativeDnsServiceOnStartup(const QString &directory)
{
    int remaining = QDir(directory).entryList({"owned-*.json"}, QDir::Files | QDir::System).size();
    const int passes = remaining + 1;
    for (int i = 0; i < passes; ++i) {
        if (recoverNativeDnsServiceGuards(directory, [](const QJsonObject &record) {
#if defined(Q_OS_LINUX)
            return LinuxDnsRecovery::restore(record.value("dns_recovery").toObject(),
                                             LinuxDnsRecovery::systemBackend());
#elif defined(Q_OS_MACOS)
            auto store = SCDynamicStoreCreate(kCFAllocatorDefault, CFSTR("amneziavpn-dns-recovery"),
                                               nullptr, nullptr);
            if (!store) return false;
            const bool result = MacosDnsRecovery::apply(store, record.value("dns_recovery").toObject(), true);
            CFRelease(store);
            return result;
#elif defined(Q_OS_WIN)
            return WindowsDnsRecovery::apply(record.value("dns_recovery").toObject(), true);
#else
            Q_UNUSED(record);
            return false;
#endif
        })) return true;
        const int next = QDir(directory).entryList({"owned-*.json"}, QDir::Files | QDir::System).size();
        if (next >= remaining) return false; // No blind retries of unresolved state.
        remaining = next;
    }
    return false;
}
#endif
