#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include "windowsdnsrecovery.h"
#include "windowsdnspolicy.h"
#include <QRegularExpression>
#include <QScopeGuard>
#include <QUuid>
#include <QMap>
#include <vector>

namespace WindowsDnsRecovery {
namespace {
const QString kind = "windows-interface-static-dns-v1";
using SetSettings = DWORD (WINAPI *)(GUID, const DNS_INTERFACE_SETTINGS *);
SetSettings setter()
{
    // Loaded once for the service lifetime. OFF requires a checked native API;
    // the older ON path retains its original netsh fallback.
    static HMODULE library = LoadLibraryW(L"iphlpapi.dll");
    static auto function = library
        ? reinterpret_cast<SetSettings>(GetProcAddress(library, "SetInterfaceDnsSettings")) : nullptr;
    return function;
}
bool parse(const QString &key, GUID &guid, bool &ipv6, QString &registry)
{
    const auto id = key.mid(3);
    const QUuid uuid(id);
    if ((key.left(3) != "v4/" && key.left(3) != "v6/") || uuid.isNull()
            || id != uuid.toString(QUuid::WithBraces)) return false;
    guid = uuid;
    ipv6 = key.startsWith("v6/");
    NET_LUID luid{};
    if (ConvertInterfaceGuidToLuid(&guid, &luid) != NO_ERROR) return false;
    MIB_IF_ROW2 row{};
    row.InterfaceLuid = luid;
    if (GetIfEntry2(&row) != NO_ERROR || !IsEqualGUID(row.InterfaceGuid, guid)) return false;
    registry = QString("SYSTEM\\CurrentControlSet\\Services\\%1\\Parameters\\Interfaces\\%2")
        .arg(ipv6 ? "Tcpip6" : "Tcpip", id);
    return true;
}
QStringList addresses(const QString &raw, bool ipv6, bool &valid)
{
    QStringList result;
    valid = true;
    for (const auto &text : raw.split(QRegularExpression("[,\\s]+"), Qt::SkipEmptyParts)) {
        const QHostAddress ip(text);
        if (ip.isNull() || ip.isMulticast() ||
            ip.protocol() != (ipv6 ? QAbstractSocket::IPv6Protocol : QAbstractSocket::IPv4Protocol)) {
            valid = false; return {};
        }
        result.append(ip.toString());
    }
    return result;
}
QJsonValue read(const QString &key)
{
    GUID guid{};
    bool ipv6;
    QString path;
    if (!setter() || !parse(key, guid, ipv6, path)) return QJsonValue(QJsonValue::Undefined);
    HKEY handle = nullptr;
    const auto opened = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        reinterpret_cast<LPCWSTR>(path.utf16()), 0, KEY_QUERY_VALUE, &handle);
    if (opened == ERROR_FILE_NOT_FOUND) return QJsonObject{{"mode", "dhcp"}, {"servers", QJsonArray{}}};
    if (opened != ERROR_SUCCESS) return QJsonValue(QJsonValue::Undefined);
    auto release = qScopeGuard([&] { RegCloseKey(handle); });
    DWORD size = 0, type = 0;
    auto status = RegQueryValueExW(handle, L"NameServer", nullptr, &type, nullptr, &size);
    if (status == ERROR_FILE_NOT_FOUND) return QJsonObject{{"mode", "dhcp"}, {"servers", QJsonArray{}}};
    if (status != ERROR_SUCCESS || (type != REG_SZ && type != REG_MULTI_SZ)
            || size > 65536 || size % sizeof(wchar_t)) return QJsonValue(QJsonValue::Undefined);
    std::vector<wchar_t> buffer(size / sizeof(wchar_t) + 2, L'\0');
    status = RegQueryValueExW(handle, L"NameServer", nullptr, &type,
                              reinterpret_cast<LPBYTE>(buffer.data()), &size);
    if (status != ERROR_SUCCESS || size % sizeof(wchar_t) || (type != REG_SZ && type != REG_MULTI_SZ))
        return QJsonValue(QJsonValue::Undefined);
    QString raw;
    for (size_t i = 0; i < size / sizeof(wchar_t); ++i) {
        const auto ch = buffer[i];
        if (ch == L'\0') {
            if (type == REG_SZ) break;
            raw += ' ';
        } else raw += QChar(ushort(ch));
    }
    bool valid = false;
    const auto servers = addresses(raw, ipv6, valid);
    if (!valid) return QJsonValue(QJsonValue::Undefined);
    QJsonArray list;
    for (const auto &server : servers) list.append(server);
    // Absent/empty static configuration is DHCP, not the current lease's DNS.
    return QJsonObject{{"mode", servers.isEmpty() ? "dhcp" : "static"}, {"servers", list}};
}
bool write(const QString &key, const QJsonValue &value)
{
    GUID guid{};
    bool ipv6;
    QString path;
    if (!setter() || !parse(key, guid, ipv6, path) || !value.isObject()) return false;
    const auto state = value.toObject();
    if (!state["servers"].isArray()) return false;
    QStringList list;
    for (const auto &server : state["servers"].toArray()) {
        if (!server.isString()) return false;
        list.append(server.toString());
    }
    bool valid = false;
    const auto normalized = addresses(list.join(','), ipv6, valid);
    const bool automatic = state["mode"] == QJsonValue("dhcp");
    if (!valid || normalized != list || (automatic && !list.isEmpty())
            || (!automatic && (state["mode"] != QJsonValue("static") || list.isEmpty()))) return false;
    auto text = list.join(',');
    DNS_INTERFACE_SETTINGS settings{};
    settings.Version = DNS_INTERFACE_SETTINGS_VERSION1;
    settings.Flags = DNS_SETTING_NAMESERVER | (ipv6 ? DNS_SETTING_IPV6 : 0);
    settings.NameServer = reinterpret_cast<PWSTR>(text.data());
    // No SEARCHLIST/DOMAIN/registration flags: original resolver metadata stays.
    return setter()(guid, &settings) == NO_ERROR;
}
}
DnsSettingsRecovery::Backend backend() { return {read, write}; }
QJsonObject capture(const QString &ifname, const QList<QHostAddress> &endpoints,
                    const QJsonObject &previous, const QList<QHostAddress> &originalServers)
{
    if (!setter() || endpoints.isEmpty()) return {};
    NET_LUID luid{};
    if (ConvertInterfaceAliasToLuid(reinterpret_cast<LPCWSTR>(ifname.utf16()), &luid) != NO_ERROR) return {};
    GUID guid{};
    if (ConvertInterfaceLuidToGuid(&luid, &guid) != NO_ERROR) return {};
    const QString id = QUuid(guid).toString(QUuid::WithBraces);
    QMap<QString, QJsonObject> old;
    if (!previous.isEmpty()) {
        if (previous["backend"] != QJsonValue(kind) || previous["guid"] != QJsonValue(id)) return {};
        for (const auto &value : previous["entries"].toArray()) {
            const auto entry = value.toObject();
            const auto key = entry["key"].toString();
            if (old.contains(key) || read(key) != entry["after"]) return {};
            old.insert(key, entry);
        }
        if (old.size() != 2) return {};
    }
    QJsonArray servers;
    for (const auto &endpoint : endpoints) {
        if (endpoint.protocol() != QAbstractSocket::IPv4Protocol) return {};
        servers.append(endpoint.toString());
    }
    QJsonArray entries;
    for (const auto &family : {QString("v4/"), QString("v6/")}) {
        const auto key = family + id;
        const auto current = read(key);
        if (current.isUndefined() || (!previous.isEmpty() && !old.contains(key))) return {};
        const auto before = old.contains(key) ? old[key]["before"] : current;
        const QJsonObject after = family == "v4/"
            ? QJsonObject{{"mode", "static"}, {"servers", servers}}
            : QJsonObject{{"mode", "dhcp"}, {"servers", QJsonArray{}}};
        entries.append(QJsonObject{{"key", key}, {"before", before}, {"after", after}});
    }
    QJsonObject snapshot{{"backend", kind}, {"guid", id}, {"entries", entries}};
    if (!originalServers.isEmpty()) {
        auto selected = originalServers;
        selected.append(endpoints);
        const bool legacy = previous["native_dns_policy"].toObject()["reader"]
            == QJsonValue("windows-native-plain-dns-policy-v1");
        const auto native = legacy ? std::optional<WindowsDnsPolicy::Selection>{}
                                   : WindowsDnsPolicy::captureSelected(ifname, selected);
        const auto policy = legacy ? WindowsDnsPolicy::capturePlain(ifname, selected)
            : (native ? std::optional<QJsonObject>(native->snapshot) : std::nullopt);
        if (!policy || (previous.contains("native_dns_policy")
                && previous["native_dns_policy"] != QJsonValue(*policy))) return {};
        QJsonArray servers;
        for (const auto &server : selected) servers.append(server.toString());
        snapshot.insert("native_dns_policy", *policy);
        snapshot.insert("policy_interface", ifname);
        snapshot.insert("policy_servers", servers);
    } else if (previous.contains("native_dns_policy")) {
        return {}; // A protected generation cannot silently lose its reader.
    }
    return snapshot;
}
bool policyUnchanged(const QJsonObject &snapshot)
{
    if (!snapshot.contains("native_dns_policy")) return true; // Legacy durable records.
    if (!snapshot["native_dns_policy"].isObject() || !snapshot["policy_servers"].isArray()
            || !snapshot["policy_interface"].isString()) return false;
    QList<QHostAddress> selected;
    for (const auto &value : snapshot["policy_servers"].toArray()) {
        if (!value.isString()) return false;
        const QHostAddress server(value.toString());
        if (server.isNull() || selected.size() >= 32) return false;
        selected.append(server);
    }
    const auto saved = snapshot["native_dns_policy"].toObject();
    std::optional<QJsonObject> current;
    if (saved["reader"] == QJsonValue("windows-native-plain-dns-policy-v1"))
        current = WindowsDnsPolicy::capturePlain(snapshot["policy_interface"].toString(), selected);
    else if (saved["reader"] == QJsonValue("windows-native-selected-dns-policy-v2")) {
        const auto native = WindowsDnsPolicy::captureSelected(snapshot["policy_interface"].toString(), selected);
        if (native) current = native->snapshot;
    } else return false;
    return current && QJsonValue(*current) == snapshot["native_dns_policy"];
}
bool apply(const QJsonObject &snapshot, bool restoring)
{
    if (!policyUnchanged(snapshot)) return false;
    return DnsSettingsRecovery::apply(snapshot, kind, backend(), restoring);
}
}
