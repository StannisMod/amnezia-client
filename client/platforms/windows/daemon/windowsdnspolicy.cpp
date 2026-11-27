#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <wbemidl.h>
#include <QJsonArray>
#include <QMap>
#include <QScopeGuard>
#include <vector>
#include "windowsdnspolicy.h"
#include "windowsdnsselection.h"
#include <QSet>

namespace {
struct Bstr {
    BSTR value;
    explicit Bstr(const wchar_t *text) : value(SysAllocString(text)) {}
    ~Bstr() { SysFreeString(value); }
    operator BSTR() const { return value; }
};
template<class T> struct Com {
    T *value = nullptr;
    ~Com() { if (value) value->Release(); }
    T *operator->() const { return value; }
};
struct Variant {
    VARIANT value{};
    ~Variant() { VariantClear(&value); }
};
bool get(IWbemClassObject *object, const wchar_t *name, Variant &value, VARTYPE type)
{
    return object && SUCCEEDED(object->Get(name, 0, &value.value, nullptr, nullptr))
        && value.value.vt == type;
}
bool connect(IWbemLocator *locator, const wchar_t *name, Com<IWbemServices> &service)
{
    Bstr space(name);
    return space.value && SUCCEEDED(locator->ConnectServer(space, nullptr, nullptr, nullptr,
        WBEM_FLAG_CONNECT_USE_MAX_WAIT, nullptr, nullptr, &service.value))
        && SUCCEEDED(CoSetProxyBlanket(service.value, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE));
}
std::optional<QJsonValue> policyValue(const wchar_t *name)
{
    HKEY key = nullptr;
    const auto opened = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"Software\\Policies\\Microsoft\\Windows NT\\DNSClient", 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key);
    if (opened == ERROR_FILE_NOT_FOUND) return QJsonValue(QJsonValue::Null);
    if (opened != ERROR_SUCCESS) return {};
    auto close = qScopeGuard([&] { RegCloseKey(key); });
    DWORD type = 0, bytes = 0;
    auto result = RegQueryValueExW(key, name, nullptr, &type, nullptr, &bytes);
    if (result == ERROR_FILE_NOT_FOUND) return QJsonValue(QJsonValue::Null);
    if (result != ERROR_SUCCESS || bytes > 65536) return {};
    if (type == REG_DWORD && bytes == sizeof(DWORD)) {
        DWORD value = 0;
        if (RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<BYTE *>(&value), &bytes)
                != ERROR_SUCCESS) return {};
        return QJsonValue(double(value));
    }
    if (type != REG_SZ || bytes % sizeof(wchar_t)) return {};
    std::vector<wchar_t> value(bytes / sizeof(wchar_t) + 1, 0);
    if (RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<BYTE *>(value.data()), &bytes)
            != ERROR_SUCCESS) return {};
    return QJsonValue(QString::fromWCharArray(value.data()));
}
std::optional<QJsonArray> interfacePolicy(const GUID &guid)
{
    static const auto library = LoadLibraryExW(L"iphlpapi.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    using Get = DWORD (WINAPI *)(GUID, DNS_INTERFACE_SETTINGS *);
    using Free = void (WINAPI *)(DNS_INTERFACE_SETTINGS *);
    static const auto getSettings = library
        ? reinterpret_cast<Get>(GetProcAddress(library, "GetInterfaceDnsSettings")) : nullptr;
    static const auto freeSettings = library
        ? reinterpret_cast<Free>(GetProcAddress(library, "FreeInterfaceDnsSettings")) : nullptr;
    if (!getSettings || !freeSettings) return {};
    QJsonArray families;
    for (bool ipv6 : {false, true}) {
        DNS_INTERFACE_SETTINGS3 settings{};
        settings.Version = DNS_INTERFACE_SETTINGS_VERSION3;
        settings.Flags = ipv6 ? DNS_SETTING_IPV6 : 0;
        auto *base = reinterpret_cast<DNS_INTERFACE_SETTINGS *>(&settings);
        if (getSettings(guid, base) != NO_ERROR) return {};
        auto free = qScopeGuard([&] { freeSettings(base); });
        // This adapter currently forwards plain DNS only. A profile resolver
        // or DoH property cannot silently be dropped by changing NameServer.
        if (settings.cServerProperties || settings.cProfileServerProperties
                || settings.ServerProperties || settings.ProfileServerProperties
                || (settings.ProfileNameServer && *settings.ProfileNameServer)
                || (settings.Flags & ~ULONG64(0x3fff))) return {};
        const auto text = [](PCWSTR value) { return value ? QString::fromWCharArray(value) : QString(); };
        families.append(QJsonObject{
            {"ipv6", ipv6}, {"flags", QString::number(settings.Flags & ~ULONG64(DNS_SETTING_NAMESERVER), 16)},
            {"domain", text(settings.Domain)}, {"search", text(settings.SearchList)},
            {"profile", text(settings.ProfileNameServer)}, {"supplemental", text(settings.SupplementalSearchList)},
            {"registration", double(settings.RegistrationEnabled)},
            {"register_adapter", double(settings.RegisterAdapterName)}, {"llmnr", double(settings.EnableLLMNR)},
            {"query_adapter", double(settings.QueryAdapterName)},
            {"disable_unconstrained", double(settings.DisableUnconstrainedQueries)}});
    }
    return families;
}
bool noEffectiveNrpt(IWbemLocator *locator)
{
    Com<IWbemServices> service;
    if (!connect(locator, L"ROOT\\Microsoft\\Windows\\DNS", service)) return false;
    Bstr path(L"PS_DnsClientNrptPolicy"), method(L"Get");
    Com<IWbemClassObject> type, inputType, input, output;
    if (FAILED(service->GetObject(path, 0, nullptr, &type.value, nullptr))
            || FAILED(type->GetMethod(method, 0, &inputType.value, nullptr))
            || !inputType.value || FAILED(inputType->SpawnInstance(0, &input.value))) return false;
    VARIANT effective{};
    effective.vt = VT_BOOL;
    effective.boolVal = VARIANT_TRUE;
    if (FAILED(input->Put(L"Effective", 0, &effective, 0))
            || FAILED(service->ExecMethod(path, method, 0, nullptr, input.value, &output.value, nullptr)))
        return false;
    // Measured native provider contract: successful no-rule Get returns a null
    // output object; a real DNSSEC rule returns typed __PARAMETERS/SAFEARRAY.
    if (!output.value) return true;
    Variant status, rules;
    if (!get(output.value, L"ReturnValue", status, VT_I4) || status.value.lVal != 0) return false;
    if (FAILED(output->Get(L"CmdletOutput", 0, &rules.value, nullptr, nullptr))) return false;
    if (rules.value.vt == VT_NULL || rules.value.vt == VT_EMPTY) return true;
    if (rules.value.vt != (VT_ARRAY | VT_UNKNOWN) || !rules.value.parray
            || SafeArrayGetDim(rules.value.parray) != 1) return false;
    LONG lower = 0, upper = 0;
    return SUCCEEDED(SafeArrayGetLBound(rules.value.parray, 1, &lower))
        && SUCCEEDED(SafeArrayGetUBound(rules.value.parray, 1, &upper)) && upper < lower;
}
std::optional<QJsonArray> selectedDoh(IWbemLocator *locator, const QList<QHostAddress> &servers,
                                    bool includeActive)
{
    Com<IWbemServices> service;
    if (!connect(locator, L"ROOT\\StandardCimv2", service)) return {};
    Bstr language(L"WQL"), query(L"SELECT * FROM MSFT_DNSClientDohServerAddress");
    Com<IEnumWbemClassObject> rows;
    if (FAILED(service->ExecQuery(language, query, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                  nullptr, &rows.value))) return {};
    QMap<QString, QJsonObject> mappings;
    for (unsigned i = 0; i < 256; ++i) {
        Com<IWbemClassObject> row;
        ULONG count = 0;
        const auto result = rows->Next(5000, 1, &row.value, &count);
        if (result == WBEM_S_FALSE && count == 0) {
            QJsonArray ordered;
            QSet<QString> emitted;
            for (const auto &server : servers)
                if (mappings.contains(server.toString())
                        && (!includeActive || !emitted.contains(server.toString()))) {
                    ordered.append(mappings[server.toString()]);
                    emitted.insert(server.toString());
                }
            return ordered;
        }
        if (result != WBEM_S_NO_ERROR || count != 1 || !row.value) return {};
        Variant address, upgrade, fallback, uri;
        if (!get(row.value, L"ServerAddress", address, VT_BSTR)
                || !get(row.value, L"AutoUpgrade", upgrade, VT_BOOL)
                || !get(row.value, L"AllowFallbackToUdp", fallback, VT_BOOL)
                || !get(row.value, L"DohTemplate", uri, VT_BSTR)) return {};
        const QHostAddress ip(QString::fromWCharArray(address.value.bstrVal));
        if (ip.isNull()) return {};
        if (!servers.contains(ip)) continue;
        if (!includeActive && upgrade.value.boolVal != VARIANT_FALSE) return {};
        if (mappings.contains(ip.toString())) return {};
        mappings.insert(ip.toString(), QJsonObject{{"server", ip.toString()},
            {"template", QString::fromWCharArray(uri.value.bstrVal)},
            {"auto_upgrade", upgrade.value.boolVal != VARIANT_FALSE},
            {"allow_fallback", fallback.value.boolVal != VARIANT_FALSE}});
    }
    return {};
}
}
static std::optional<QJsonObject> capturePolicy(const QString &name,
                                              const QList<QHostAddress> &servers, bool selected)
{
    if (servers.isEmpty() || servers.size() > 32) return {};
    NET_LUID luid{};
    GUID guid{};
    if (ConvertInterfaceAliasToLuid(reinterpret_cast<LPCWSTR>(name.utf16()), &luid) != NO_ERROR
            || ConvertInterfaceLuidToGuid(&luid, &guid) != NO_ERROR) return {};
    const auto interfaces = interfacePolicy(guid);
    const auto doh = policyValue(L"DoHPolicy"), globalServers = policyValue(L"NameServer");
    if (!interfaces || !doh || !globalServers
            || (!doh->isNull() && *doh != QJsonValue(1))
            || (!globalServers->isNull() && *globalServers != QJsonValue(QString()))) return {};
    const auto initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(initialized) && initialized != RPC_E_CHANGED_MODE) return {};
    auto uninitialize = qScopeGuard([&] { if (SUCCEEDED(initialized)) CoUninitialize(); });
    Com<IWbemLocator> locator;
    if (FAILED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
            IID_IWbemLocator, reinterpret_cast<void **>(&locator.value))) || !noEffectiveNrpt(locator.value))
        return {};
    const auto mappings = selectedDoh(locator.value, servers, selected);
    if (!mappings) return {};
    return QJsonObject{{"reader", selected ? "windows-native-selected-dns-policy-v2"
                                         : "windows-native-plain-dns-policy-v1"},
        {"interface", *interfaces}, {"doh_policy", *doh}, {"global_servers", *globalServers},
        {"selected_doh_mappings", *mappings}, {"effective_nrpt", QJsonArray{}}};
}
std::optional<QJsonObject> WindowsDnsPolicy::capturePlain(const QString &name,
                                                       const QList<QHostAddress> &servers)
{
    return capturePolicy(name, servers, false);
}
std::optional<WindowsDnsPolicy::Selection> WindowsDnsPolicy::captureSelected(
    const QString &name, const QList<QHostAddress> &servers)
{
    const auto snapshot = capturePolicy(name, servers, true);
    if (!snapshot) return {};
    const auto policy = selectedResolverPolicy(servers, (*snapshot)["selected_doh_mappings"].toArray(),
        (*snapshot)["doh_policy"] == QJsonValue(1));
    if (!policy) return {};
    return Selection{*snapshot, *policy};
}
