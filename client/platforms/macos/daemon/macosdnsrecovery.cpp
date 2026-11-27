#include "macosdnsrecovery.h"
#include <QScopeGuard>
#include <QUuid>
#include <QMap>

namespace MacosDnsRecovery {
namespace {
const QString kind = "macos-dynamic-store-plist-v1";
QJsonValue encode(CFPropertyListRef value)
{
    if (!value) return QJsonValue(QJsonValue::Null);
    CFDataRef data = CFPropertyListCreateData(kCFAllocatorDefault, value,
                                             kCFPropertyListBinaryFormat_v1_0, 0, nullptr);
    if (!data) return QJsonValue(QJsonValue::Undefined);
    auto release = qScopeGuard([&] { CFRelease(data); });
    const auto bytes = QByteArray(reinterpret_cast<const char *>(CFDataGetBytePtr(data)),
                                 CFDataGetLength(data));
    return QString::fromLatin1(bytes.toBase64());
}
CFDictionaryRef decode(const QJsonValue &value)
{
    if (!value.isString()) return nullptr;
    const auto encoded = value.toString().toLatin1();
    const auto bytes = QByteArray::fromBase64(encoded, QByteArray::AbortOnBase64DecodingErrors);
    if (bytes.isEmpty() || bytes.toBase64() != encoded || bytes.size() > 65536) return nullptr;
    CFDataRef data = CFDataCreate(kCFAllocatorDefault,
        reinterpret_cast<const UInt8 *>(bytes.constData()), bytes.size());
    if (!data) return nullptr;
    auto release = qScopeGuard([&] { CFRelease(data); });
    auto plist = CFPropertyListCreateWithData(kCFAllocatorDefault, data,
                                              kCFPropertyListImmutable, nullptr, nullptr);
    if (!plist) return nullptr;
    if (CFGetTypeID(plist) != CFDictionaryGetTypeID()) { CFRelease(plist); return nullptr; }
    return static_cast<CFDictionaryRef>(plist);
}
bool validKey(const QString &key)
{
    const auto id = key.mid(QString("Setup:/Network/Service/").size()).section('/', 0, 0);
    return !QUuid(id).isNull() && key == "Setup:/Network/Service/" + id + "/DNS";
}
CFStringRef cfString(const QString &text)
{
    return CFStringCreateWithCharacters(kCFAllocatorDefault,
        reinterpret_cast<const UniChar *>(text.utf16()), text.size());
}
QJsonValue read(SCDynamicStoreRef store, const QString &key)
{
    if (!store || !validKey(key)) return QJsonValue(QJsonValue::Undefined);
    // Do not recreate a removed service during recovery.
    auto parent = cfString(key.chopped(4));
    if (!parent) return QJsonValue(QJsonValue::Undefined);
    auto service = SCDynamicStoreCopyValue(store, parent);
    CFRelease(parent);
    if (!service) return QJsonValue(QJsonValue::Undefined);
    CFRelease(service);
    auto path = cfString(key);
    if (!path) return QJsonValue(QJsonValue::Undefined);
    auto value = SCDynamicStoreCopyValue(store, path);
    CFRelease(path);
    if (!value) {
        if (SCError() == kSCStatusNoKey) return QJsonValue(QJsonValue::Null);
        return QJsonValue(QJsonValue::Undefined);
    }
    auto release = qScopeGuard([&] { CFRelease(value); });
    if (CFGetTypeID(value) != CFDictionaryGetTypeID()) return QJsonValue(QJsonValue::Undefined);
    return encode(value);
}
}
DnsSettingsRecovery::Backend backend(SCDynamicStoreRef store)
{
    return {
        [store](const QString &key) { return read(store, key); },
        [store](const QString &key, const QJsonValue &value) {
            if (read(store, key).isUndefined()) return false;
            auto path = cfString(key);
            if (!path) return false;
            auto release = qScopeGuard([&] { CFRelease(path); });
            if (value.isNull())
                return SCDynamicStoreRemoveValue(store, path) || SCError() == kSCStatusNoKey;
            auto dict = decode(value);
            if (!dict) return false;
            const bool result = SCDynamicStoreSetValue(store, path, dict);
            CFRelease(dict);
            return result;
        },
        [](const QJsonValue &a, const QJsonValue &b) {
            if (a.isNull() || b.isNull()) return a.isNull() && b.isNull();
            auto left = decode(a);
            auto right = decode(b);
            const bool equal = left && right && CFEqual(left, right);
            if (left) CFRelease(left);
            if (right) CFRelease(right);
            return equal;
        }
    };
}
QJsonObject capture(SCDynamicStoreRef store, const QList<QHostAddress> &endpoints,
                    const QJsonObject &previous)
{
    if (!store || endpoints.isEmpty()) return {};
    CFArrayRef services = SCDynamicStoreCopyKeyList(store, CFSTR("^Setup:/Network/Service/[0-9A-F-]+$"));
    if (!services) return {};
    auto release = qScopeGuard([&] { CFRelease(services); });
    QStringList keys;
    for (CFIndex i = 0; i < CFArrayGetCount(services); ++i) {
        auto service = static_cast<CFStringRef>(CFArrayGetValueAtIndex(services, i));
        if (CFGetTypeID(service) != CFStringGetTypeID()) return {};
        QString text(CFStringGetLength(service), QChar(0));
        CFStringGetCharacters(service, CFRangeMake(0, text.size()),
                              reinterpret_cast<UniChar *>(text.data()));
        keys.append(text + "/DNS");
    }
    return captureServices(store, keys, endpoints, previous);
}
QJsonObject captureServices(SCDynamicStoreRef store, const QStringList &dnsKeys,
                            const QList<QHostAddress> &endpoints, const QJsonObject &previous)
{
    if (!store || dnsKeys.isEmpty() || endpoints.isEmpty()) return {};
    QMap<QString, QJsonObject> old;
    const auto transport = backend(store);
    if (!previous.isEmpty()) {
        if (previous["backend"] != QJsonValue(kind) || !previous["entries"].isArray()) return {};
        for (const auto &item : previous["entries"].toArray()) {
            const auto entry = item.toObject();
            const auto key = entry["key"].toString();
            const auto current = transport.read(key);
            if (!validKey(key) || old.contains(key) || current.isUndefined()
                    || !transport.equal(current, entry["after"])) return {};
            old.insert(key, entry);
        }
    }
    QJsonArray entries;
    QSet<QString> seen;
    for (const auto &key : dnsKeys) {
        if (!validKey(key) || seen.contains(key)) return {};
        seen.insert(key);
        const auto current = transport.read(key);
        if (current.isUndefined()) return {};
        const auto before = old.contains(key) ? old[key]["before"] : current;
        auto original = before.isNull() ? nullptr : decode(before);
        if (!before.isNull() && !original) return {};
        auto dict = original ? CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, original)
            : CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        if (original) CFRelease(original);
        if (!dict) return {};
        auto dictRelease = qScopeGuard([&] { CFRelease(dict); });
        auto servers = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
        if (!servers) return {};
        auto serversRelease = qScopeGuard([&] { CFRelease(servers); });
        for (const auto &ip : endpoints) {
            if (ip.protocol() != QAbstractSocket::IPv4Protocol) return {};
            auto address = cfString(ip.toString());
            if (!address) return {};
            CFArrayAppendValue(servers, address);
            CFRelease(address);
        }
        CFDictionarySetValue(dict, kSCPropNetDNSServerAddresses, servers);
        const auto after = encode(dict);
        if (after.isUndefined()) return {};
        entries.append(QJsonObject{{"key", key}, {"before", before}, {"after", after}});
    }
    for (auto it = old.begin(); it != old.end(); ++it)
        if (!seen.contains(it.key())) return {};
    if (entries.isEmpty()) return {};
    return {{"backend", kind}, {"entries", entries}};
}
bool apply(SCDynamicStoreRef store, const QJsonObject &snapshot, bool restoring)
{
    return DnsSettingsRecovery::apply(snapshot, kind, backend(store), restoring);
}
}
