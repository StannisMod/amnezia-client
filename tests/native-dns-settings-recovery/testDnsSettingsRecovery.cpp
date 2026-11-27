#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <fwpmu.h>
#endif
#include <QtTest>
#include "daemon/dnssettingsrecovery.h"
#include <QSaveFile>
#include <QTemporaryDir>
#include <QProcess>
#include <QScopeGuard>
#include <QUuid>
#include <cstdlib>
#ifdef Q_OS_MACOS
#include "platforms/macos/daemon/macosdnsrecovery.h"
#elif defined(Q_OS_WIN)
#include "platforms/windows/daemon/windowsdnsrecovery.h"
#include "platforms/windows/daemon/nativednsfirewall.h"
#endif

class TestDnsSettingsRecovery : public QObject {
    Q_OBJECT
    const QString kind = "fixture";
    const QJsonObject snapshot{{"backend", "fixture"}, {"entries", QJsonArray{
        QJsonObject{{"key", "first"}, {"before", QJsonValue(QJsonValue::Null)}, {"after", "managed1"}},
        QJsonObject{{"key", "second"}, {"before", "original"}, {"after", "managed2"}}}}};
private slots:
#ifdef Q_OS_WIN
    void windowsDnsLeaseIsLocalIpv4OnlyAndOwned() {
        if (qEnvironmentVariable("AMNEZIA_NATIVE_DNS_SETTINGS_TEST") != "isolated-fixture")
            QSKIP("requires the owned native Windows fixture");
        QVERIFY(!NativeDnsFirewall::openLease({QHostAddress("2001:db8::53")}));
        QVERIFY(!NativeDnsFirewall::openLease({QHostAddress("192.0.2.53")}));
        HANDLE lease = NativeDnsFirewall::openLease({QHostAddress("198.19.255.251")});
        QVERIFY(lease);
        auto close = qScopeGuard([&] { FwpmEngineClose0(lease); });
        HANDLE enumeration = nullptr;
        QCOMPARE(FwpmFilterCreateEnumHandle0(lease, nullptr, &enumeration), DWORD(ERROR_SUCCESS));
        auto destroy = qScopeGuard([&] { FwpmFilterDestroyEnumHandle0(lease, enumeration); });
        int owned = 0;
        for (;;) {
            FWPM_FILTER0 **filters = nullptr;
            UINT32 count = 0;
            QCOMPARE(FwpmFilterEnum0(lease, enumeration, 1024, &filters, &count), DWORD(ERROR_SUCCESS));
            auto release = qScopeGuard([&] { if (filters) FwpmFreeMemory0(reinterpret_cast<void **>(&filters)); });
            if (!count) break;
            for (UINT32 i = 0; i < count; ++i) {
                const auto &filter = *filters[i];
                if (QString::fromWCharArray(filter.displayData.name) != "Amnezia native DNS local IPv4") continue;
                ++owned;
                QVERIFY(IsEqualGUID(filter.subLayerKey, NativeDnsFirewall::baselineSublayer));
                QVERIFY(IsEqualGUID(filter.layerKey, FWPM_LAYER_ALE_AUTH_CONNECT_V4)
                        || IsEqualGUID(filter.layerKey, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4));
                QCOMPARE(filter.action.type, FWP_ACTION_PERMIT);
                QCOMPARE(filter.numFilterConditions, UINT32(4));
                bool local = false, port = false, address = false, protocol = false;
                for (UINT32 j = 0; j < filter.numFilterConditions; ++j) {
                    const auto &condition = filter.filterCondition[j];
                    if (IsEqualGUID(condition.fieldKey, FWPM_CONDITION_FLAGS)) {
                        QCOMPARE(condition.matchType, FWP_MATCH_FLAGS_ALL_SET);
                        QCOMPARE(condition.conditionValue.type, FWP_UINT32);
                        QCOMPARE(condition.conditionValue.uint32, UINT32(FWP_CONDITION_FLAG_IS_LOOPBACK));
                        local = true;
                    } else if (IsEqualGUID(condition.fieldKey, FWPM_CONDITION_IP_LOCAL_PORT)
                               || IsEqualGUID(condition.fieldKey, FWPM_CONDITION_IP_REMOTE_PORT)) {
                        QCOMPARE(condition.matchType, FWP_MATCH_EQUAL);
                        QCOMPARE(condition.conditionValue.type, FWP_UINT16);
                        QCOMPARE(condition.conditionValue.uint16, UINT16(53));
                        port = true;
                    } else if (IsEqualGUID(condition.fieldKey, FWPM_CONDITION_IP_LOCAL_ADDRESS)
                               || IsEqualGUID(condition.fieldKey, FWPM_CONDITION_IP_REMOTE_ADDRESS)) {
                        QCOMPARE(condition.matchType, FWP_MATCH_EQUAL);
                        QCOMPARE(condition.conditionValue.type, FWP_V4_ADDR_MASK);
                        QVERIFY(condition.conditionValue.v4AddrMask);
                        QCOMPARE(condition.conditionValue.v4AddrMask->addr, QHostAddress("198.19.255.251").toIPv4Address());
                        QCOMPARE(condition.conditionValue.v4AddrMask->mask, UINT32(0xffffffffu));
                        address = true;
                    } else if (IsEqualGUID(condition.fieldKey, FWPM_CONDITION_IP_PROTOCOL)) {
                        QCOMPARE(condition.matchType, FWP_MATCH_EQUAL);
                        QCOMPARE(condition.conditionValue.type, FWP_UINT8);
                        QVERIFY(condition.conditionValue.uint8 == IPPROTO_UDP || condition.conditionValue.uint8 == IPPROTO_TCP);
                        protocol = true;
                    }
                }
                QVERIFY(local && port && address && protocol);
            }
        }
        QCOMPARE(owned, 4);
    }
#endif
    void nativeCrashChild() {
        const auto path = qEnvironmentVariable("AMNEZIA_DNS_SETTINGS_CRASH_SNAPSHOT");
        if (path.isEmpty()) QSKIP("child-only abrupt termination fixture");
        QFile file(path);
        QVERIFY(file.open(QIODevice::ReadOnly));
        const auto snapshot = QJsonDocument::fromJson(file.readAll()).object();
        QVERIFY(!snapshot.isEmpty());
#ifdef Q_OS_MACOS
        auto store = SCDynamicStoreCreate(kCFAllocatorDefault, CFSTR("amnezia-recovery-child"), nullptr, nullptr);
        QVERIFY(store);
        const auto backend = MacosDnsRecovery::backend(store);
#elif defined(Q_OS_WIN)
        const auto backend = WindowsDnsRecovery::backend();
#else
        QFAIL("native crash fixture requires a native Windows/macOS host");
#endif
#if defined(Q_OS_MACOS) || defined(Q_OS_WIN)
        const auto stage = qEnvironmentVariable("AMNEZIA_DNS_SETTINGS_CRASH_STAGE");
        if (stage == "partial") {
            const auto entry = snapshot["entries"].toArray().first().toObject();
            QVERIFY(backend.write(entry["key"].toString(), entry["after"]));
            QVERIFY(backend.equal(backend.read(entry["key"].toString()), entry["after"]));
        } else if (stage == "published") {
            QVERIFY(DnsSettingsRecovery::apply(snapshot, snapshot["backend"].toString(), backend, false));
        } else QCOMPARE(stage, QString("before"));
        std::_Exit(77);
#endif
    }
    void nativeSnapshotCrashRestore_data() {
        QTest::addColumn<QString>("stage");
        QTest::addColumn<bool>("staticDns");
        for (const auto &stage : {QString("before"), QString("partial"), QString("published")})
            for (bool mode : {false, true})
                QTest::newRow(qPrintable(stage + (mode ? "-static" : "-automatic-or-absent")))
                    << stage << mode;
    }
    void nativeSnapshotCrashRestore() {
        if (qEnvironmentVariable("AMNEZIA_NATIVE_DNS_SETTINGS_TEST") != "isolated-fixture")
            QSKIP("requires an explicitly isolated native OS fixture; portable success is not native acceptance");
        QFETCH(QString, stage);
        QFETCH(bool, staticDns);
#ifdef Q_OS_MACOS
        auto store = SCDynamicStoreCreate(kCFAllocatorDefault, CFSTR("amnezia-recovery-fixture"), nullptr, nullptr);
        QVERIFY(store);
        auto releaseStore = qScopeGuard([&] { CFRelease(store); });
        QStringList keys;
        QList<CFStringRef> parents;
        auto cleanup = qScopeGuard([&] {
            for (const auto &key : keys) {
                auto path = CFStringCreateWithCharacters(kCFAllocatorDefault,
                    reinterpret_cast<const UniChar *>(key.utf16()), key.size());
                if (!SCDynamicStoreRemoveValue(store, path) && SCError() != kSCStatusNoKey)
                    QTest::qFail("could not remove owned fixture DNS", __FILE__, __LINE__);
                CFRelease(path);
            }
            for (auto parent : parents) {
                if (!SCDynamicStoreRemoveValue(store, parent))
                    QTest::qFail("could not remove owned fixture service", __FILE__, __LINE__);
                CFRelease(parent);
            }
        });
        for (int i = 0; i < 2; ++i) {
            const auto id = QUuid::createUuid().toString(QUuid::WithoutBraces).toUpper();
            const auto text = "Setup:/Network/Service/" + id;
            auto parent = CFStringCreateWithCharacters(kCFAllocatorDefault,
                reinterpret_cast<const UniChar *>(text.utf16()), text.size());
            auto existing = SCDynamicStoreCopyValue(store, parent);
            if (existing) { CFRelease(existing); CFRelease(parent); QFAIL("fixture UUID collision"); }
            auto dict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
            QVERIFY(dict);
            CFDictionarySetValue(dict, CFSTR("UserDefinedName"), CFSTR("Amnezia isolated DNS recovery fixture"));
            const bool created = SCDynamicStoreSetValue(store, parent, dict);
            CFRelease(dict);
            if (!created) { CFRelease(parent); QFAIL("could not create isolated service dictionary"); }
            parents.append(parent);
            keys.append(text + "/DNS");
        }
        const auto backend = MacosDnsRecovery::backend(store);
        // First service starts with no DNS dictionary. Second retains unknown
        // metadata and ordered supplemental/search domains across publication.
        const auto xml = QByteArray("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict>"
            "<key>ServerAddresses</key><array><string>192.0.2.53</string><string>2001:db8::53</string></array>"
            "<key>DomainName</key><string>scope.test</string>"
            "<key>SearchDomains</key><array><string>one.test</string><string>two.test</string></array>"
            "<key>SupplementalMatchDomains</key><array><string>private.test</string></array>"
            "<key>AmneziaFixtureUnknownMetadata</key><integer>17</integer></dict></plist>");
        QVERIFY(backend.write(keys[1], QString::fromLatin1(xml.toBase64())));
        if (staticDns) QVERIFY(backend.write(keys[0], QString::fromLatin1(xml.toBase64())));
        // Read-only check of production enumeration: DNS child keys must not
        // be mistaken for parent services and acquire a second /DNS suffix.
        const auto enumerated = MacosDnsRecovery::capture(store, {QHostAddress("198.19.255.251")});
        QVERIFY(!enumerated.isEmpty());
        QSet<QString> enumeratedKeys;
        for (const auto &item : enumerated["entries"].toArray()) {
            const auto key = item.toObject()["key"].toString();
            QVERIFY(!key.endsWith("/DNS/DNS"));
            enumeratedKeys.insert(key);
        }
        for (const auto &key : keys) QVERIFY(enumeratedKeys.contains(key));
        const auto snapshot = MacosDnsRecovery::captureServices(
            store, keys, {QHostAddress("198.19.255.251")});
#elif defined(Q_OS_WIN)
        const auto dllPath = qEnvironmentVariable("AMNEZIA_DNS_RECOVERY_WINTUN_DLL");
        QVERIFY2(QDir::isAbsolutePath(dllPath), "requires the existing pinned Wintun DLL's absolute path");
        const HMODULE library = LoadLibraryExW(reinterpret_cast<LPCWSTR>(dllPath.utf16()), nullptr,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
        QVERIFY2(library, "could not load existing Wintun DLL");
        auto unload = qScopeGuard([&] { FreeLibrary(library); });
        using CreateAdapter = void *(WINAPI *)(LPCWSTR, LPCWSTR, const GUID *);
        using CloseAdapter = void (WINAPI *)(void *);
        const auto create = reinterpret_cast<CreateAdapter>(GetProcAddress(library, "WintunCreateAdapter"));
        const auto close = reinterpret_cast<CloseAdapter>(GetProcAddress(library, "WintunCloseAdapter"));
        QVERIFY(create && close);
        const auto name = "Amnezia-DNS-Recovery-" + QUuid::createUuid().toString(QUuid::WithoutBraces).left(8);
        void *adapter = create(reinterpret_cast<LPCWSTR>(name.utf16()), L"Amnezia DNS test", nullptr);
        QVERIFY2(adapter, "could not create owned disposable Wintun adapter");
        auto closeAdapter = qScopeGuard([&] { close(adapter); });
        const auto backend = WindowsDnsRecovery::backend();
        if (staticDns) {
            const auto initial = WindowsDnsRecovery::capture(name, {QHostAddress("198.19.255.251")});
            QVERIFY(!initial.isEmpty());
            for (const auto &item : initial["entries"].toArray()) {
                const auto entry = item.toObject();
                const auto key = entry["key"].toString();
                const QJsonArray servers{key.startsWith("v6/") ? "2001:db8::53" : "192.0.2.53"};
                QVERIFY(backend.write(key, QJsonObject{{"mode", "static"}, {"servers", servers}}));
            }
        }
        const auto snapshot = WindowsDnsRecovery::capture(name, {QHostAddress("198.19.255.251")});
#else
        QSKIP("native OS verification requires Windows or macOS");
#endif
#if defined(Q_OS_MACOS) || defined(Q_OS_WIN)
        QVERIFY(!snapshot.isEmpty());
        const auto entries = snapshot["entries"].toArray();
        QCOMPARE(entries.size(), 2);
        auto restoreOwnedFixture = qScopeGuard([&] {
            // Revert only this explicitly owned fixture, even if an assertion
            // interrupts the scenario. This is not production recovery.
            for (const auto &item : entries) {
                const auto entry = item.toObject();
                if (!backend.write(entry["key"].toString(), entry["before"]))
                    QTest::qFail("could not restore owned fixture settings", __FILE__, __LINE__);
            }
        });
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        const auto path = directory.filePath("snapshot.json");
        QSaveFile journal(path);
        QVERIFY(journal.open(QIODevice::WriteOnly));
        const auto bytes = QJsonDocument(snapshot).toJson();
        QCOMPARE(journal.write(bytes), qint64(bytes.size()));
        QVERIFY(journal.commit());
        QProcess child;
        auto environment = QProcessEnvironment::systemEnvironment();
        environment.insert("AMNEZIA_DNS_SETTINGS_CRASH_SNAPSHOT", path);
        environment.insert("AMNEZIA_DNS_SETTINGS_CRASH_STAGE", stage);
        child.setProcessEnvironment(environment);
        child.start(QCoreApplication::applicationFilePath(), {"nativeCrashChild"});
        QVERIFY(child.waitForFinished(15000));
        const auto output = child.readAllStandardOutput() + child.readAllStandardError();
        QVERIFY2(child.exitCode() == 77, output.constData());
        // Re-open durable state rather than using the in-memory snapshot.
        QFile saved(path);
        QVERIFY(saved.open(QIODevice::ReadOnly));
        const auto recovered = QJsonDocument::fromJson(saved.readAll()).object();
        QCOMPARE(recovered, snapshot);
        const auto first = entries.first().toObject();
        const auto key = first["key"].toString();
        const auto interruptedState = backend.read(key);
#ifdef Q_OS_MACOS
        const auto externalXml = QByteArray("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict>"
            "<key>DomainName</key><string>administrator.test</string></dict></plist>");
        const QJsonValue external(QString::fromLatin1(externalXml.toBase64()));
#else
        const QJsonValue external(QJsonObject{{"mode", "static"},
            {"servers", QJsonArray{"192.0.2.99"}}});
#endif
        QVERIFY(backend.write(key, external));
        QVERIFY(!DnsSettingsRecovery::apply(recovered, recovered["backend"].toString(), backend, true));
        QVERIFY(backend.equal(backend.read(key), external));
        QVERIFY(backend.write(key, interruptedState));
        QVERIFY(DnsSettingsRecovery::apply(recovered, recovered["backend"].toString(), backend, true));
        for (const auto &item : entries) {
            const auto entry = item.toObject();
            QVERIFY(backend.equal(backend.read(entry["key"].toString()), entry["before"]));
        }
        QVERIFY(DnsSettingsRecovery::apply(recovered, recovered["backend"].toString(), backend, true));
#endif
    }
    void publicationAndRestorePreserveAbsenceAndAreIdempotent() {
        QMap<QString, QJsonValue> state{{"first", QJsonValue(QJsonValue::Null)}, {"second", "original"}};
        const auto before = state;
        int writes = 0;
        DnsSettingsRecovery::Backend backend{
            [&](const QString &key) { return state.value(key, QJsonValue(QJsonValue::Undefined)); },
            [&](const QString &key, const QJsonValue &value) { ++writes; state[key] = value; return true; }};
        QVERIFY(DnsSettingsRecovery::apply(snapshot, kind, backend, false));
        QCOMPARE(state["first"], QJsonValue("managed1"));
        QVERIFY(DnsSettingsRecovery::apply(snapshot, kind, backend, false));
        QCOMPARE(writes, 2);
        QVERIFY(DnsSettingsRecovery::apply(snapshot, kind, backend, true));
        QCOMPARE(state, before);
        QVERIFY(DnsSettingsRecovery::apply(snapshot, kind, backend, true));
        QCOMPARE(writes, 4);
    }
    void interruptedPublicationAndRestorationCanResume() {
        QMap<QString, QJsonValue> state{{"first", QJsonValue(QJsonValue::Null)}, {"second", "original"}};
        const auto before = state;
        int writes = 0;
        DnsSettingsRecovery::Backend backend{
            [&](const QString &key) { return state.value(key, QJsonValue(QJsonValue::Undefined)); },
            [&](const QString &key, const QJsonValue &value) {
                if (++writes == 2) return false;
                state[key] = value; return true;
            }};
        QVERIFY(!DnsSettingsRecovery::apply(snapshot, kind, backend, false));
        QCOMPARE(state["first"], QJsonValue("managed1"));
        QVERIFY(DnsSettingsRecovery::apply(snapshot, kind, backend, true));
        QCOMPARE(state, before);
        QVERIFY(DnsSettingsRecovery::apply(snapshot, kind, backend, false));
        writes = 0;
        QVERIFY(!DnsSettingsRecovery::apply(snapshot, kind, backend, true));
        QVERIFY(DnsSettingsRecovery::apply(snapshot, kind, backend, true));
        QCOMPARE(state, before);
    }
    void externalChangeOrUnreadableSettingPreventsEveryWrite() {
        QMap<QString, QJsonValue> state{{"first", "managed1"}, {"second", "administrator"}};
        int writes = 0;
        DnsSettingsRecovery::Backend backend{
            [&](const QString &key) { return state.value(key, QJsonValue(QJsonValue::Undefined)); },
            [&](const QString &, const QJsonValue &) { ++writes; return true; }};
        QVERIFY(!DnsSettingsRecovery::apply(snapshot, kind, backend, true));
        QCOMPARE(writes, 0);
        state.remove("second");
        QVERIFY(!DnsSettingsRecovery::apply(snapshot, kind, backend, true));
        QCOMPARE(writes, 0);
    }
    void lateChangeCannotConfirmCleanup() {
        QMap<QString, QJsonValue> state{{"first", "managed1"}, {"second", "managed2"}};
        DnsSettingsRecovery::Backend backend{
            [&](const QString &key) { return state.value(key, QJsonValue(QJsonValue::Undefined)); },
            [&](const QString &key, const QJsonValue &value) {
                state[key] = value;
                if (key == "second") state["first"] = "administrator";
                return true;
            }};
        QVERIFY(!DnsSettingsRecovery::apply(snapshot, kind, backend, true));
        QCOMPARE(state["first"], QJsonValue("administrator"));
    }
    void malformedOrDuplicateRecordCannotAuthorizeWrites() {
        int writes = 0;
        DnsSettingsRecovery::Backend backend{
            [](const QString &) { return QJsonValue("managed1"); },
            [&](const QString &, const QJsonValue &) { ++writes; return true; }};
        auto invalid = snapshot;
        auto entries = invalid["entries"].toArray();
        entries.append(entries.first());
        invalid["entries"] = entries;
        QVERIFY(!DnsSettingsRecovery::apply(invalid, kind, backend, true));
        QVERIFY(!DnsSettingsRecovery::apply(snapshot, "unknown-backend", backend, true));
        QCOMPARE(writes, 0);
    }
#ifdef Q_OS_MACOS
    void macosPlistComparisonPreservesUnknownMetadataAndIgnoresDictionaryOrder() {
        const auto plist = [](const QByteArray &body) {
            const auto xml = QByteArray("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict>")
                + body + "</dict></plist>";
            return QJsonValue(QString::fromLatin1(xml.toBase64()));
        };
        const auto first = plist("<key>DomainName</key><string>scope.test</string>"
                                 "<key>SupplementalMatchDomains</key><array><string>private.test</string></array>");
        const auto reordered = plist("<key>SupplementalMatchDomains</key><array><string>private.test</string></array>"
                                     "<key>DomainName</key><string>scope.test</string>");
        const auto changed = plist("<key>DomainName</key><string>administrator.test</string>");
        const auto backend = MacosDnsRecovery::backend(nullptr);
        QVERIFY(backend.equal(first, reordered));
        QVERIFY(!backend.equal(first, changed));
        QVERIFY(!backend.equal(first, QJsonValue(QJsonValue::Null)));
        QVERIFY(!backend.equal(QJsonValue("invalid-base64"), QJsonValue("invalid-base64")));
    }
#endif
};
QTEST_GUILESS_MAIN(TestDnsSettingsRecovery)
#include "testDnsSettingsRecovery.moc"
