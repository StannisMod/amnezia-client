#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#endif
#include <QtTest>
#include <QScopeGuard>
#include <QTemporaryDir>
#include <QNetworkInterface>
#include <QProcess>
#include <QUdpSocket>
#include <QTcpSocket>
#include <QJsonDocument>
#include <QJsonArray>
#include <QUuid>
#include <cstdlib>
#include "nativednsservice.h"
#ifdef Q_OS_WIN
#include "platforms/windows/daemon/windowsdnsrecovery.h"
#else
#include "platforms/macos/daemon/macosdnsrecovery.h"
#endif

namespace {
bool present(const QHostAddress &ip)
{
    for (const auto &iface : QNetworkInterface::allInterfaces())
        for (const auto &entry : iface.addressEntries())
            if (entry.ip() == ip) return true;
    return false;
}
bool interfaceUp(const QString &name)
{
    for (const auto &iface : QNetworkInterface::allInterfaces())
        if ((iface.name() == name || iface.humanReadableName() == name)
                && iface.flags().testFlag(QNetworkInterface::IsUp)) return true;
    return false;
}
bool dnsReply(const QHostAddress &ip, bool tcp, int type = 28, int rcode = 0)
{
    auto query = QByteArray::fromHex("123401000001000000000000076578616d706c65047465737400001c0001");
    query[query.size() - 3] = char(type);
    QByteArray response;
    if (tcp) {
        QTcpSocket socket;
        socket.connectToHost(ip, 53);
        if (!socket.waitForConnected(2000)) {
            qWarning() << "TCP alias connect failed" << ip << socket.errorString();
            return false;
        }
        auto data = QByteArray(2, '\0') + query;
        data[0] = char(query.size() >> 8);
        data[1] = char(query.size());
        if (socket.write(data) != data.size() || !socket.waitForBytesWritten(2000)) return false;
        while (socket.bytesAvailable() < 2)
            if (!socket.waitForReadyRead(2000)) return false;
        const auto length = socket.read(2);
        const int size = (quint8(length[0]) << 8) | quint8(length[1]);
        while (response.size() < size) {
            response += socket.read(size - response.size());
            if (response.size() < size && !socket.waitForReadyRead(2000)) return false;
        }
    } else {
        QUdpSocket socket;
        if (socket.writeDatagram(query, ip, 53) != query.size() || !socket.waitForReadyRead(2000)) {
            qWarning() << "UDP alias query failed" << ip << socket.errorString()
                       << socket.localAddress() << socket.localPort();
            return false;
        }
        response.resize(socket.pendingDatagramSize());
        if (socket.readDatagram(response.data(), response.size()) != response.size()) return false;
    }
    const bool valid = response.size() >= 12 && response.left(2) == query.left(2)
        && (quint8(response[2]) & 0x80) && (quint8(response[3]) & 15) == rcode
        && response[6] == 0 && response[7] == 0;
    if (!valid) qWarning() << "Unexpected alias DNS response" << ip << tcp << response.toHex();
    return valid;
}
#ifdef Q_OS_MACOS
CFStringRef cfString(const QString &text)
{
    return CFStringCreateWithCharacters(kCFAllocatorDefault,
        reinterpret_cast<const UniChar *>(text.utf16()), text.size());
}
#endif
}

class TestNativeDnsDesktopLifecycle : public QObject {
    Q_OBJECT
private slots:
    void initTestCase() {
        if (qEnvironmentVariable("AMNEZIA_NATIVE_DNS_DESKTOP_TEST") != "isolated-fixture")
            QSKIP("requires explicitly owned native fixture; not portable acceptance");
    }
    void crashChild() {
        const auto directory = qEnvironmentVariable("AMNEZIA_DNS_DESKTOP_CHILD_DIRECTORY");
        if (directory.isEmpty()) QSKIP("child-only abrupt termination fixture");
        const auto ifname = qEnvironmentVariable("AMNEZIA_DNS_DESKTOP_CHILD_INTERFACE");
        auto guard = createNativeDnsServiceGuard(directory);
        QList<QHostAddress> endpoints;
        QVERIFY(guard->prepare(ifname,
            {QHostAddress("2001:db8::53"), QHostAddress("2001:db8::53")}, endpoints));
        QCOMPARE(endpoints.size(), 2);
        QVERIFY(endpoints[0] != endpoints[1]); // Preserve duplicate resolver occurrences.
        QVERIFY(guard->healthy());
        for (const auto &endpoint : endpoints) {
            const bool udp = dnsReply(endpoint, false);
            const bool tcp = dnsReply(endpoint, true);
            qInfo() << "Actual alias DNS listeners:" << endpoint << "UDP" << udp << "TCP" << tcp;
            QVERIFY(udp);
            QVERIFY(tcp);
            QVERIFY(dnsReply(endpoint, false, 1, 2)); // IPv6-only upstream remains fail-closed.
            QVERIFY(dnsReply(endpoint, true, 1, 2));
        }
#ifdef Q_OS_WIN
        const auto snapshot = WindowsDnsRecovery::capture(ifname, endpoints);
        const auto backend = WindowsDnsRecovery::backend();
#else
        auto store = SCDynamicStoreCreate(kCFAllocatorDefault, CFSTR("amnezia-service-child"), nullptr, nullptr);
        QVERIFY(store);
        const auto snapshot = MacosDnsRecovery::captureServices(store,
            {qEnvironmentVariable("AMNEZIA_DNS_DESKTOP_CHILD_SERVICE")}, endpoints);
        const auto backend = MacosDnsRecovery::backend(store);
#endif
        QVERIFY(!snapshot.isEmpty());
        QVERIFY(guard->storeDnsRecovery(snapshot)); // Production durable journal.
        const auto stage = qEnvironmentVariable("AMNEZIA_DNS_DESKTOP_CHILD_STAGE");
        if (stage == "published")
            QVERIFY(DnsSettingsRecovery::apply(snapshot, snapshot["backend"].toString(), backend, false));
        else if (stage == "partial") {
            const auto entry = snapshot["entries"].toArray().first().toObject();
            QVERIFY(backend.write(entry["key"].toString(), entry["after"]));
        } else QCOMPARE(stage, QString("before"));
        std::_Exit(77); // Go listener/lease die, assigned aliases and journal remain.
    }
    void startupRecoveryAndAliasOwnership_data() {
        QTest::addColumn<QString>("stage");
        QTest::newRow("before-publication") << QString("before");
        QTest::newRow("partial-publication") << QString("partial");
        QTest::newRow("published") << QString("published");
    }
    void startupRecoveryAndAliasOwnership() {
        QFETCH(QString, stage);
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        directory.setAutoRemove(false); // Failed recovery evidence must survive.
        qInfo() << "Owned lifecycle recovery directory:" << directory.path();
#ifdef Q_OS_WIN
        const auto dll = qEnvironmentVariable("AMNEZIA_DNS_RECOVERY_WINTUN_DLL");
        QVERIFY(QDir::isAbsolutePath(dll));
        const HMODULE library = LoadLibraryExW(reinterpret_cast<LPCWSTR>(dll.utf16()), nullptr,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
        QVERIFY(library);
        auto unload = qScopeGuard([&] { FreeLibrary(library); });
        using Create = void *(WINAPI *)(LPCWSTR, LPCWSTR, const GUID *);
        using Close = void (WINAPI *)(void *);
        using Start = void *(WINAPI *)(void *, DWORD);
        const auto create = reinterpret_cast<Create>(GetProcAddress(library, "WintunCreateAdapter"));
        const auto close = reinterpret_cast<Close>(GetProcAddress(library, "WintunCloseAdapter"));
        const auto start = reinterpret_cast<Start>(GetProcAddress(library, "WintunStartSession"));
        const auto end = reinterpret_cast<Close>(GetProcAddress(library, "WintunEndSession"));
        QVERIFY(create && close && start && end);
        const auto ifname = "Amnezia-DNS-Recovery-" + QUuid::createUuid().toString(QUuid::WithoutBraces).left(8);
        void *adapter = create(reinterpret_cast<LPCWSTR>(ifname.utf16()), L"Amnezia DNS test", nullptr);
        QVERIFY(adapter);
        auto closeAdapter = qScopeGuard([&] { close(adapter); });
        void *session = start(adapter, 0x20000);
        QVERIFY(session);
        auto endSession = qScopeGuard([&] { end(session); });
        NET_LUID luid{};
        QCOMPARE(ConvertInterfaceAliasToLuid(reinterpret_cast<LPCWSTR>(ifname.utf16()), &luid), ULONG(NO_ERROR));
        MIB_UNICASTIPADDRESS_ROW address{};
        InitializeUnicastIpAddressEntry(&address);
        address.InterfaceLuid = luid;
        address.Address.Ipv4.sin_family = AF_INET;
        address.Address.Ipv4.sin_addr.s_addr = htonl(QHostAddress("192.0.2.10").toIPv4Address());
        address.OnLinkPrefixLength = 32;
        address.SkipAsSource = false; // Ordinary native primary; only managed aliases skip source selection.
        QCOMPARE(CreateUnicastIpAddressEntry(&address), ULONG(NO_ERROR));
        QTRY_VERIFY_WITH_TIMEOUT(interfaceUp(ifname), 5000);
        const auto backend = WindowsDnsRecovery::backend();
        const auto initial = WindowsDnsRecovery::capture(ifname, {QHostAddress("198.19.255.251")});
        QVERIFY(!initial.isEmpty());
        for (const auto &item : initial["entries"].toArray()) {
            const auto entry = item.toObject();
            const auto setting = entry["key"].toString();
            const QJsonArray servers{setting.startsWith("v6/") ? "2001:db8::54" : "192.0.2.54"};
            QVERIFY(backend.write(setting, QJsonObject{{"mode", "static"}, {"servers", servers}}));
        }
#else
        const QString ifname = "lo0";
        auto store = SCDynamicStoreCreate(kCFAllocatorDefault, CFSTR("amnezia-service-fixture"), nullptr, nullptr);
        QVERIFY(store);
        auto releaseStore = qScopeGuard([&] { CFRelease(store); });
        const auto service = "Setup:/Network/Service/" +
            QUuid::createUuid().toString(QUuid::WithoutBraces).toUpper();
        auto parent = cfString(service);
        QVERIFY(parent);
        auto existing = SCDynamicStoreCopyValue(store, parent);
        if (existing) { CFRelease(existing); CFRelease(parent); QFAIL("fixture UUID collision"); }
        auto value = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        QVERIFY(value);
        CFDictionarySetValue(value, CFSTR("UserDefinedName"), CFSTR("Amnezia owned service recovery fixture"));
        const bool created = SCDynamicStoreSetValue(store, parent, value);
        CFRelease(value);
        QVERIFY(created);
        const QString key = service + "/DNS";
        auto cleanup = qScopeGuard([&] {
            auto dnsPath = cfString(key);
            SCDynamicStoreRemoveValue(store, dnsPath);
            CFRelease(dnsPath);
            SCDynamicStoreRemoveValue(store, parent);
            CFRelease(parent);
        });
        const auto backend = MacosDnsRecovery::backend(store);
#endif
        QProcess child;
        auto environment = QProcessEnvironment::systemEnvironment();
        environment.insert("AMNEZIA_DNS_DESKTOP_CHILD_DIRECTORY", directory.path());
        environment.insert("AMNEZIA_DNS_DESKTOP_CHILD_INTERFACE", ifname);
        environment.insert("AMNEZIA_DNS_DESKTOP_CHILD_STAGE", stage);
#ifdef Q_OS_MACOS
        environment.insert("AMNEZIA_DNS_DESKTOP_CHILD_SERVICE", key);
#endif
        child.setProcessEnvironment(environment);
        child.start(QCoreApplication::applicationFilePath(), {"crashChild"});
        QVERIFY(child.waitForFinished(15000));
        const auto output = child.readAllStandardOutput() + child.readAllStandardError();
        QVERIFY2(child.exitCode() == 77, output.constData());
        const auto files = QDir(directory.path()).entryList({"owned-*.json"}, QDir::Files);
        QCOMPARE(files.size(), 1);
        const auto journalPath = directory.filePath(files.first());
        QFile journal(journalPath);
        QVERIFY(journal.open(QIODevice::ReadOnly));
        const auto bytes = journal.readAll();
        journal.close();
        const auto record = QJsonDocument::fromJson(bytes).object();
        QList<QHostAddress> aliases;
        for (const auto &value : record["installed"].toArray()) aliases.append(QHostAddress(value.toString()));
        QCOMPARE(aliases.size(), 2);
        for (const auto &alias : aliases) QVERIFY(present(alias));
        // Even a syntactically intact OS snapshot cannot authorize aliases
        // after the ownership journal was edited.
        QVERIFY(journal.open(QIODevice::Append));
        journal.write("\n");
        journal.close();
        QVERIFY(!recoverNativeDnsServiceOnStartup(directory.path()));
        for (const auto &alias : aliases) QVERIFY(present(alias));
        QVERIFY(journal.open(QIODevice::WriteOnly | QIODevice::Truncate));
        QCOMPARE(journal.write(bytes), qint64(bytes.size()));
        journal.close();
        const auto first = record["dns_recovery"].toObject()["entries"].toArray().first().toObject();
        const auto setting = first["key"].toString();
        const auto interrupted = backend.read(setting);
#ifdef Q_OS_WIN
        const QJsonValue external(QJsonObject{{"mode", "static"}, {"servers", QJsonArray{"192.0.2.99"}}});
#else
        const auto xml = QByteArray("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict>"
            "<key>DomainName</key><string>administrator.test</string></dict></plist>");
        const QJsonValue external(QString::fromLatin1(xml.toBase64()));
#endif
        QVERIFY(backend.write(setting, external));
        QVERIFY(!recoverNativeDnsServiceOnStartup(directory.path()));
        QVERIFY(backend.equal(backend.read(setting), external));
        for (const auto &alias : aliases) QVERIFY(present(alias));
        QVERIFY(QFileInfo::exists(journalPath));
        QVERIFY(backend.write(setting, interrupted));
        QVERIFY(recoverNativeDnsServiceOnStartup(directory.path()));
        for (const auto &alias : aliases) QVERIFY(!present(alias));
        QVERIFY(!QFileInfo::exists(journalPath));
        const auto snapshot = record["dns_recovery"].toObject();
        for (const auto &item : snapshot["entries"].toArray()) {
            const auto entry = item.toObject();
            QVERIFY(backend.equal(backend.read(entry["key"].toString()), entry["before"]));
        }
        QVERIFY(recoverNativeDnsServiceOnStartup(directory.path()));
        directory.setAutoRemove(true);
    }
};
QTEST_GUILESS_MAIN(TestNativeDnsDesktopLifecycle)
#include "testNativeDnsDesktopLifecycle.moc"
