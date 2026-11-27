#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windns.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <QtTest>
#include <QFile>
#include <QDir>
#include <QJsonArray>
#include <QJsonDocument>
#include <QNetworkInterface>
#include <QProcess>
#include <QScopeGuard>
#include <QTcpSocket>
#include <QUdpSocket>
#include <QUuid>
#include <vector>
#include <cstring>
#include "core/protocols/ikev2VpnProtocolWindows.h"
#include "core/protocols/protocolUtils.h"
#include "core/utils/constants/configKeys.h"
#include "windowsdnsrecovery.h"
#include "ipc.h"

namespace {
QByteArray query(quint16 type, const QByteArray &label = "ikev2-native")
{
    auto data = QByteArray::fromHex("4b6a01000001000000000000");
    for (const auto &part : {label, QByteArray("test")}) {
        data.append(char(part.size()));
        data.append(part);
    }
    data.append('\0');
    data.append(char(type >> 8)); data.append(char(type));
    data.append('\0'); data.append('\1');
    return data;
}
QByteArray exchange(const QHostAddress &server, quint16 type, bool tcp,
                    const QByteArray &label = "ikev2-native")
{
    const auto packet = query(type, label);
    if (!tcp) {
        QUdpSocket socket;
        if (socket.writeDatagram(packet, server, 53) != packet.size()
                || !socket.waitForReadyRead(3000)) return {};
        QByteArray result(65535, 0);
        const auto size = socket.readDatagram(result.data(), result.size());
        return size < 0 ? QByteArray{} : result.left(size);
    }
    QTcpSocket socket;
    socket.connectToHost(server, 53);
    if (!socket.waitForConnected(3000)) return {};
    QByteArray frame;
    frame.append(char(packet.size() >> 8)); frame.append(char(packet.size())); frame.append(packet);
    if (socket.write(frame) != frame.size() || !socket.waitForBytesWritten(3000)) return {};
    auto read = [&](qsizetype count) {
        while (socket.bytesAvailable() < count)
            if (!socket.waitForReadyRead(3000)) return QByteArray{};
        return socket.read(count);
    };
    const auto header = read(2);
    if (header.size() != 2) return {};
    return read((quint8(header[0]) << 8) | quint8(header[1]));
}
bool nodata(const QByteArray &packet)
{
    return packet.size() >= 12 && packet.left(2) == query(28).left(2)
        && (quint8(packet[3]) & 15) == 0 && packet.mid(6, 2) == QByteArray(2, 0);
}
QList<QHostAddress> aliases()
{
    QList<QHostAddress> result;
    for (const auto &iface : QNetworkInterface::allInterfaces())
        for (const auto &entry : iface.addressEntries())
            if (entry.ip().isInSubnet(QHostAddress("198.19.255.0"), 24))
                result.append(entry.ip());
    return result;
}
QList<QHostAddress> selectedDns(int index)
{
    ULONG size = 0;
    if (GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, nullptr, &size) != ERROR_BUFFER_OVERFLOW)
        return {};
    std::vector<BYTE> storage(size);
    auto *first = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(storage.data());
    if (GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, first, &size) != NO_ERROR) return {};
    QList<QHostAddress> result;
    for (auto *adapter = first; adapter; adapter = adapter->Next) {
        if (adapter->IfIndex != ULONG(index)) continue;
        for (auto *dns = adapter->FirstDnsServerAddress; dns; dns = dns->Next) {
            if (!dns->Address.lpSockaddr) return {};
            if (dns->Address.lpSockaddr->sa_family == AF_INET
                    && dns->Address.iSockaddrLength >= sizeof(sockaddr_in)) {
                const auto *ip = reinterpret_cast<const sockaddr_in *>(dns->Address.lpSockaddr);
                result.append(QHostAddress(ntohl(ip->sin_addr.s_addr)));
            } else if (dns->Address.lpSockaddr->sa_family == AF_INET6
                    && dns->Address.iSockaddrLength >= sizeof(sockaddr_in6)) {
                const auto *ip = reinterpret_cast<const sockaddr_in6 *>(dns->Address.lpSockaddr);
                Q_IPV6ADDR bytes;
                std::memcpy(bytes.c, &ip->sin6_addr, sizeof(bytes.c));
                QHostAddress server(bytes);
                if (ip->sin6_scope_id) server.setScopeId(QString::number(ip->sin6_scope_id));
                result.append(server);
            } else return {};
        }
    }
    return result;
}
}

class NativeIkev2ClientTest : public QObject
{
    Q_OBJECT
private slots:
    void initTestCase()
    {
        QCOMPARE(qEnvironmentVariable("AMNEZIA_IKEV2_DNS_NATIVE_TEST"), QString("isolated-fixture"));
        auto service = IpcClient::Interface();
        QVERIFY(service && service->waitForSource(8000) && service->isReplicaValid());
        service->setLogsEnabled(true);
        QVERIFY(aliases().isEmpty());
    }
    void actualCertificateUtilityHasConfirmedResults()
    {
        auto process = IpcClient::CreatePrivilegedProcess();
        QVERIFY(process && process->waitForSource(5000));
        auto unset = process->confirmedExitCode();
        QVERIFY(unset.waitForFinished());
        QCOMPARE(unset.returnValue(), -1);
        process->setProgram(amnezia::PermittedProcess::CertUtil);
        process->setArguments({"-?"});
        process->start();
        auto wait = process->waitForFinished(10000);
        QVERIFY(wait.waitForFinished());
        auto result = process->confirmedExitCode();
        QVERIFY(result.waitForFinished());
        QCOMPARE(result.returnValue(), 0);
        process->setArguments({"-amnezia-native-invalid-option"});
        process->start();
        wait = process->waitForFinished(10000);
        QVERIFY(wait.waitForFinished());
        result = process->confirmedExitCode();
        QVERIFY(result.waitForFinished());
        QVERIFY(result.returnValue() != 0);
        process->close();
    }
    void strictOffHasNoIpv6EndpointException()
    {
        QUdpSocket receiver;
        QVERIFY(receiver.bind(QHostAddress(QHostAddress::LocalHostIPv6), quint16(0)));
        const QByteArray packet("owned-ipv6-policy-witness");
        const auto delivered = [&] {
            QUdpSocket sender;
            if (sender.writeDatagram(packet, QHostAddress(QHostAddress::LocalHostIPv6),
                                     receiver.localPort()) != packet.size()) return false;
            if (!receiver.waitForReadyRead(500)) return false;
            QByteArray answer(packet.size(), Qt::Uninitialized);
            return receiver.readDatagram(answer.data(), answer.size()) == packet.size()
                && answer == packet;
        };
        QVERIFY2(delivered(), "Actual IPv6 positive control must work before OFF");
        auto service = IpcClient::Interface();
        auto cleanup = qScopeGuard([&] {
            auto released = service->setNativeIpv6Blocked(false, {});
            released.waitForFinished();
        });
        auto applied = service->setNativeIpv6Blocked(true, QStringList{"::1"});
        QVERIFY(applied.waitForFinished());
        QVERIFY(applied.returnValue());
        QVERIFY2(!delivered(), "Even an explicitly listed IPv6 endpoint must stay blocked under strict OFF");
        auto released = service->setNativeIpv6Blocked(false, {});
        QVERIFY(released.waitForFinished());
        QVERIFY(released.returnValue());
        QVERIFY2(delivered(), "Confirmed native policy retirement must restore IPv6");
        cleanup.dismiss();
    }
    void nativePolicyAdmission()
    {
        QFile pfx(qEnvironmentVariable("AMNEZIA_IKEV2_CLIENT_PFX"));
        QVERIFY(pfx.open(QIODevice::ReadOnly));
        const QJsonObject config{{"ipv6_enabled", false},
            {ProtocolUtils::key_proto_config_data(Proto::Ikev2), QJsonObject{
                {configKey::hostName, "10.0.2.2"}, {configKey::cert, QString::fromLatin1(pfx.readAll().toBase64())},
                {configKey::password, "fixture-only"}}}};
        Ikev2Protocol protocol(config);
        auto cleanup = qScopeGuard([&] { protocol.stop(); });
        if (qEnvironmentVariable("AMNEZIA_POLICY_EXPECT") == "refuse") {
            QCOMPARE(protocol.start(), ErrorCode::InternalError);
            QVERIFY(protocol.connectionState() != Vpn::Connected);
        } else {
            QCOMPARE(protocol.start(), ErrorCode::NoError);
            QTRY_COMPARE_WITH_TIMEOUT(protocol.connectionState(), Vpn::Connected, 30000);
        }
        protocol.stop();
        QTRY_COMPARE_WITH_TIMEOUT(protocol.connectionState(), Vpn::Disconnected, 15000);
        QVERIFY(aliases().isEmpty());
    }
    void defaultAndExplicitOnPreserveNativeDns_data()
    {
        QTest::addColumn<bool>("explicitOn");
        QTest::newRow("legacy-missing-setting-is-on") << false;
        QTest::newRow("explicit-on") << true;
    }
    void defaultAndExplicitOnPreserveNativeDns()
    {
        QFETCH(bool, explicitOn);
        QFile pfx(qEnvironmentVariable("AMNEZIA_IKEV2_CLIENT_PFX"));
        QVERIFY(pfx.open(QIODevice::ReadOnly));
        QJsonObject config{{ProtocolUtils::key_proto_config_data(Proto::Ikev2), QJsonObject{
            {configKey::hostName, "10.0.2.2"}, {configKey::cert, QString::fromLatin1(pfx.readAll().toBase64())},
            {configKey::password, "fixture-only"}}}};
        if (explicitOn) config["ipv6_enabled"] = true;
        Ikev2Protocol protocol(config);
        QCOMPARE(protocol.start(), ErrorCode::NoError);
        auto cleanup = qScopeGuard([&] { protocol.stop(); });
        QTRY_COMPARE_WITH_TIMEOUT(protocol.connectionState(), Vpn::Connected, 30000);
        QVERIFY(aliases().isEmpty());
        QNetworkInterface native;
        for (const auto &iface : QNetworkInterface::allInterfaces())
            for (const auto &entry : iface.addressEntries())
                if (entry.ip() == QHostAddress("10.70.0.2")) native = iface;
        QVERIFY(native.isValid());
        const auto resolvers = selectedDns(native.index());
        QCOMPARE(resolvers, QList<QHostAddress>{QHostAddress("10.70.0.1")});
        for (bool tcp : {false, true}) {
            const auto a = exchange(resolvers[0], 1, tcp, "ikev2-native-on");
            QVERIFY(a.size() >= 16 && (quint8(a[3]) & 15) == 0);
            QVERIFY(a.endsWith(QByteArray::fromHex("c000027b")));
            const auto aaaa = exchange(resolvers[0], 28, tcp, "ikev2-native-on");
            QVERIFY(aaaa.size() >= 28 && (quint8(aaaa[3]) & 15) == 0);
            QVERIFY(aaaa.endsWith(QByteArray::fromHex("20010db8000000000000000000000123")));
        }
        protocol.stop();
        QTRY_COMPARE_WITH_TIMEOUT(protocol.connectionState(), Vpn::Disconnected, 15000);
        QTRY_VERIFY_WITH_TIMEOUT(!QNetworkInterface::interfaceFromIndex(native.index()).isValid(), 15000);
        QVERIFY(aliases().isEmpty());
        protocol.stop();
        QCOMPARE(protocol.connectionState(), Vpn::Disconnected);
    }
    void realNegotiatedDnsAndRestoreBeforeNativeHangup()
    {
        using namespace amnezia;
        HMODULE fixtureLibrary = nullptr;
        void *fixtureAdapter = nullptr, *fixtureSession = nullptr;
        using CloseFixture = void (WINAPI *)(void *);
        CloseFixture closeFixture = nullptr, endFixture = nullptr;
        auto retireFixture = qScopeGuard([&] {
            if (fixtureSession) endFixture(fixtureSession);
            if (fixtureAdapter) closeFixture(fixtureAdapter);
            if (fixtureLibrary) FreeLibrary(fixtureLibrary);
        });
        QHostAddress sideScopeAddress("10.0.2.15");
        if (qEnvironmentVariableIsSet("AMNEZIA_TEST_OWNED_IPV6_DNS_LINK")) {
            sideScopeAddress = QHostAddress("192.0.2.10");
            for (const auto &iface : QNetworkInterface::allInterfaces())
                for (const auto &entry : iface.addressEntries())
                    QVERIFY(entry.ip() != sideScopeAddress);
            const auto dll = qEnvironmentVariable("AMNEZIA_DNS_RECOVERY_WINTUN_DLL");
            QVERIFY(QDir::isAbsolutePath(dll));
            fixtureLibrary = LoadLibraryExW(reinterpret_cast<LPCWSTR>(dll.utf16()), nullptr,
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
            QVERIFY(fixtureLibrary);
            using Create = void *(WINAPI *)(LPCWSTR, LPCWSTR, const GUID *);
            using Start = void *(WINAPI *)(void *, DWORD);
            const auto create = reinterpret_cast<Create>(GetProcAddress(fixtureLibrary, "WintunCreateAdapter"));
            const auto start = reinterpret_cast<Start>(GetProcAddress(fixtureLibrary, "WintunStartSession"));
            closeFixture = reinterpret_cast<CloseFixture>(GetProcAddress(fixtureLibrary, "WintunCloseAdapter"));
            endFixture = reinterpret_cast<CloseFixture>(GetProcAddress(fixtureLibrary, "WintunEndSession"));
            QVERIFY(create && start && closeFixture && endFixture);
            const auto name = "Amnezia-v6-DNS-" + QUuid::createUuid().toString(QUuid::WithoutBraces).left(8);
            fixtureAdapter = create(reinterpret_cast<LPCWSTR>(name.utf16()), L"Amnezia owned DNS test", nullptr);
            QVERIFY(fixtureAdapter);
            fixtureSession = start(fixtureAdapter, 0x20000);
            QVERIFY(fixtureSession);
            NET_LUID luid{};
            QCOMPARE(ConvertInterfaceAliasToLuid(reinterpret_cast<LPCWSTR>(name.utf16()), &luid), ULONG(NO_ERROR));
            MIB_UNICASTIPADDRESS_ROW address{};
            InitializeUnicastIpAddressEntry(&address);
            address.InterfaceLuid = luid;
            address.Address.Ipv4.sin_family = AF_INET;
            address.Address.Ipv4.sin_addr.s_addr = htonl(sideScopeAddress.toIPv4Address());
            address.OnLinkPrefixLength = 32;
            address.SkipAsSource = false;
            QCOMPARE(CreateUnicastIpAddressEntry(&address), ULONG(NO_ERROR));
            const auto fixtureLink = [&] {
                for (const auto &iface : QNetworkInterface::allInterfaces())
                    if (iface.humanReadableName() == name) return iface;
                return QNetworkInterface{};
            };
            QTRY_VERIFY_WITH_TIMEOUT(fixtureLink().flags().testFlag(QNetworkInterface::IsUp), 5000);
            const auto snapshot = WindowsDnsRecovery::capture(name, {QHostAddress("198.19.255.251")});
            QVERIFY(!snapshot.isEmpty());
            bool selected = false;
            for (const auto &value : snapshot["entries"].toArray()) {
                const auto key = value.toObject()["key"].toString();
                if (!key.startsWith("v6/")) continue;
                QVERIFY(WindowsDnsRecovery::backend().write(key,
                    QJsonObject{{"mode", "static"}, {"servers", QJsonArray{"2001:db8::53"}}}));
                selected = true;
            }
            QVERIFY(selected);
            QTRY_COMPARE_WITH_TIMEOUT(selectedDns(fixtureLink().index()),
                QList<QHostAddress>{QHostAddress("2001:db8::53")}, 5000);
        }
        QFile pfx(qEnvironmentVariable("AMNEZIA_IKEV2_CLIENT_PFX"));
        QVERIFY(pfx.open(QIODevice::ReadOnly));
        const QJsonObject config{{"ipv6_enabled", false},
            {ProtocolUtils::key_proto_config_data(Proto::Ikev2), QJsonObject{
                {configKey::hostName, "10.0.2.2"}, {configKey::cert, QString::fromLatin1(pfx.readAll().toBase64())},
                {configKey::password, "fixture-only"}}}};
        Ikev2Protocol protocol(config);
        QCOMPARE(protocol.start(), ErrorCode::NoError);
        auto cleanup = qScopeGuard([&] { protocol.stop(); });
        QTRY_COMPARE_WITH_TIMEOUT(protocol.connectionState(), Vpn::Connected, 30000);
        const auto managed = aliases();
        QVERIFY(managed.size() >= 2); // PPP plus the already-selected Ethernet DNS scope.
        QNetworkInterface native;
        QHostAddress nativeAlias;
        for (const auto &iface : QNetworkInterface::allInterfaces())
            for (const auto &entry : iface.addressEntries())
                if (entry.ip() == QHostAddress("10.70.0.2")) native = iface;
        QVERIFY(native.isValid());
        QVERIFY(native.flags().testFlag(QNetworkInterface::IsUp));
        for (const auto &entry : native.addressEntries())
            if (managed.contains(entry.ip())) {
                QVERIFY(nativeAlias.isNull());
                nativeAlias = entry.ip();
            }
        QVERIFY(!nativeAlias.isNull());
        for (const auto &alias : managed)
            for (bool tcp : {false, true})
                QVERIFY2(nodata(exchange(alias, 28, tcp)), "Every OS-selected scope must return AAAA NODATA");
        if (qEnvironmentVariableIsSet("AMNEZIA_TEST_IPV6_ONLY_OS_SCOPE")) {
            QHostAddress sideAlias;
            for (const auto &iface : QNetworkInterface::allInterfaces()) {
                bool underlay = false;
                for (const auto &entry : iface.addressEntries())
                    if (entry.ip() == sideScopeAddress) underlay = true;
                if (!underlay) continue;
                for (const auto &entry : iface.addressEntries())
                    if (managed.contains(entry.ip())) {
                        QVERIFY(sideAlias.isNull());
                        sideAlias = entry.ip();
                    }
            }
            QVERIFY(!sideAlias.isNull());
            for (bool tcp : {false, true}) {
                const auto answer = exchange(sideAlias, 1, tcp, "ikev2-native-v6scope");
                QVERIFY(answer.size() >= 12);
                QCOMPARE(quint8(answer[3]) & 15, 2); // SERVFAIL; never substitute PPP/underlay DNS.
                QCOMPARE(answer.mid(6, 2), QByteArray(2, 0));
            }
        }
        for (bool tcp : {false, true}) {
            QVERIFY2(nodata(exchange(nativeAlias, 28, tcp)), tcp ? "TCP AAAA NODATA" : "UDP AAAA NODATA");
            const auto answer = exchange(nativeAlias, 1, tcp);
            QVERIFY(answer.size() >= 16 && (quint8(answer[3]) & 15) == 0);
            QVERIFY(answer.endsWith(QByteArray::fromHex("c000027b")));
        }
        DNS_QUERY_REQUEST request{};
        request.Version = DNS_QUERY_REQUEST_VERSION1;
        request.QueryName = L"ikev2-native.test.";
        request.QueryType = DNS_TYPE_AAAA;
        request.QueryOptions = DNS_QUERY_STANDARD | DNS_QUERY_TREAT_AS_FQDN | DNS_QUERY_BYPASS_CACHE;
        DNS_QUERY_RESULT result{};
        result.Version = DNS_QUERY_RESULTS_VERSION1;
        QElapsedTimer systemElapsed;
        systemElapsed.start();
        const auto status = DnsQueryEx(&request, &result, nullptr);
        auto freeRecords = qScopeGuard([&] {
            if (result.pQueryRecords) DnsRecordListFree(result.pQueryRecords, DnsFreeRecordList);
        });
        qInfo() << "Native system AAAA lookup completed in" << systemElapsed.elapsed() << "ms; status" << status;
        // Microsoft documents NODATA as DNS_INFO_NO_RECORDS (9501), not
        // ERROR_SUCCESS. Qt 6.10.1 maps it to ResolverError; do not accept a
        // generic Qt resolver error or an OS timeout as empty DNS success.
        QCOMPARE(status, DNS_STATUS(DNS_INFO_NO_RECORDS));
        QVERIFY(!result.pQueryRecords);
        QVERIFY(systemElapsed.elapsed() < 5000);
        const auto lifecycleGate = qEnvironmentVariable("AMNEZIA_TEST_LIFECYCLE_GATE");
        if (!lifecycleGate.isEmpty()) {
            QJsonArray addresses;
            for (const auto &alias : managed) addresses.append(alias.toString());
            QFile ready(lifecycleGate + ".ready");
            QVERIFY(!ready.exists());
            QVERIFY(ready.open(QIODevice::WriteOnly | QIODevice::NewOnly));
            const auto record = QJsonDocument(QJsonObject{
                {"native_index", native.index()}, {"aliases", addresses}}).toJson(QJsonDocument::Compact);
            QCOMPARE(ready.write(record), qint64(record.size()));
            ready.close();
            QTRY_VERIFY_WITH_TIMEOUT(QFile::exists(lifecycleGate + ".release"), 60000);
            QTRY_COMPARE_WITH_TIMEOUT(protocol.connectionState(), Vpn::Disconnected, 15000);
            QVERIFY(aliases().isEmpty());
            cleanup.dismiss();
            return;
        }
        if (qEnvironmentVariableIsSet("AMNEZIA_TEST_POLICY_MUTATION")) {
            const auto powershell = [](const QString &script) {
                QProcess process;
                process.start("powershell.exe", {"-NoProfile", "-NonInteractive", "-Command",
                    "$ErrorActionPreference='Stop'; " + script});
                if (!process.waitForStarted(5000) || !process.waitForFinished(15000)) {
                    process.kill();
                    process.waitForFinished();
                    return false;
                }
                if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
                    qWarning().noquote() << process.readAllStandardError();
                    return false;
                }
                return true;
            };
            const QString remove =
                "$m=Get-DnsClientDohServerAddress -ServerAddress '10.70.0.1'; "
                "if (!$m -or $m.DohTemplate -ne 'https://amnezia-owned-mutation.test/dns-query' "
                "-or !$m.AutoUpgrade -or $m.AllowFallbackToUdp) { throw 'Owned DoH mapping changed; preserve it' }; "
                "Remove-DnsClientDohServerAddress -ServerAddress '10.70.0.1' -Confirm:$false; "
                "if (Get-DnsClientDohServerAddress -ServerAddress '10.70.0.1' -ErrorAction SilentlyContinue) "
                "{ throw 'Owned DoH cleanup unfinished' }";
            bool owned = false;
            auto repairPolicy = qScopeGuard([&] { if (owned) powershell(remove); });
            QVERIFY(powershell(
                "if (Get-DnsClientDohServerAddress -ServerAddress '10.70.0.1' -ErrorAction SilentlyContinue) "
                "{ throw 'Refusing pre-existing selected DoH mapping' }; "
                "Add-DnsClientDohServerAddress -ServerAddress '10.70.0.1' "
                "-DohTemplate 'https://amnezia-owned-mutation.test/dns-query' "
                "-AllowFallbackToUdp $false -AutoUpgrade $true"));
            owned = true;
            const auto failedClosed = [&] {
                const auto answer = exchange(nativeAlias, 1, false, "ikev2-native-policy-quiesced");
                return answer.size() >= 12 && (quint8(answer[3]) & 15) == 2;
            };
            QTRY_VERIFY_WITH_TIMEOUT(failedClosed(), 5000);
            protocol.stop();
            QTest::qWait(800);
            QCOMPARE(protocol.connectionState(), Vpn::Disconnecting);
            QVERIFY(QNetworkInterface::interfaceFromIndex(native.index()).isValid());
            QCOMPARE(aliases(), managed);
            for (const auto &alias : managed) {
                for (bool tcp : {false, true}) {
                    QVERIFY(nodata(exchange(alias, 28, tcp)));
                    const auto answer = exchange(alias, 1, tcp, "ikev2-native-policy-quiesced");
                    QVERIFY(answer.size() >= 12);
                    QCOMPARE(quint8(answer[3]) & 15, 2);
                    QCOMPARE(answer.mid(6, 2), QByteArray(2, 0));
                }
            }
            QVERIFY(powershell(remove));
            owned = false;
            QTRY_COMPARE_WITH_TIMEOUT(protocol.connectionState(), Vpn::Disconnected, 15000);
            QVERIFY(aliases().isEmpty());
            cleanup.dismiss();
            return;
        }
        const auto snapshot = WindowsDnsRecovery::capture(native.humanReadableName(), {nativeAlias});
        QVERIFY(!snapshot.isEmpty());
        const auto key = snapshot["entries"].toArray().first().toObject()["key"].toString();
        const auto backend = WindowsDnsRecovery::backend();
        const auto published = backend.read(key);
        QVERIFY(published.isObject());
        const QJsonObject external{{"mode", "static"}, {"servers", QJsonArray{"192.0.2.77"}}};
        bool edited = false;
        auto repair = qScopeGuard([&] { if (edited && backend.read(key) == external) backend.write(key, published); });
        QVERIFY(backend.write(key, external));
        edited = true;
        protocol.stop();
        QTest::qWait(800);
        QCOMPARE(protocol.connectionState(), Vpn::Disconnecting);
        QVERIFY(QNetworkInterface::interfaceFromIndex(native.index()).isValid());
        QCOMPARE(aliases(), managed);
        QCOMPARE(backend.read(key), QJsonValue(external));
        QVERIFY(nodata(exchange(managed[0], 28, false)));
        QVERIFY(nodata(exchange(managed[0], 28, true)));
        QVERIFY(backend.write(key, published));
        edited = false;
        QTRY_COMPARE_WITH_TIMEOUT(protocol.connectionState(), Vpn::Disconnected, 15000);
        QVERIFY(aliases().isEmpty());
        cleanup.dismiss();
    }
};

QTEST_GUILESS_MAIN(NativeIkev2ClientTest)
#include "testNativeClient.moc"
