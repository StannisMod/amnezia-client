#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <wincrypt.h>
#include <QtTest>
#include <QJsonArray>
#include <QJsonDocument>
#include <QProcess>
#include <QScopeGuard>
#include <QTemporaryDir>
#include <QFile>
#include <QUuid>
#include <memory>
#include <vector>
#include "nativednsservice.h"
#include "platforms/windows/daemon/dnsutilswindows.h"
#include "platforms/windows/daemon/windowsdnsrecovery.h"
#include "dnsWireFixture.h"

namespace {
bool powershell(const QString &command)
{
    auto process = std::make_unique<QProcess>();
    const auto encoded = QByteArray(reinterpret_cast<const char *>(command.utf16()), command.size() * 2).toBase64();
    process->start("powershell.exe", {"-NoProfile", "-NonInteractive", "-EncodedCommand", QString::fromLatin1(encoded)});
    if (!process->waitForStarted(5000) || !process->waitForFinished(10000)) {
        if (process->state() != QProcess::NotRunning) process.release();
        qWarning() << "Native policy command cleanup remains pending; no forced termination";
        return false;
    }
    const auto output = process->readAllStandardOutput(), errors = process->readAllStandardError();
    if (process->exitCode()) qWarning().noquote() << output << errors;
    return process->exitStatus() == QProcess::NormalExit && process->exitCode() == 0;
}
}

class TestNativeDnsWindowsService : public QObject {
    Q_OBJECT
private slots:
    void selectedDohPublicationTrustAndConfirmedRetirement()
    {
        if (qEnvironmentVariable("AMNEZIA_NATIVE_DNS_SETTINGS_TEST") != "isolated-fixture")
            QSKIP("requires the explicitly owned elevated Windows fixture");
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        directory.setAutoRemove(false); // Failed ownership/trust evidence must survive.
        qInfo() << "Owned native DNS fixture:" << directory.path();
        auto fixture = std::make_unique<QProcess>();
        fixture->start(QString::fromUtf8(AMNEZIA_DNS_TLS_FIXTURE_PATH), {directory.filePath("test-ca.pem")});
        QVERIFY(fixture->waitForStarted(5000));
        auto joinFixture = qScopeGuard([&] {
            fixture->closeWriteChannel();
            if (fixture->state() != QProcess::NotRunning && !fixture->waitForFinished(10000)) {
                fixture.release(); // Preserve pending normal cleanup; never force-kill a worker.
                QFAIL("test upstream normal shutdown remains pending");
            }
            qInfo().noquote() << fixture->readAllStandardOutput() << fixture->readAllStandardError();
            QCOMPARE(fixture->exitCode(), 0);
        });
        while (!fixture->canReadLine()) QVERIFY(fixture->waitForReadyRead(5000));
        const auto upstream = QJsonDocument::fromJson(fixture->readLine()).object();
        const auto uri = upstream["url"].toString();
        QVERIFY(uri.startsWith("https://selected.invalid:") && uri.endsWith("/selected-dns"));
        QVERIFY(!uri.contains('\''));
        const auto wrongUri = QString(uri).replace("selected.invalid", "wrong.invalid");

        // Explicit fixture trust through the ordinary native Windows root
        // store, not custom Go roots, name bypass, or production trust changes.
        QFile ca(directory.filePath("test-ca.pem"));
        QVERIFY(ca.open(QIODevice::ReadOnly));
        const auto pem = ca.readAll();
        DWORD length = 0;
        QVERIFY(CryptStringToBinaryA(pem.constData(), DWORD(pem.size()), CRYPT_STRING_BASE64HEADER,
                                    nullptr, &length, nullptr, nullptr));
        std::vector<BYTE> der(length);
        QVERIFY(CryptStringToBinaryA(pem.constData(), DWORD(pem.size()), CRYPT_STRING_BASE64HEADER,
                                    der.data(), &length, nullptr, nullptr));
        // The service's normal machine trust scope also works in the isolated
        // non-interactive WinRM fixture. CurrentUser ROOT writes are unsupported
        // there; never replace chain verification with custom Go roots.
        const auto store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
            CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG, L"ROOT");
        QVERIFY(store);
        auto closeStore = qScopeGuard([&] { QVERIFY(CertCloseStore(store, 0)); });
        PCCERT_CONTEXT ownedCertificate = nullptr;
        const auto addTrust = [&] {
            const bool result = CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING,
                der.data(), length, CERT_STORE_ADD_NEW, &ownedCertificate);
            const auto error = GetLastError();
            if (!result) qWarning() << "Native machine-root add error:" << error;
            return result;
        };
        QVERIFY(addTrust());
        DWORD hashSize = 20;
        BYTE hash[20]{};
        QVERIFY(CertGetCertificateContextProperty(ownedCertificate, CERT_SHA1_HASH_PROP_ID, hash, &hashSize));
        auto removeTrust = qScopeGuard([&] {
            if (ownedCertificate) QVERIFY(CertDeleteCertificateFromStore(ownedCertificate));
            CRYPT_HASH_BLOB fingerprint{hashSize, hash};
            const auto remaining = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0,
                CERT_FIND_SHA1_HASH, &fingerprint, nullptr);
            if (remaining) CertFreeCertificateContext(remaining);
            QVERIFY(!remaining);
        });
        QVERIFY(CertDeleteCertificateFromStore(ownedCertificate));
        ownedCertificate = nullptr; // First phase must use the normal untrusted-root path.
        QVERIFY(powershell("$ErrorActionPreference='Stop';"
            "if(@(Get-DnsClientDohServerAddress | Where-Object ServerAddress -eq '127.0.0.1').Count){exit 2}"));
        QString expectedMapping;
        auto removeMapping = qScopeGuard([&] {
            if (expectedMapping.isEmpty()) return;
            QVERIFY(powershell("$ErrorActionPreference='Stop';"
                "$m=@(Get-DnsClientDohServerAddress | Where-Object ServerAddress -eq '127.0.0.1');"
                "if($m.Count -ne 1 -or $m[0].DohTemplate -ne '" + expectedMapping + "'){exit 2};"
                "Remove-DnsClientDohServerAddress -ServerAddress '127.0.0.1' -Confirm:$false;"
                "if(@(Get-DnsClientDohServerAddress | Where-Object ServerAddress -eq '127.0.0.1').Count){exit 3}"));
        });
        const auto setMapping = [&](const QString &value) {
            const auto verb = expectedMapping.isEmpty() ? "Add" : "Set";
            if (!powershell("$ErrorActionPreference='Stop';" + QString(verb)
                + "-DnsClientDohServerAddress -ServerAddress '127.0.0.1' -DohTemplate '" + value
                + "' -AutoUpgrade $true -AllowFallbackToUdp $false")) return false;
            expectedMapping = value;
            return true;
        };

        const auto dllPath = qEnvironmentVariable("AMNEZIA_DNS_RECOVERY_WINTUN_DLL");
        QVERIFY(QDir::isAbsolutePath(dllPath));
        const auto library = LoadLibraryExW(reinterpret_cast<LPCWSTR>(dllPath.utf16()), nullptr,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
        QVERIFY(library);
        auto unload = qScopeGuard([&] { FreeLibrary(library); });
        using Create = void *(WINAPI *)(LPCWSTR, LPCWSTR, const GUID *);
        using Close = void (WINAPI *)(void *);
        using Luid = void (WINAPI *)(void *, NET_LUID *);
        using Start = void *(WINAPI *)(void *, DWORD);
        using End = void (WINAPI *)(void *);
        const auto create = reinterpret_cast<Create>(GetProcAddress(library, "WintunCreateAdapter"));
        const auto close = reinterpret_cast<Close>(GetProcAddress(library, "WintunCloseAdapter"));
        const auto luid = reinterpret_cast<Luid>(GetProcAddress(library, "WintunGetAdapterLUID"));
        const auto start = reinterpret_cast<Start>(GetProcAddress(library, "WintunStartSession"));
        const auto end = reinterpret_cast<End>(GetProcAddress(library, "WintunEndSession"));
        QVERIFY(create && close && luid && start && end);
        const auto name = "Amnezia-DoH-" + QUuid::createUuid().toString(QUuid::WithoutBraces).left(8);
        auto adapter = create(reinterpret_cast<LPCWSTR>(name.utf16()), L"Amnezia DNS test", nullptr);
        QVERIFY(adapter);
        auto closeAdapter = qScopeGuard([&] { close(adapter); });
        auto session = start(adapter, 0x200000);
        QVERIFY(session);
        auto endSession = qScopeGuard([&] { end(session); });
        MIB_UNICASTIPADDRESS_ROW address{};
        InitializeUnicastIpAddressEntry(&address);
        luid(adapter, &address.InterfaceLuid);
        address.Address.Ipv4.sin_family = AF_INET;
        address.Address.Ipv4.sin_addr.S_un.S_addr = htonl(QHostAddress("192.0.2.10").toIPv4Address());
        address.OnLinkPrefixLength = 24;
        address.DadState = IpDadStatePreferred;
        QCOMPARE(CreateUnicastIpAddressEntry(&address), ULONG(NO_ERROR));
        NET_IFINDEX index = 0;
        QCOMPARE(ConvertInterfaceLuidToIndex(&address.InterfaceLuid, &index), ULONG(NO_ERROR));
        QTRY_VERIFY(QNetworkInterface::interfaceFromIndex(index).flags().testFlag(QNetworkInterface::IsUp));

        DnsUtils::setNativeDnsFactory([&] { return createNativeDnsServiceGuard(directory.path()); });
        auto resetFactory = qScopeGuard([] { DnsUtils::setNativeDnsFactory({}); });
        QVERIFY(setMapping(uri));
        for (int phase = 0; phase < 4; ++phase) {
            const bool trusted = phase != 0, wrongName = phase == 3;
            if (phase == 1) QVERIFY(addTrust());
            if (phase == 2) QVERIFY(setMapping(uri + "{?dns}"));
            if (wrongName) QVERIFY(setMapping(wrongUri + "{?dns}"));
            DnsUtilsWindows dns(nullptr);
            QVERIFY(dns.updateResolvers(name, {QHostAddress("127.0.0.1")}, false, "selected-doh"));
            const auto journals = QDir(directory.path()).entryList({"owned-*.json"}, QDir::Files);
            QCOMPARE(journals.size(), 1);
            QFile journal(directory.filePath(journals[0]));
            QVERIFY(journal.open(QIODevice::ReadOnly));
            const auto record = QJsonDocument::fromJson(journal.readAll()).object();
            journal.close();
            const auto resolver = record["resolver_policy"].toArray().first().toObject();
            QCOMPARE(resolver["transport"], QJsonValue("https"));
            QCOMPARE(resolver["https_url"], QJsonValue(expectedMapping));
            const QHostAddress endpoint(record["installed"].toArray().first().toString());
            QVERIFY(!endpoint.isNull() && DnsWireFixture::present(endpoint));
            for (const bool tcp : {false, true}) {
                QVERIFY(DnsWireFixture::reply(endpoint, tcp, 28, 0));
                const bool accepted = trusted && !wrongName;
                QString diagnostic;
                // Scoped trust may not recursively fetch through OS/default
                // DNS. All cases, including an unknown CA, keep the 1s wait.
                const bool replied = DnsWireFixture::reply(endpoint, tcp, 1, accepted ? 0 : 2, accepted,
                    &diagnostic);
                qInfo() << "Native DoH phase:" << phase << "TCP client:" << tcp
                        << "expected accepted:" << accepted << diagnostic;
                QVERIFY2(replied, qPrintable(diagnostic));
            }
            if (phase == 1) {
                {
                    // Go's normal root/name validation alone is not enough:
                    // the native Windows Disallowed policy must also win.
                    const auto disallowed = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                        CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG, L"Disallowed");
                    QVERIFY(disallowed);
                    auto closeDisallowed = qScopeGuard([&] { QVERIFY(CertCloseStore(disallowed, 0)); });
                    PCCERT_CONTEXT denied = nullptr;
                    QVERIFY(CertAddEncodedCertificateToStore(disallowed, X509_ASN_ENCODING, der.data(), length,
                        CERT_STORE_ADD_NEW, &denied));
                    auto removeDenied = qScopeGuard([&] {
                        QVERIFY(CertDeleteCertificateFromStore(denied));
                        CRYPT_HASH_BLOB fingerprint{hashSize, hash};
                        const auto remaining = CertFindCertificateInStore(disallowed, X509_ASN_ENCODING, 0,
                            CERT_FIND_SHA1_HASH, &fingerprint, nullptr);
                        if (remaining) CertFreeCertificateContext(remaining);
                        QVERIFY(!remaining);
                    });
                    for (const bool tcp : {false, true}) {
                        QVERIFY(DnsWireFixture::reply(endpoint, tcp, 28, 0));
                        QString diagnostic;
                        const bool refused = DnsWireFixture::reply(endpoint, tcp, 1, 2, false, &diagnostic);
                        qInfo() << "Native disallowed CA, TCP client:" << tcp << diagnostic;
                        QVERIFY2(refused, qPrintable(diagnostic));
                    }
                }
                QVERIFY(setMapping(wrongUri));
                QVERIFY(!dns.nativeDnsHealthy("selected-doh"));
                QVERIFY(!dns.restoreResolvers("selected-doh"));
                QVERIFY(DnsWireFixture::present(endpoint) && QFile::exists(journal.fileName()));
                for (const bool tcp : {false, true}) {
                    QVERIFY(DnsWireFixture::reply(endpoint, tcp, 28, 0));
                    QVERIFY(DnsWireFixture::reply(endpoint, tcp, 1, 2));
                }
                QVERIFY(setMapping(uri));
            }
            QVERIFY(dns.restoreResolvers("selected-doh"));
            QVERIFY(!DnsWireFixture::present(endpoint));
            QVERIFY(!QFile::exists(journal.fileName()));
        }
        fixture->closeWriteChannel();
        QVERIFY(fixture->waitForFinished(10000));
        const auto statistics = fixture->readAllStandardOutput();
        qInfo().noquote() << statistics;
        const auto counts = QJsonDocument::fromJson(statistics).object();
        QCOMPARE(counts["doh_queries"].toInt(), 4);
        QCOMPARE(counts["doh_post_queries"].toInt(), 2);
        QCOMPARE(counts["doh_get_queries"].toInt(), 2);
        QCOMPARE(counts["doh_connections"].toInt(), 10); // No implicit CTL/AIA/default-DNS recursion.
        QCOMPARE(counts["dot_queries"].toInt(), 0);
        QCOMPARE(counts["plain_tcp_queries"].toInt(), 0);
        QCOMPARE(counts["plain_udp_queries"].toInt(), 0);
        directory.setAutoRemove(true);
    }
};
QTEST_GUILESS_MAIN(TestNativeDnsWindowsService)
#include "testNativeDnsWindowsService.moc"
