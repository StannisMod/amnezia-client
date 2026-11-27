#include <QtTest>
#include <QFile>
#include <QNetworkInterface>
#include <QProcess>
#include <QProcessEnvironment>
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QTemporaryDir>
#include <QTcpSocket>
#include <QUdpSocket>
#include <QScopeGuard>
#include <QJsonDocument>
#include <QJsonArray>
#include <QDBusConnection>
#include <QDBusMessage>
#include <cstdlib>
#include "daemon/dnsutils.h"
#include "nativednsservice.h"
#include "openvpndnssession.h"
#include "openvpndnsselection.h"
#include "platforms/linux/daemon/dnsutilslinux.h"
#include "platforms/linux/daemon/linuxdnsrecovery.h"

namespace {
QByteArray dnsQuery(int type)
{
    auto query = QByteArray::fromHex("123401000001000000000000076578616d706c6504746573740000000001");
    query[query.size() - 3] = char(type);
    return query;
}

bool reply(const QHostAddress &endpoint, bool tcp, int type, int rcode, bool expectedAnswer = false)
{
    const auto query = dnsQuery(type);
    QByteArray answer;
    if (tcp) {
        QTcpSocket socket;
        socket.connectToHost(endpoint, 53);
        if (!socket.waitForConnected(1000)) return false;
        QByteArray frame;
        frame.append(char(query.size() >> 8));
        frame.append(char(query.size()));
        frame.append(query);
        if (socket.write(frame) != frame.size() || !socket.waitForBytesWritten(1000)) return false;
        while (socket.bytesAvailable() < 2)
            if (!socket.waitForReadyRead(1000)) return false;
        const auto length = socket.read(2);
        const int size = (quint8(length[0]) << 8) | quint8(length[1]);
        while (answer.size() < size) {
            answer += socket.read(size - answer.size());
            if (answer.size() < size && !socket.waitForReadyRead(1000)) return false;
        }
    } else {
        QUdpSocket socket;
        if (socket.writeDatagram(query, endpoint, 53) != query.size() || !socket.waitForReadyRead(1000)) return false;
        answer.resize(socket.pendingDatagramSize());
        if (socket.readDatagram(answer.data(), answer.size()) != answer.size()) return false;
    }
    return answer.size() >= 12 && quint8(answer[0]) == 0x12 && quint8(answer[1]) == 0x34
        && (quint8(answer[2]) & 0x80) && (quint8(answer[3]) & 15) == rcode
        && answer[6] == 0 && answer[7] == (expectedAnswer ? 1 : 0)
        && (expectedAnswer ? bool(quint8(answer[3]) & 0x20) : !(quint8(answer[3]) & 0x20))
        && (!expectedAnswer || answer.right(4) == QByteArray::fromHex("c6336402"));
}

bool present(const QHostAddress &ip)
{
    for (const auto &iface : QNetworkInterface::allInterfaces())
        for (const auto &entry : iface.addressEntries())
            if (entry.ip() == ip) return true;
    return false;
}

class Resolvers final : public DnsUtils {
public:
    Resolvers() : DnsUtils(nullptr) {}
    bool publish = true, restore = true;
    QList<QHostAddress> last;
protected:
    bool updateResolversNative(const QString &, const QList<QHostAddress> &servers, bool strict) override {
        if (!strict) return false;
        last = servers;
        return publish;
    }
    bool restoreResolversNative(bool strict) override { return strict && restore; }
};
}

class TestNativeDnsService : public QObject {
    Q_OBJECT
private slots:
    void initTestCase() {
        if (qEnvironmentVariable("AMNEZIA_NATIVE_DNS_SERVICE_TEST") != "isolated-namespace")
            QSKIP("requires a caller-owned isolated network namespace");
        const auto iface = QNetworkInterface::interfaceFromName("dns-fixture");
        QVERIFY(iface.isValid());
        QVERIFY(present(QHostAddress("192.0.2.10")));
    }
    void cleanup() { DnsUtils::setNativeDnsFactory({}); }
    void invalidResolverPolicyCannotMutateAliases()
    {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        const QJsonObject original{{"server", "192.0.2.53"}, {"port", 853}, {"transport", "tls"}};
        for (const auto &change : {
                QJsonObject{{"port", 0}}, QJsonObject{{"port", 65536}}, QJsonObject{{"port", 2.5}},
                QJsonObject{{"port", "853"}}, QJsonObject{{"server", "hostname.example"}},
                QJsonObject{{"transport", "unknown"}}, QJsonObject{{"dnssec", "yes"}},
                QJsonObject{{"transport", "plain"}, {"server_name", "selected.example"}},
                QJsonObject{{"https_url", "https://selected.example/original"}},
                QJsonObject{{"transport", "https"}}}) {
            auto policy = original;
            for (auto it = change.begin(); it != change.end(); ++it) policy.insert(it.key(), it.value());
            auto guard = createNativeDnsServiceGuard(directory.path());
            QVERIFY(!guard->setResolverPolicy(QJsonArray{policy}));
            QVERIFY(QDir(directory.path()).entryList({"owned-*.json"}, QDir::Files).isEmpty());
        }
        auto guard = createNativeDnsServiceGuard(directory.path());
        QVERIFY(guard->setResolverPolicy(QJsonArray{original}));
        QList<QHostAddress> endpoints;
        QVERIFY(!guard->prepare("dns-fixture", {QHostAddress("192.0.2.54")}, endpoints));
        QVERIFY(endpoints.isEmpty());
        QVERIFY(QDir(directory.path()).entryList({"owned-*.json"}, QDir::Files).isEmpty());
    }
    void malformedResolverPolicyRecoveryRetainsOwnedAliasUntilValidRecordRestored()
    {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        const auto backend = LinuxDnsRecovery::systemBackend();
        const int index = QNetworkInterface::interfaceFromName("dns-fixture").index();
        const auto before = backend.read(index);
        QVERIFY(!before.isEmpty());
        const QJsonArray policy{QJsonObject{{"server", "2001:db8::53"}, {"port", 853},
            {"transport", "tls"}, {"server_name", "selected.example"}}};
        auto guard = createNativeDnsServiceGuard(directory.path());
        QVERIFY(guard->setResolverPolicy(policy));
        QList<QHostAddress> endpoints;
        QVERIFY(guard->prepare("dns-fixture", {QHostAddress("2001:db8::53")}, endpoints));
        QCOMPARE(endpoints.size(), 1);
        const auto files = QDir(directory.path()).entryList({"owned-*.json"}, QDir::Files);
        QCOMPARE(files.size(), 1);
        QFile file(QDir(directory.path()).filePath(files[0]));
        QVERIFY(file.open(QIODevice::ReadOnly));
        const auto original = file.readAll();
        file.close();
        guard.reset(); // Join Go, deliberately retain unpublished aliases/journal for recovery.
        auto damaged = QJsonDocument::fromJson(original).object();
        damaged.remove("checksum");
        damaged["resolver_policy"] = QJsonArray{QJsonObject{{"server", "2001:db8::53"}, {"port", 853},
            {"transport", "plain"}, {"server_name", "must-not-drop.example"}}};
        damaged["checksum"] = QString::fromLatin1(QCryptographicHash::hash(
            QJsonDocument(damaged).toJson(QJsonDocument::Compact), QCryptographicHash::Sha256).toHex());
        QVERIFY(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
        const auto edited = QJsonDocument(damaged).toJson();
        QCOMPARE(file.write(edited), edited.size());
        file.close();
        int restores = 0;
        const auto restore = [&](const QJsonObject &record) {
            ++restores;
            // This fixture never published OS DNS; prove it is still original
            // instead of giving recovery an unconditional success callback.
            return record["resolver_policy"].toArray() == policy && backend.read(index) == before;
        };
        QVERIFY(!recoverNativeDnsServiceGuards(directory.path(), restore));
        QCOMPARE(restores, 0);
        QVERIFY(present(endpoints[0]));
        QVERIFY(file.open(QIODevice::ReadOnly));
        QCOMPARE(file.readAll(), edited);
        file.close();
        QVERIFY(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
        QCOMPARE(file.write(original), original.size());
        file.close();
        QVERIFY(recoverNativeDnsServiceGuards(directory.path(), restore));
        QCOMPARE(restores, 1);
        QVERIFY(!present(endpoints[0]));
        QVERIFY(!QFile::exists(file.fileName()));
    }
    void openVpnScopedPublicationRestore()
    {
        if (!qEnvironmentVariableIsSet("AMNEZIA_DNS_REAL_RESOLVED"))
            QSKIP("requires private real systemd-resolved and D-Bus");
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        DnsUtils::setNativeDnsFactory([&] { return createNativeDnsServiceGuard(directory.path()); });
        DnsUtilsLinux dns(nullptr);
        const auto backend = LinuxDnsRecovery::systemBackend();
        QVERIFY(QProcess::execute("ip", {"link", "add", "dns-scoped-peer", "type", "dummy"}) == 0);
        auto removePeer = qScopeGuard([] {
            QProcess::execute("ip", {"link", "del", "dns-scoped-peer"});
        });
        QVERIFY(QProcess::execute("ip", {"link", "set", "dns-scoped-peer", "up"}) == 0);
        const int peerIndex = QNetworkInterface::interfaceFromName("dns-scoped-peer").index();
        const QJsonArray peerDomains{
            QJsonObject{{"name", "."}, {"routing_only", true}},
            QJsonObject{{"name", "peer.example"}, {"routing_only", false}}};
        QVERIFY(backend.write(peerIndex, "domains", peerDomains));
        const auto peerBefore = backend.read(peerIndex);
        const int index = QNetworkInterface::interfaceFromName("dns-fixture").index();
        const auto before = backend.read(index);
        QVERIFY(!before.isEmpty());
        const QJsonObject environment{
            {"dev", "dns-fixture"},
            {"dns_server_1_address_1", "2001:db8::53"},
            {"dns_server_1_address_2", "2001:db8::53"},
            {"dns_server_1_transport", "plain"},
            {"dns_search_domain_1", "search.example"},
            {"dns_server_1_resolve_domain_1", "route.example"}};
        QVERIFY(!openVpnDnsSelection(environment)); // No scope support on other adapters.
        auto malformed = environment;
        malformed["dns_server_1_resolve_domain_3"] = "gap.example";
        QVERIFY(!openVpnDnsSelection(malformed, true));
        malformed = environment;
        malformed["dns_server_2_address_1"] = "192.0.2.54";
        QVERIFY(!openVpnDnsSelection(malformed, true)); // No group flattening.
        const auto legacy = openVpnDnsSelection(QJsonObject{
            {"dev", "dns-fixture"}, {"foreign_option_1", "dhcp-option DNS 2001:db8::53"},
            {"foreign_option_2", "dhcp-option DOMAIN-SEARCH search.example"}}, true);
        QVERIFY(legacy);
        QCOMPARE(legacy->linkPolicy["default_route"], QJsonValue(true));
        const auto selected = openVpnDnsSelection(environment, true);
        QVERIFY(selected);
        const auto publish = [&](const OpenVpnDnsSelection &selection) {
            return dns.updateResolvers(selection.interfaceName, selection.servers, false, "scoped",
                QJsonObject{{"protocol", "openvpn"}, {"native", selection.metadata}}, selection.linkPolicy,
                selection.resolverPolicy);
        };
        QVERIFY(publish(*selected));
        const auto installed = backend.read(index);
        QCOMPARE(installed["domains"], selected->linkPolicy["domains"]);
        QCOMPARE(installed["default_route"], QJsonValue(false));
        QCOMPARE(backend.read(peerIndex), peerBefore);
        const auto endpoints = installed["dns"].toArray();
        QCOMPARE(endpoints.size(), 2);
        QVERIFY(endpoints[0] != endpoints[1]);
        for (const auto &value : endpoints)
            for (const bool tcp : {false, true}) {
                QVERIFY(reply(QHostAddress(value.toString()), tcp, 28, 0));
                QVERIFY(reply(QHostAddress(value.toString()), tcp, 1, 2));
            }
        // Reuse the active listeners but replace the scoped publication and its
        // expected recovery state; never overwrite the original OS snapshot.
        auto replacement = environment;
        replacement["dns_server_1_resolve_domain_1"] = ".";
        const auto next = openVpnDnsSelection(replacement, true);
        QVERIFY(next);
        QVERIFY(publish(*next));
        QCOMPARE(backend.read(index)["default_route"], QJsonValue(true));
        QCOMPARE(backend.read(index)["domains"], next->linkPolicy["domains"]);
        QCOMPARE(backend.read(peerIndex)["domains"].toArray(),
            QJsonArray({QJsonObject{{"name", "peer.example"}, {"routing_only", false}}}));
        QVERIFY(dns.restoreResolvers("scoped"));
        QCOMPARE(backend.read(index), before);
        QCOMPARE(backend.read(peerIndex), peerBefore);
        for (const auto &value : endpoints) QVERIFY(!present(QHostAddress(value.toString())));
        QVERIFY(QDir(directory.path()).entryList({"*.json"}, QDir::Files).isEmpty());
        replacement["dns_server_1_dnssec"] = "yes";
        QVERIFY(!openVpnDnsSelection(replacement, true));
        replacement.remove("dns_server_1_dnssec");
        replacement["dns_server_1_transport"] = "DoH"; // No native URI contract: still refused.
        QVERIFY(!openVpnDnsSelection(replacement, true));
    }
    void selectedEncryptedTransportSurvivesNativePublicationAndTrustValidation()
    {
        QVERIFY(qEnvironmentVariableIsSet("AMNEZIA_DNS_REAL_RESOLVED"));
        const auto selected = qgetenv("AMNEZIA_DNS_TLS_CHILD");
        if (selected.isEmpty()) {
            QTemporaryDir fixtureDirectory;
            QVERIFY(fixtureDirectory.isValid());
            QProcess fixture;
            fixture.start(AMNEZIA_DNS_TLS_FIXTURE_PATH, {fixtureDirectory.filePath("test-ca.pem")});
            const bool started = fixture.waitForStarted(5000);
            if (!started) fixture.waitForFinished(-1);
            QVERIFY(started);
            bool verifyCounts = false;
            auto join = qScopeGuard([&] {
                fixture.closeWriteChannel();
                fixture.waitForFinished(-1); // EOF performs joined cleanup; never kill a pending fixture.
                const auto statistics = fixture.readAllStandardOutput();
                qInfo().noquote() << statistics << fixture.readAllStandardError();
                QCOMPARE(fixture.exitCode(), 0);
                if (verifyCounts) {
                    const auto counts = QJsonDocument::fromJson(statistics).object();
                    QCOMPARE(counts["dot_queries"].toInt(), 2);
                    QCOMPARE(counts["doh_queries"].toInt(), 0);
                    QCOMPARE(counts["plain_tcp_queries"].toInt(), 1);
                    QVERIFY(counts["plain_udp_queries"].toInt() >= 1); // Ordinary UDP retry is permitted.
                }
            });
            QByteArray selection;
            while (!fixture.canReadLine()) {
                QVERIFY(fixture.waitForReadyRead(5000));
            }
            selection = fixture.readLine();
            const auto upstream = QJsonDocument::fromJson(selection).object();
            QVERIFY(!upstream.isEmpty());
            auto environment = QProcessEnvironment::systemEnvironment();
            environment.insert("AMNEZIA_DNS_TLS_CHILD", QString::fromUtf8(selection));
            environment.insert("SSL_CERT_FILE", upstream["ca"].toString());
            environment.insert("SSL_CERT_DIR", fixtureDirectory.path());
            QProcess child;
            child.setProcessEnvironment(environment);
            child.start(QCoreApplication::applicationFilePath(),
                {"selectedEncryptedTransportSurvivesNativePublicationAndTrustValidation"});
            const bool childStarted = child.waitForStarted(5000);
            if (!childStarted) child.waitForFinished(-1);
            QVERIFY(childStarted);
            child.waitForFinished(-1);
            qInfo().noquote() << child.readAllStandardOutput() << child.readAllStandardError();
            QCOMPARE(child.exitStatus(), QProcess::NormalExit);
            QCOMPARE(child.exitCode(), 0);
            verifyCounts = true;
            return;
        }
        const auto upstream = QJsonDocument::fromJson(selected).object();
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        DnsUtils::setNativeDnsFactory([&] { return createNativeDnsServiceGuard(directory.path()); });
        DnsUtilsLinux dns(nullptr);
        const auto backend = LinuxDnsRecovery::systemBackend();
        const int index = QNetworkInterface::interfaceFromName("dns-fixture").index();
        const auto before = backend.read(index);
        QVERIFY(!before.isEmpty());
        QJsonObject metadata{{"dev", "dns-fixture"}};
        QList<QHostAddress> allEndpoints;
        for (int phase = 0; phase < 3; ++phase) {
            const bool plain = phase == 0, wrongName = phase == 2;
            const auto peer = upstream[plain ? "plain" : "dot"].toString().split(':');
            QCOMPARE(peer.size(), 2);
            QCOMPARE(peer[0], QString("127.0.0.1"));
            bool validPort;
            const auto port = peer[1].toUShort(&validPort);
            QVERIFY(validPort && port && port != 53);
            metadata["dns_server_1_address_1"] = peer[0];
            metadata["dns_server_1_port_1"] = peer[1];
            metadata["dns_server_1_transport"] = plain ? "plain" : "DoT";
            if (plain) metadata.remove("dns_server_1_sni");
            else metadata["dns_server_1_sni"] = wrongName ? "wrong.invalid" : upstream["name"].toString();
            const auto selection = openVpnDnsSelection(metadata, true);
            QVERIFY(selection);
            QVERIFY(dns.updateResolvers("dns-fixture", selection->servers, false, "encrypted",
                QJsonObject{{"protocol", "openvpn"}, {"native", selection->metadata}},
                selection->linkPolicy, selection->resolverPolicy));
            const auto endpoints = backend.read(index)["dns"].toArray();
            QCOMPARE(endpoints.size(), 1);
            const QHostAddress endpoint(endpoints[0].toString());
            if (!allEndpoints.isEmpty())
                QVERIFY(allEndpoints.last() != endpoint); // A changed policy cannot reuse its active forwarders.
            allEndpoints.append(endpoint);
            for (const bool tcp : {false, true}) {
                QVERIFY(reply(endpoint, tcp, 28, 0));
                QVERIFY(reply(endpoint, tcp, 1, wrongName ? 2 : 0, !wrongName));
            }
            const auto records = QDir(directory.path()).entryList({"owned-*.json"}, QDir::Files);
            QCOMPARE(records.size(), 1);
            QFile record(QDir(directory.path()).filePath(records[0]));
            QVERIFY(record.open(QIODevice::ReadOnly));
            QCOMPARE(QJsonDocument::fromJson(record.readAll()).object()["resolver_policy"].toArray(),
                selection->resolverPolicy);
        }
        QVERIFY(dns.restoreResolvers("encrypted"));
        QCOMPARE(backend.read(index), before);
        for (const auto &endpoint : allEndpoints) QVERIFY(!present(endpoint));
        QVERIFY(QDir(directory.path()).entryList({"owned-*.json"}, QDir::Files).isEmpty());
    }
    void openVpnServiceOwnedDnsPublicationReconnectAndExternalEdit()
    {
        if (!qEnvironmentVariableIsSet("AMNEZIA_DNS_REAL_RESOLVED"))
            QSKIP("requires private real systemd-resolved and D-Bus");
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        DnsUtils::setNativeDnsFactory([&] { return createNativeDnsServiceGuard(directory.path()); });
        DnsUtilsLinux dns(nullptr);
        const auto index = QNetworkInterface::interfaceFromName("dns-fixture").index();
        const auto backend = LinuxDnsRecovery::systemBackend();
        const auto before = backend.read(index);
        QVERIFY(!before.isEmpty());
        int publications = 0, failures = 0;
        OpenVpnDnsSession session({
            [&](const QString &owner, const QJsonObject &metadata) {
                ++publications;
                const auto selection = openVpnDnsSelection(metadata);
                return selection && dns.updateResolvers(selection->interfaceName, selection->servers, false, owner,
                    QJsonObject{{"protocol", "openvpn"}, {"native", selection->metadata}});
            },
            [&](const QString &owner) {
                const bool restored = dns.restoreResolvers(owner);
                if (!restored) ++failures;
                return restored;
            }
        });
        QVERIFY(session.start());
        auto gui = std::make_unique<QObject>();
        connect(&session, &OpenVpnDnsSession::managementLine, gui.get(), [](const QString &) {});
        QTcpSocket native;
        native.connectToHost(QHostAddress::LocalHost, session.port());
        QVERIFY(native.waitForConnected(1000));
        const auto publish = [&](const QString &routes, int serial, const QString &upstream) {
            const auto lines = QString(">UPDOWN:UP\r\n>UPDOWN:ENV,dev=dns-fixture\r\n"
                ">UPDOWN:ENV,amnezia_native_dns=external\r\n>UPDOWN:ENV,amnezia_native_routes=%1\r\n"
                ">UPDOWN:ENV,foreign_option_1=dhcp-option DNS %2\r\n"
                ">UPDOWN:ENV,foreign_option_2=dhcp-option DNS %2\r\n>UPDOWN:ENV,END\r\n"
                ">NEED-OK:Need 'AMNEZIA-DNS-PUBLISH:%3' confirmation MSG:service DNS\r\n")
                .arg(routes, upstream).arg(serial).toUtf8();
            QCOMPARE(native.write(lines), lines.size()); native.flush();
        };
        publish("success", 1, "2001:db8::53");
        QTRY_VERIFY_WITH_TIMEOUT(native.canReadLine(), 3000);
        QCOMPARE(native.readLine(), QByteArray("needok 'AMNEZIA-DNS-PUBLISH:1' ok\n"));
        QCOMPARE(publications, 1);
        auto installed = backend.read(index);
        const auto first = installed["dns"].toArray();
        QCOMPARE(first.size(), 2);
        QVERIFY(first[0] != first[1]); // Duplicate upstreams retain distinct native endpoints.
        for (const auto &value : first) {
            const QHostAddress ip(value.toString());
            QVERIFY(present(ip));
            for (const bool tcp : {false, true}) {
                QVERIFY(reply(ip, tcp, 28, 0));
                QVERIFY(reply(ip, tcp, 1, 2));
            }
        }
        gui.reset(); // GUI loss does not close the service's native management socket.
        publish("preserved", 2, "2001:db8::54");
        QTRY_VERIFY_WITH_TIMEOUT(native.canReadLine(), 3000);
        QCOMPARE(native.readLine(), QByteArray("needok 'AMNEZIA-DNS-PUBLISH:2' ok\n"));
        QCOMPARE(publications, 2);
        installed = backend.read(index);
        for (const auto &value : installed["dns"].toArray())
            QVERIFY(reply(QHostAddress(value.toString()), true, 28, 0));
        const auto journals = QDir(directory.path()).entryList({"*.json"}, QDir::Files);
        QCOMPARE(journals.size(), 1);
        QFile journal(directory.filePath(journals.first()));
        QVERIFY(journal.open(QIODevice::ReadOnly));
        const auto record = QJsonDocument::fromJson(journal.readAll()).object();
        const auto metadata = record["dns_recovery"].toObject()["protocol_metadata"].toObject();
        QCOMPARE(metadata["native"].toObject()["foreign_option_1"].toString(),
                 QString("dhcp-option DNS 2001:db8::54"));
        journal.close();
        const QJsonArray external{QString("192.0.2.77")};
        QVERIFY(backend.write(index, "dns", external));
        native.write(">NEED-OK:Need 'AMNEZIA-DNS-RESTORE:3' confirmation MSG:service DNS\r\n");
        native.flush();
        QTRY_VERIFY_WITH_TIMEOUT(failures > 0, 3000);
        QVERIFY(!native.bytesAvailable()); QVERIFY(!session.cleanupConfirmed());
        QCOMPARE(backend.read(index)["dns"].toArray(), external); // Do not overwrite external DNS.
        for (const auto &value : installed["dns"].toArray())
            QVERIFY(present(QHostAddress(value.toString())));
        // Fixture resolves the external edit; only now may the service restore
        // original settings, retire both aliases and unblock native teardown.
        QVERIFY(backend.write(index, "dns", installed["dns"]));
        QTRY_VERIFY_WITH_TIMEOUT(native.canReadLine(), 3000);
        QCOMPARE(native.readLine(), QByteArray("needok 'AMNEZIA-DNS-RESTORE:3' ok\n"));
        QVERIFY(session.cleanupConfirmed());
        QCOMPARE(backend.read(index), before);
        for (const auto &value : installed["dns"].toArray())
            QVERIFY(!present(QHostAddress(value.toString())));
        QVERIFY(QDir(directory.path()).entryList({"*.json"}, QDir::Files).isEmpty());
        QVERIFY(session.nativeFinished());
    }
    void createCrashFixture() {
        const auto path = qEnvironmentVariable("AMNEZIA_DNS_CRASH_FIXTURE");
        if (path.isEmpty()) QSKIP("child-only abrupt-termination fixture");
        if (qEnvironmentVariableIsSet("AMNEZIA_DNS_CRASH_REAL")) {
            const auto stage = qEnvironmentVariable("AMNEZIA_DNS_CRASH_STAGE");
            if (stage != "published") {
                auto first = createNativeDnsServiceGuard(path);
                QList<QHostAddress> endpoints;
                QVERIFY(first->prepare("dns-fixture", {QHostAddress("2001:db8::53")}, endpoints));
                const auto snapshot = LinuxDnsRecovery::capture("dns-fixture", endpoints);
                QVERIFY(!snapshot.isEmpty());
                QVERIFY(first->storeDnsRecovery(snapshot));
                const auto backend = LinuxDnsRecovery::systemBackend();
                const auto publish = [&](const QJsonObject &state, bool dnsOnly) {
                    for (const auto &value : state["links"].toArray()) {
                        const auto link = value.toObject();
                        const auto after = link["after"].toObject();
                        for (auto it = after.begin(); it != after.end(); ++it) {
                            if (dnsOnly && it.key() != "dns" && it.key() != "dns_ex") continue;
                            if (!backend.write(link["index"].toInt(), it.key(), it.value())) return false;
                        }
                    }
                    return true;
                };
                if (stage == "partial") QVERIFY(publish(snapshot, true));
                if (stage == "two-generations") {
                    QVERIFY(publish(snapshot, false));
                    auto second = createNativeDnsServiceGuard(path);
                    QList<QHostAddress> next;
                    QVERIFY(second->prepare("dns-fixture", {QHostAddress("2001:db8::54")}, next));
                    const auto replacement = LinuxDnsRecovery::capture("dns-fixture", next, snapshot);
                    QVERIFY(!replacement.isEmpty());
                    QVERIFY(second->storeDnsRecovery(replacement));
                    QVERIFY(publish(replacement, false));
                    std::_Exit(77);
                }
                std::_Exit(77);
            }
            DnsUtils::setNativeDnsFactory([&] { return createNativeDnsServiceGuard(path); });
            DnsUtilsLinux dns(nullptr);
            QVERIFY(dns.updateResolvers("dns-fixture", {QHostAddress("2001:db8::53")}, false, "crash"));
            std::_Exit(77);
        }
        auto guard = createNativeDnsServiceGuard(path);
        QList<QHostAddress> endpoints;
        QVERIFY(guard->prepare("dns-fixture", {QHostAddress("2001:db8::53")}, endpoints));
        QVERIFY(guard->healthy());
        std::_Exit(77); // No destructors or graceful Go/alias cleanup.
    }
    void realResolvedSecurityPolicyIsNeverDisabledOrSilentlyAdopted()
    {
        const auto backend = LinuxDnsRecovery::systemBackend();
        const int index = QNetworkInterface::interfaceFromName("dns-fixture").index();
        const auto original = backend.read(index);
        QVERIFY(!original.isEmpty());
        const auto initial = original["native_policy"].toObject();
        const auto setMode = [&](const QString &field, const QString &mode) {
            auto message = QDBusMessage::createMethodCall("org.freedesktop.resolve1",
                "/org/freedesktop/resolve1", "org.freedesktop.resolve1.Manager", "SetLink" + field);
            message.setArguments({index, mode});
            return QDBusConnection::systemBus().call(message).type() == QDBusMessage::ReplyMessage;
        };
        auto restoreModes = qScopeGuard([&] {
            QVERIFY(setMode("DNSSEC", initial["DNSSEC"].toString()));
            QVERIFY(setMode("DNSOverTLS", initial["DNSOverTLS"].toString()));
        });
        for (const auto &field : {QString("DNSSEC"), QString("DNSOverTLS")}) {
            QVERIFY(setMode(field, "yes"));
            const auto secured = backend.read(index);
            QVERIFY(LinuxDnsRecovery::capture("dns-fixture", {QHostAddress("198.19.255.1")}).isEmpty());
            QCOMPARE(backend.read(index), secured); // No policy reset or alias publication.
            QVERIFY(setMode(field, initial[field].toString()));
        }
        const auto snapshot = LinuxDnsRecovery::capture("dns-fixture", {QHostAddress("198.19.255.1")});
        QVERIFY(!snapshot.isEmpty());
        const auto after = snapshot["links"].toArray().first().toObject()["after"].toObject();
        auto restoreSnapshot = qScopeGuard([&] {
            QVERIFY(setMode("DNSSEC", initial["DNSSEC"].toString()));
            QVERIFY(LinuxDnsRecovery::restore(snapshot, backend));
        });
        for (auto it = after.begin(); it != after.end(); ++it)
            QVERIFY(backend.write(index, it.key(), it.value()));
        QVERIFY(setMode("DNSSEC", "yes"));
        const auto edited = backend.read(index);
        QVERIFY(!LinuxDnsRecovery::restore(snapshot, backend));
        QCOMPARE(backend.read(index), edited);
        QVERIFY(LinuxDnsRecovery::capture("dns-fixture", {QHostAddress("198.19.255.2")}, snapshot).isEmpty());
        QCOMPARE(backend.read(index), edited);
    }
    void realResolvedExtendedEndpointsRestoreAndMetadataOnlyEdit()
    {
        const auto backend = LinuxDnsRecovery::systemBackend();
        const int index = QNetworkInterface::interfaceFromName("dns-fixture").index();
        const auto original = backend.read(index);
        QVERIFY(original.contains("dns_ex"));
        auto restoreOriginal = qScopeGuard([&] {
            QVERIFY(backend.write(index, "dns_ex", original["dns_ex"]));
            QVERIFY(backend.write(index, "domains", original["domains"]));
            QVERIFY(backend.write(index, "default_route", original["default_route"]));
        });
        const QJsonArray selected{
            QJsonObject{{"server", "192.0.2.53"}, {"port", 1853}, {"server_name", "original.example"}},
            QJsonObject{{"server", "2001:db8::54"}, {"port", 2853}, {"server_name", "v6.example"}}};
        QVERIFY(backend.write(index, "dns_ex", selected));
        QCOMPARE(backend.read(index)["dns_ex"].toArray(), selected);
        const auto snapshot = LinuxDnsRecovery::capture(
            "dns-fixture", {QHostAddress("198.19.255.1")});
        QVERIFY(!snapshot.isEmpty());
        const auto link = snapshot["links"].toArray().first().toObject();
        QCOMPARE(link["before"].toObject()["dns_ex"].toArray(), selected);
        const auto after = link["after"].toObject();
        for (auto it = after.begin(); it != after.end(); ++it)
            QVERIFY(backend.write(index, it.key(), it.value()));
        auto edited = after["dns_ex"].toArray();
        auto endpoint = edited[0].toObject();
        endpoint["server_name"] = "external-edit.example";
        edited[0] = endpoint;
        QVERIFY(backend.write(index, "dns_ex", edited));
        // Same address list is not proof that resolver identity is unchanged.
        QVERIFY(!LinuxDnsRecovery::restore(snapshot, backend));
        QCOMPARE(backend.read(index)["dns_ex"].toArray(), edited);
        QVERIFY(backend.write(index, "dns_ex", after["dns_ex"]));
        QVERIFY(LinuxDnsRecovery::restore(snapshot, backend));
        QCOMPARE(backend.read(index)["dns_ex"].toArray(), selected);
    }
    void realResolvedScopedPolicySnapshotRestore() {
        if (!qEnvironmentVariableIsSet("AMNEZIA_DNS_REAL_RESOLVED"))
            QSKIP("requires private real systemd-resolved and D-Bus");
        const auto backend = LinuxDnsRecovery::systemBackend();
        const int index = QNetworkInterface::interfaceFromName("dns-fixture").index();
        const auto original = backend.read(index);
        QVERIFY(!original.isEmpty());
        const QJsonArray domains{
            QJsonObject{{"name", "search.example"}, {"routing_only", false}},
            QJsonObject{{"name", "route.example"}, {"routing_only", true}}};
        const QJsonObject policy{{"domains", domains}, {"default_route", false}};
        const auto snapshot = LinuxDnsRecovery::capture(
            "dns-fixture", {QHostAddress("198.19.255.1")}, {}, policy);
        QVERIFY(!snapshot.isEmpty());
        const auto links = snapshot["links"].toArray();
        QCOMPARE(links.size(), 1); // Scoped publication must not steal other root domains.
        const auto after = links.first().toObject()["after"].toObject();
        QCOMPARE(after["domains"].toArray(), domains);
        QCOMPARE(after["default_route"], QJsonValue(false));
        auto restore = qScopeGuard([&] { LinuxDnsRecovery::restore(snapshot, backend); });
        for (auto it = after.begin(); it != after.end(); ++it)
            QVERIFY(backend.write(index, it.key(), it.value()));
        QCOMPARE(backend.read(index)["domains"].toArray(), domains);
        QVERIFY(LinuxDnsRecovery::restore(snapshot, backend));
        QCOMPARE(backend.read(index), original);
        QVERIFY(LinuxDnsRecovery::capture("dns-fixture", {QHostAddress("198.19.255.1")}, {},
            QJsonObject{{"domains", domains}, {"default_route", "false"}}).isEmpty());
    }
    void realResolvedSnapshotCrashCompareRestore_data() {
        QTest::addColumn<QString>("stage");
        QTest::newRow("before-publication") << QString("before");
        QTest::newRow("partial-publication") << QString("partial");
        QTest::newRow("published") << QString("published");
        QTest::newRow("two-generations") << QString("two-generations");
    }
    void realResolvedSnapshotCrashCompareRestore() {
        if (!qEnvironmentVariableIsSet("AMNEZIA_DNS_REAL_RESOLVED"))
            QSKIP("requires private real systemd-resolved and D-Bus");
        QFETCH(QString, stage);
        const auto backend = LinuxDnsRecovery::systemBackend();
        QVERIFY(QProcess::execute("ip", {"link", "add", "dns-other", "type", "dummy"}) == 0);
        auto removeOther = qScopeGuard([] {
            QProcess::execute("ip", {"link", "del", "dns-other"});
        });
        QVERIFY(QProcess::execute("ip", {"link", "set", "dns-other", "up"}) == 0);
        const int otherIndex = QNetworkInterface::interfaceFromName("dns-other").index();
        const QJsonArray otherDomains{
            QJsonObject{{"name", "."}, {"routing_only", true}},
            QJsonObject{{"name", "scoped.test"}, {"routing_only", true}}};
        QVERIFY(backend.write(otherIndex, "domains", otherDomains));
        const auto originalOther = backend.read(otherIndex);
        QVERIFY(!originalOther.isEmpty());
        const int index = QNetworkInterface::interfaceFromName("dns-fixture").index();
        const QJsonArray originalDns{"192.0.2.53", "2001:db8::54"};
        const QJsonArray originalDomains{QJsonObject{{"name", "original.test"}, {"routing_only", false}}};
        QVERIFY(backend.write(index, "dns", originalDns));
        QVERIFY(backend.write(index, "domains", originalDomains));
        QVERIFY(backend.write(index, "default_route", false));
        const auto original = backend.read(index);
        QVERIFY(!original.isEmpty());
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        QProcess child;
        auto environment = QProcessEnvironment::systemEnvironment();
        environment.insert("AMNEZIA_DNS_CRASH_FIXTURE", directory.path());
        environment.insert("AMNEZIA_DNS_CRASH_REAL", "1");
        environment.insert("AMNEZIA_DNS_CRASH_STAGE", stage);
        child.setProcessEnvironment(environment);
        child.start(QCoreApplication::applicationFilePath(), {"createCrashFixture"});
        QVERIFY(child.waitForFinished(10000));
        const auto childOutput = child.readAllStandardOutput() + child.readAllStandardError();
        QVERIFY2(child.exitCode() == 77, childOutput.constData());
        const auto files = QDir(directory.path()).entryList({"owned-*.json"}, QDir::Files);
        QCOMPARE(files.size(), stage == "two-generations" ? 2 : 1);
        QList<QHostAddress> aliases;
        QString activeJournal = files.first();
        for (const auto &name : files) {
            QFile saved(QDir(directory.path()).filePath(name));
            QVERIFY(saved.open(QIODevice::ReadOnly));
            const auto record = QJsonDocument::fromJson(saved.readAll()).object();
            const QHostAddress ip(record["installed"].toArray().first().toString());
            aliases.append(ip);
            if (backend.read(index)["dns"].toArray() == QJsonArray{ip.toString()}) activeJournal = name;
        }
        QFile journal(QDir(directory.path()).filePath(activeJournal));
        QVERIFY(journal.open(QIODevice::ReadOnly));
        const auto record = QJsonDocument::fromJson(journal.readAll()).object();
        journal.close();
        const QHostAddress alias(record["installed"].toArray().first().toString());
        QVERIFY(present(alias));
        const auto snapshot = record["dns_recovery"].toObject();
        QVERIFY(!snapshot.isEmpty());
        const auto crashDns = backend.read(index)["dns"].toArray();
        if (stage == "before") QCOMPARE(crashDns, originalDns);
        else QCOMPARE(crashDns, QJsonArray{alias.toString()});
        const auto recover = [&] {
            return recoverNativeDnsServiceOnStartup(directory.path());
        };
        // An administrator's edit must survive, with aliases/journal retained.
        const QJsonArray externalDns{"192.0.2.99"};
        QVERIFY(backend.write(index, "dns", externalDns));
        QVERIFY(!recover());
        QCOMPARE(backend.read(index)["dns"].toArray(), externalDns);
        QVERIFY(present(alias));
        QVERIFY(QFileInfo::exists(journal.fileName()));
        QVERIFY(backend.write(index, "dns", crashDns));
        if (stage == "published") {
            auto interrupted = backend;
            int writes = 0;
            interrupted.write = [&](int link, const QString &field, const QJsonValue &value) {
                if (++writes > 1) return false;
                return backend.write(link, field, value);
            };
            QVERIFY(!LinuxDnsRecovery::restore(snapshot, interrupted));
            QCOMPARE(writes, 2);
            QVERIFY(present(alias));
            QVERIFY(QFileInfo::exists(journal.fileName()));
        }
        QVERIFY(recover());
        QCOMPARE(backend.read(index), original);
        QCOMPARE(backend.read(otherIndex), originalOther);
        for (const auto &ip : aliases) QVERIFY(!present(ip));
        QVERIFY(QDir(directory.path()).entryList({"owned-*.json"}, QDir::Files).isEmpty());
        QVERIFY(recover());
        QCOMPARE(backend.read(index), original);
        QCOMPARE(backend.read(otherIndex), originalOther);
    }
    void realResolvedGracefulReplacementRetainsPreVpnSnapshot() {
        if (!qEnvironmentVariableIsSet("AMNEZIA_DNS_REAL_RESOLVED"))
            QSKIP("requires private real systemd-resolved and D-Bus");
        const auto backend = LinuxDnsRecovery::systemBackend();
        const int index = QNetworkInterface::interfaceFromName("dns-fixture").index();
        const auto original = backend.read(index);
        QVERIFY(!original.isEmpty());
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        DnsUtils::setNativeDnsFactory([&] { return createNativeDnsServiceGuard(directory.path()); });
        DnsUtilsLinux dns(nullptr);
        QVERIFY(dns.updateResolvers("dns-fixture", {QHostAddress("2001:db8::53")}, false, "current"));
        const auto first = backend.read(index)["dns"].toArray();
        QVERIFY(first != original["dns"].toArray());
        // Idempotent reuse must retain the same pre-VPN snapshot.
        QVERIFY(dns.updateResolvers("dns-fixture", {QHostAddress("2001:db8::53")}, false, "current"));
        QCOMPARE(backend.read(index)["dns"].toArray(), first);
        QVERIFY(dns.updateResolvers("dns-fixture", {QHostAddress("2001:db8::54")}, false, "current"));
        QVERIFY(backend.read(index)["dns"].toArray() != first);
        QVERIFY(dns.restoreResolvers("current"));
        QCOMPARE(backend.read(index), original);
        QVERIFY(QDir(directory.path()).entryList({"owned-*.json"}, QDir::Files).isEmpty());
    }
    void crashRecoveryRequiresDnsConfirmationAndPreservesModifiedState() {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        QProcess child;
        auto environment = QProcessEnvironment::systemEnvironment();
        environment.insert("AMNEZIA_DNS_CRASH_FIXTURE", directory.path());
        child.setProcessEnvironment(environment);
        child.start(QCoreApplication::applicationFilePath(), {"createCrashFixture"});
        QVERIFY(child.waitForFinished(10000));
        QCOMPARE(child.exitCode(), 77);
        const auto files = QDir(directory.path()).entryList({"owned-*.json"}, QDir::Files);
        QCOMPARE(files.size(), 1);
        const auto path = QDir(directory.path()).filePath(files[0]);
        QFile journal(path);
        QVERIFY(journal.open(QIODevice::ReadOnly));
        const auto bytes = journal.readAll();
        journal.close();
        const auto record = QJsonDocument::fromJson(bytes).object();
        const QHostAddress endpoint(record["installed"].toArray().first().toString());
        QVERIFY(present(endpoint));
        int callbacks = 0;
        QVERIFY(!recoverNativeDnsServiceGuards(directory.path(), [&](const QJsonObject &) {
            ++callbacks;
            return false; // OS DNS restoration failed: retain alias and journal.
        }));
        QCOMPARE(callbacks, 1);
        QVERIFY(present(endpoint));
        QVERIFY(QFileInfo::exists(path));
        auto modified = record;
        modified["interface_name"] = "unknown-interface";
        QVERIFY(journal.open(QIODevice::WriteOnly | QIODevice::Truncate));
        journal.write(QJsonDocument(modified).toJson());
        journal.close();
        QVERIFY(!recoverNativeDnsServiceGuards(directory.path(), [&](const QJsonObject &) {
            ++callbacks; return true;
        }));
        QCOMPARE(callbacks, 1); // Corruption cannot authorize even OS restore.
        QVERIFY(present(endpoint));
        QVERIFY(journal.open(QIODevice::WriteOnly | QIODevice::Truncate));
        QCOMPARE(journal.write(bytes), qint64(bytes.size()));
        journal.close();
        QVERIFY(QProcess::execute("ip", {"address", "add", "192.0.2.11/32", "dev", "dns-fixture"}) == 0);
        QVERIFY(!recoverNativeDnsServiceGuards(directory.path(), [&](const QJsonObject &) {
            ++callbacks; return true;
        }));
        QCOMPARE(callbacks, 1);
        QVERIFY(present(endpoint));
        QVERIFY(QProcess::execute("ip", {"address", "del", "192.0.2.11/32", "dev", "dns-fixture"}) == 0);
        QVERIFY(!recoverNativeDnsServiceGuards(directory.path(), [&](const QJsonObject &) {
            ++callbacks;
            if (!journal.open(QIODevice::Append)) return false;
            journal.write("\n");
            journal.close();
            return true; // Late journal modification invalidates authorization.
        }));
        QCOMPARE(callbacks, 2);
        QVERIFY(present(endpoint));
        QVERIFY(journal.open(QIODevice::WriteOnly | QIODevice::Truncate));
        QCOMPARE(journal.write(bytes), qint64(bytes.size()));
        journal.close();
        QVERIFY(recoverNativeDnsServiceGuards(directory.path(), [&](const QJsonObject &saved) {
            ++callbacks;
            return saved == record && present(endpoint); // Explicit test OS confirmation.
        }));
        QCOMPARE(callbacks, 3);
        QVERIFY(!present(endpoint));
        QVERIFY(!QFileInfo::exists(path));
        QVERIFY(recoverNativeDnsServiceGuards(directory.path(), [&](const QJsonObject &) {
            ++callbacks; return false;
        }));
        QCOMPARE(callbacks, 3); // Restart/retry is idempotent.
    }
    void actualAliasesAndGoGenerations() {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        const QList<QHostAddress> original = {QHostAddress("2001:db8::53"), QHostAddress("2001:db8::53")};
        auto first = createNativeDnsServiceGuard(directory.path());
        QList<QHostAddress> endpoints;
        QVERIFY(first->prepare("dns-fixture", original, endpoints));
        QCOMPARE(endpoints.size(), 2);
        QVERIFY(endpoints[0] != endpoints[1]);
        QVERIFY(first->healthy());
        QVERIFY(!recoverNativeDnsServiceGuards(directory.path(), [](const QJsonObject &) {
            QTest::qFail("live owner must not invoke recovery", __FILE__, __LINE__);
            return true;
        }));
        QVERIFY(first->matches("dns-fixture", original));
        for (const auto &ip : endpoints) {
            QVERIFY(present(ip));
            QVERIFY(reply(ip, false, 28, 0));
            QVERIFY(reply(ip, true, 28, 0));
            QVERIFY(reply(ip, false, 1, 2));
        }
        auto second = createNativeDnsServiceGuard(directory.path());
        QList<QHostAddress> replacement;
        QVERIFY(second->prepare("dns-fixture", original, replacement));
        QVERIFY(first->healthy());
        QVERIFY(second->healthy());
        QVERIFY(reply(endpoints[0], true, 28, 0)); // Still-published predecessor.
        QVERIFY(first->retire());
        for (const auto &ip : endpoints) QVERIFY(!present(ip));
        QVERIFY(second->healthy());
        QVERIFY(reply(replacement[0], false, 28, 0));
        QCOMPARE(QDir(directory.path()).entryList({"owned-*.json"}, QDir::Files).size(), 1);
        QVERIFY(second->retire());
        for (const auto &ip : replacement) QVERIFY(!present(ip));
        QVERIFY(QDir(directory.path()).entryList({"owned-*.json"}, QDir::Files).isEmpty());
        QVERIFY(present(QHostAddress("192.0.2.10")));
    }
    void journalReplacementCannotDeleteAssignedState() {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        auto guard = createNativeDnsServiceGuard(directory.path());
        QList<QHostAddress> endpoints;
        QVERIFY(guard->prepare("dns-fixture", {QHostAddress("2001:db8::53")}, endpoints));
        const auto files = QDir(directory.path()).entryList({"owned-*.json"}, QDir::Files);
        QCOMPARE(files.size(), 1);
        QFile journal(QDir(directory.path()).filePath(files[0]));
        QVERIFY(journal.open(QIODevice::ReadOnly));
        const auto original = journal.readAll();
        journal.close();
        QVERIFY(journal.open(QIODevice::Append));
        QCOMPARE(journal.write("\n"), qint64(1));
        journal.close();
        QVERIFY(!guard->retire());
        QVERIFY(present(endpoints[0]));
        // Undo only this test's own edit; retain the failed proof above.
        QVERIFY(journal.open(QIODevice::WriteOnly | QIODevice::Truncate));
        QCOMPARE(journal.write(original), qint64(original.size()));
        journal.close();
        QVERIFY(guard->retire());
        QVERIFY(!present(endpoints[0]));
    }
    void lostResolverScopeReportsFailureEvenWhileNativeLinkIsUp() {
        QVERIFY(QProcess::execute("ip", {"link", "set", "lo", "up"}) == 0);
        auto restoreLoopback = qScopeGuard([] {
            QProcess::execute("ip", {"link", "set", "lo", "up"});
        });
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        auto guard = createNativeDnsServiceGuard(directory.path());
        QList<QHostAddress> endpoints;
        QVERIFY(guard->prepare("dns-fixture", {QHostAddress("127.0.0.53")}, endpoints));
        QVERIFY(guard->healthy());
        QVERIFY(QProcess::execute("ip", {"link", "set", "lo", "down"}) == 0);
        QVERIFY(QNetworkInterface::interfaceFromName("dns-fixture").flags()
                    .testFlag(QNetworkInterface::IsUp));
        QVERIFY(!guard->healthy());
        QVERIFY(QProcess::execute("ip", {"link", "set", "lo", "up"}) == 0);
        QVERIFY(guard->retire());
        QVERIFY(!present(endpoints[0]));
    }
    void uncertainPublicationKeepsRealEndpointUntilRestore() {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        DnsUtils::setNativeDnsFactory([&] { return createNativeDnsServiceGuard(directory.path()); });
        Resolvers dns;
        dns.publish = false;
        QVERIFY(!dns.updateResolvers("dns-fixture", {QHostAddress("2001:db8::53")}, false));
        QCOMPARE(dns.last.size(), 1);
        const auto endpoint = dns.last[0];
        QVERIFY(reply(endpoint, false, 28, 0));
        dns.restore = false;
        QVERIFY(!dns.restoreResolvers());
        QVERIFY(reply(endpoint, true, 28, 0));
        dns.restore = true;
        QVERIFY(dns.restoreResolvers());
        QVERIFY(!present(endpoint));
    }
};

QTEST_GUILESS_MAIN(TestNativeDnsService)
#include "testNativeDnsService.moc"
