#include <QtTest>
#include <QDir>
#include <QFileInfo>
#include "../../core/utils/domainRoutingConfig.h"
#include "../../core/utils/splitDnsConfig.h"
#include "../../core/utils/proxyIpv6Routes.h"
#include "../../core/utils/openVpnIpv6.h"
#include "../../core/utils/ipv6Policy.h"
#include "../../platforms/macos/daemon/macproxyipv6.h"
#include "../../platforms/windows/daemon/windowsproxyipv6.h"
#include "../../platforms/windows/daemon/windowsopenvpnipv6policy.h"
#include "../../platforms/windows/daemon/windowsopenvpnipv6routes.h"

namespace win6 = amnezia::windowsOpenVpnIpv6;
struct WindowsOpenVpnRouteFixture {
    std::vector<win6::Route> routes;
    int creates = 0, failCreate = 0, sourceQueries = 0;
    int updates = 0, failUpdate = 0;
    bool weak = false, changeSourcePath = false, changeDirectSourcePath = false;
    bool vpnSourceRequiresHostRoute = false;
    static win6::Address address(unsigned char value) {
        win6::Address result{}; result[0] = 0x20; result[1] = 1; result[15] = value; return result;
    }
    static win6::Path path(bool vpn) { return {vpn ? 1u : 2u, address(vpn ? 1 : 2), 0}; }
    static bool same(const win6::Route &a, const win6::Route &b) {
        return a.destination == b.destination && a.path == b.path && a.metric == b.metric;
    }
    win6::Api api() {
        win6::Api result;
        result.interfaceLuid = [](std::uint32_t index) -> std::optional<std::uint64_t> {
            if (index == 42) return 1; return {};
        };
        result.strongHost = [this](std::uint64_t) { return !weak; };
        result.sources = [] { return std::optional<std::vector<win6::Source>>{
            std::vector<win6::Source>{{address(10), 1}, {address(20), 2}}}; };
        result.path = [](std::uint64_t, const win6::Address &, bool vpn) { return std::optional<win6::Path>{path(vpn)}; };
        result.fromSource = [this](const win6::Address &source, const win6::Address &) {
            ++sourceQueries;
            bool vpn = source == address(10);
            // An include-only TAP profile has no broader route to a new
            // DNS address. Its original source still needs the owned /128.
            if (vpn && vpnSourceRequiresHostRoute &&
                std::none_of(routes.begin(), routes.end(), [](const win6::Route &row) {
                    return row.path.luid == 1;
                })) return std::optional<win6::Path>{};
            if ((changeSourcePath && !routes.empty()) || (changeDirectSourcePath &&
                std::any_of(routes.begin(), routes.end(), [](const win6::Route &row) {
                    return row.path.luid == 2;
                }))) vpn = !vpn;
            return std::optional<win6::Path>{path(vpn)};
        };
        result.foreignHostRouteExists = [this](const win6::Address &host, const std::vector<win6::Route> &ours) {
            return std::optional<bool>{std::any_of(routes.begin(), routes.end(), [&](const win6::Route &row) {
                return row.destination == host && std::none_of(ours.begin(), ours.end(), [&](const win6::Route &owned) { return same(row, owned); });
            })};
        };
        result.owns = [this](const win6::Route &row) {
            return std::any_of(routes.begin(), routes.end(), [&](const win6::Route &current) { return same(row, current); });
        };
        result.create = [this](const win6::Route &row) {
            if (++creates == failCreate) return false;
            if (std::any_of(routes.begin(), routes.end(), [&](const win6::Route &current) {
                    return current.destination == row.destination && current.path.luid == row.path.luid;
                })) return false;
            routes.push_back(row); return true;
        };
        result.interfaceMetric = [](std::uint64_t luid) -> std::optional<std::uint32_t> {
            return luid == 1 ? 25u : 75u;
        };
        result.updateOwned = [this](const win6::Route &before, const win6::Route &after) {
            if (++updates == failUpdate) return false;
            for (auto &route : routes) if (same(route, before)) { route = after; return true; }
            return false;
        };
        result.removeOwned = [this](const win6::Route &row) {
            routes.erase(std::remove_if(routes.begin(), routes.end(),
                [&](const win6::Route &current) { return same(row, current); }), routes.end());
            return true;
        };
        return result;
    }
};

class DomainRoutingConfigTest : public QObject {
    Q_OBJECT
private slots:
    void ipv6PreferenceDoesNotInventServerCapability() {
        QVERIFY(!amnezia::ipv6Policy::tunnelAvailable({}));
        QJsonObject config{{"protocol", "openvpn"}, {"openvpn_config_data", QJsonObject{{"ipv6Tunnel", true}}}};
        QVERIFY(amnezia::ipv6Policy::tunnelAvailable(config)); // Missing preference defaults ON.
        config["ipv6_enabled"] = false;
        QVERIFY(!amnezia::ipv6Policy::tunnelAvailable(config));
        config = {{"protocol", "awg"}, {"awg_config_data", QJsonObject{{"client_ip", "10.77.0.2, fd77::2/128"}}}};
        QVERIFY(amnezia::ipv6Policy::tunnelAvailable(config));
        config["awg_config_data"] = QJsonObject{{"client_ip", "10.77.0.2"}};
        QVERIFY(!amnezia::ipv6Policy::tunnelAvailable(config));
        config = {{"proxyIpv6", true}};
        QVERIFY(amnezia::ipv6Policy::tunnelAvailable(config));
        config["ipv6_enabled"] = false;
        QVERIFY(!amnezia::ipv6Policy::tunnelAvailable(config));
    }
    void disabledXrayIpv6PreservesForeignPolicyAndUsesUniqueTag() {
        const QJsonObject original{
            {"outbounds", QJsonArray{QJsonObject{{"protocol", "vless"}, {"tag", "amnezia-ipv6-disabled"},
                                                 {"settings", QJsonObject{{"synthetic", "preserve"}}}}}},
            {"routing", QJsonObject{{"domainStrategy", "AsIs"}, {"rules", QJsonArray{
                QJsonObject{{"type", "field"}, {"domain", QJsonArray{"example.test"}}, {"outboundTag", "amnezia-ipv6-disabled"}}}}}}
        };
        const auto input = QString::fromUtf8(QJsonDocument(original).toJson());
        const auto output = QJsonDocument::fromJson(amnezia::ipv6Policy::disableXray(input).toUtf8()).object();
        const auto outbounds = output.value("outbounds").toArray();
        QCOMPARE(outbounds.first(), original.value("outbounds").toArray().first());
        QCOMPARE(outbounds.last().toObject().value("tag").toString(), QString("amnezia-ipv6-disabled_"));
        QCOMPARE(outbounds.last().toObject().value("protocol").toString(), QString("blackhole"));
        const auto routing = output.value("routing").toObject();
        QCOMPARE(routing.value("domainStrategy"), QJsonValue("AsIs"));
        const auto rules = routing.value("rules").toArray();
        QCOMPARE(rules.size(), 2);
        QCOMPARE(rules.first().toObject().value("ip").toArray(), QJsonArray{"::/0"});
        QCOMPARE(rules.first().toObject().value("outboundTag"), outbounds.last().toObject().value("tag"));
        QCOMPARE(rules.last(), original.value("routing").toObject().value("rules").toArray().first());
        QCOMPARE(amnezia::ipv6Policy::disableXray("not-json"), QString("not-json"));
    }
    void windowsOpenVpnValidatesQtAddressesBeforeNativeChanges()
    {
        WindowsOpenVpnRouteFixture fixture;
        WindowsOpenVpnIpv6Routes routes(fixture.api(), [](const QHostAddress &local) -> std::uint32_t {
            return local == QHostAddress("10.8.0.6") ? 42 : 0;
        }, 555);
        QVERIFY(!routes.add("not-an-address", {"2001::1e"}, true));
        QVERIFY(!routes.add("10.8.0.7", {"2001::1e"}, true));
        QVERIFY(!routes.add("10.8.0.6", {"fe80::1%foreign"}, true));
        QVERIFY(!routes.add("10.8.0.6", {"::ffff:192.0.2.1"}, true));
        QCOMPARE(fixture.creates, 0);
        QVERIFY(routes.add("10.8.0.6", {"2001::1e"}, true));
        QCOMPARE(fixture.routes.size(), std::size_t(1));
        QCOMPARE(fixture.routes[0].destination, fixture.address(30));
    }
    void windowsOpenVpnUpdatesPreserveBothSourcePaths()
    {
        WindowsOpenVpnRouteFixture fixture;
        win6::Policy policy(fixture.api(), 555);
        const auto host = fixture.address(30);
        QVERIFY(policy.add(42, {host, host}, true));
        QCOMPARE(fixture.routes.size(), std::size_t(1));
        QCOMPARE(fixture.routes[0].path.luid, std::uint64_t(1));
        QVERIFY(policy.add(42, {host, host}, false));
        QCOMPARE(fixture.routes.size(), std::size_t(2));
        const auto active = std::find_if(fixture.routes.begin(), fixture.routes.end(),
                                        [](const win6::Route &route) { return route.path.luid == 2; });
        QVERIFY(active != fixture.routes.end());
        QCOMPARE(active->metric + 75u, 555u);
        QCOMPARE(fixture.sourceQueries, 8); // Both sources before/after each update.
        QVERIFY(policy.clear());
        QVERIFY(fixture.routes.empty());
    }
    void windowsOpenVpnIncludeDirectionChangeRetainsOriginalVpnPath()
    {
        WindowsOpenVpnRouteFixture fixture;
        fixture.vpnSourceRequiresHostRoute = true;
        win6::Policy policy(fixture.api(), 555);
        const auto host = fixture.address(30);
        QVERIFY(policy.add(42, {host}, true));
        // New sockets must become DIRECT without removing the sole route
        // available to TCP sockets already bound to the VPN source.
        QVERIFY(policy.add(42, {host}, false));
        QVERIFY(std::any_of(fixture.routes.begin(), fixture.routes.end(),
                            [](const win6::Route &row) { return row.path.luid == 1; }));
        QVERIFY(std::any_of(fixture.routes.begin(), fixture.routes.end(),
                            [](const win6::Route &row) { return row.path.luid == 2; }));
        for (int i = 0; i < 6; ++i) {
            const bool vpn = (i % 2) == 0;
            QVERIFY(policy.add(42, {host}, vpn));
            QCOMPARE(fixture.routes.size(), std::size_t(2));
            for (const auto &route : fixture.routes) {
                const bool selected = route.path.luid == (vpn ? 1u : 2u);
                const unsigned interfaceMetric = route.path.luid == 1 ? 25u : 75u;
                QCOMPARE(route.metric + interfaceMetric, selected ? 555u : 556u);
            }
        }
        QVERIFY(policy.clear());
        QVERIFY(fixture.routes.empty());
    }
    void windowsOpenVpnMetricFailureRestoresBothOwnedPaths()
    {
        WindowsOpenVpnRouteFixture fixture;
        fixture.vpnSourceRequiresHostRoute = true;
        win6::Policy policy(fixture.api(), 555);
        const auto host = fixture.address(30);
        QVERIFY(policy.add(42, {host}, true));
        QVERIFY(policy.add(42, {host}, false));
        const auto original = fixture.routes;
        // The preferred route changes first; fail the second metric change.
        fixture.failUpdate = fixture.updates + 2;
        QVERIFY(!policy.add(42, {host}, true));
        QCOMPARE(fixture.routes.size(), original.size());
        for (std::size_t i = 0; i < original.size(); ++i)
            QVERIFY(fixture.same(original[i], fixture.routes[i]));
        fixture.failUpdate = 0;
        QVERIFY(policy.add(42, {host}, true));
        QVERIFY(policy.clear());
        QVERIFY(fixture.routes.empty());
    }
    void windowsOpenVpnRollsBackAndKeepsForeignRows()
    {
        WindowsOpenVpnRouteFixture fixture;
        win6::Policy policy(fixture.api(), 555);
        const auto first = fixture.address(30), second = fixture.address(40);
        fixture.failCreate = 2;
        QVERIFY(!policy.add(42, {first, second}, true));
        QVERIFY(fixture.routes.empty());
        fixture.failCreate = 0; fixture.changeSourcePath = true;
        QVERIFY(!policy.add(42, {first}, true));
        QVERIFY(fixture.routes.empty());
        fixture.changeSourcePath = false;
        fixture.routes.push_back({second, fixture.path(false), 999});
        fixture.creates = 0;
        QVERIFY(!policy.add(42, {first, second}, true));
        QCOMPARE(fixture.creates, 0); // Validate the whole batch before mutation.
        QCOMPARE(fixture.routes.size(), std::size_t(1));
        QVERIFY(policy.add(42, {first}, true));
        fixture.routes.back().metric = 777; // Administrator replaced our row.
        QVERIFY(policy.clear());
        QCOMPARE(fixture.routes.size(), std::size_t(2));
        fixture.weak = true;
        QVERIFY(!policy.add(42, {fixture.address(50)}, true));
        QCOMPARE(fixture.routes.size(), std::size_t(2));
    }
    void windowsOpenVpnFailedDirectionChangeRestoresPreviousRoute()
    {
        WindowsOpenVpnRouteFixture fixture;
        win6::Policy policy(fixture.api(), 555);
        const auto host = fixture.address(30);
        QVERIFY(policy.add(42, {host}, true));
        const auto original = fixture.routes.front();
        fixture.changeDirectSourcePath = true;
        QVERIFY(!policy.add(42, {host}, false));
        QCOMPARE(fixture.routes.size(), std::size_t(1));
        QVERIFY(fixture.same(fixture.routes.front(), original));
        fixture.changeDirectSourcePath = false;
        QVERIFY(policy.add(42, {host}, false));
        QCOMPARE(fixture.routes.size(), std::size_t(2));
        const auto direct = std::find_if(fixture.routes.begin(), fixture.routes.end(),
                                        [](const win6::Route &route) { return route.path.luid == 2; });
        QVERIFY(direct != fixture.routes.end());
        QCOMPARE(direct->metric + 75u, 555u);
        QVERIFY(policy.clear());
        QVERIFY(fixture.routes.empty());
    }
    void openVpnCapabilityRequiresAnActiveTunnel()
    {
        const QString config = "server-ipv6 fd6e:a81b:704f:1101::/64\n";
        const QString row = "fd6ea81b704f11010000000000000001 00000003 40 00 80 tun0\n";
        QVERIFY(amnezia::openVpnIpv6::activeServerTunnel(config, row));
        QVERIFY(amnezia::openVpnIpv6::activeServerTunnel("\t--" + config.trimmed() + " # managed\n", row));
        QVERIFY(!amnezia::openVpnIpv6::activeServerTunnel("# " + config, row));
        QVERIFY(!amnezia::openVpnIpv6::activeServerTunnel(config, QString(row).replace("tun0", "eth0")));
        QVERIFY(!amnezia::openVpnIpv6::activeServerTunnel(config, QString(row).replace(" 80 ", " 40 ")));
        QVERIFY(!amnezia::openVpnIpv6::activeServerTunnel(config, QString(row).replace("fd6e", "fd99")));
        QVERIFY(!amnezia::openVpnIpv6::activeServerTunnel(config, ""));
    }
    void windowsIpv6ChangesAreTemporaryAndOwned()
    {
        QList<QStringList> calls;
        int additions = 0;
        WindowsProxyIpv6 policy(42, [&](const QStringList &arguments) {
            calls.append(arguments);
            if (arguments.contains("add") && arguments.contains("route")) return ++additions != 2;
            return true;
        });
        QVERIFY(!policy.configure({"::/0"}, {}));
        int deletedRoutes = 0;
        for (const auto &args : calls) {
            QVERIFY(args.contains("interface=42"));
            QVERIFY(args.contains("store=active"));
            QVERIFY(!args.contains("store=persistent"));
            if (args.contains("route") && args.contains("delete")) {
                ++deletedRoutes;
                QVERIFY(args.contains("prefix=::/1"));
                QVERIFY(!args.contains("prefix=8000::/1"));
            }
        }
        QCOMPARE(deletedRoutes, 1);
        QVERIFY(calls.last().contains("delete"));
        QVERIFY(calls.last().contains("address=fdfe:dcba:9876::2"));
        calls.clear();
        QVERIFY(policy.clear());
        QVERIFY(calls.isEmpty());
        WindowsProxyIpv6 invalid(0, [&](const QStringList &args) { calls.append(args); return true; });
        QVERIFY(!invalid.configure({"::/0"}, {}));
        QVERIFY(calls.isEmpty());
    }
    void desktopIpv6RollbackOwnsOnlySuccessfulChanges()
    {
        QStringList calls;
        int additions = 0;
        MacProxyIpv6 policy([&](const QString &program, const QStringList &arguments) {
            calls.append(program + ' ' + arguments.join(' '));
            if (program.endsWith("route") && arguments.contains("add")) return ++additions != 2;
            return true;
        });
        QVERIFY(!policy.configure({"::/0"}, {}));
        QVERIFY(calls.contains("/sbin/route -n delete -inet6 -net ::/1 -interface utun22"));
        QVERIFY(!calls.contains("/sbin/route -n delete -inet6 -net 8000::/1 -interface utun22"));
        QCOMPARE(calls.last(), QString("/sbin/ifconfig utun22 inet6 fdfe:dcba:9876::2 -alias"));
        calls.clear();
        QVERIFY(policy.clear());
        QVERIFY(calls.isEmpty());
        // A failed first add (e.g. an existing foreign route) must never be deleted.
        MacProxyIpv6 foreign([&](const QString &program, const QStringList &arguments) {
            calls.append(program + ' ' + arguments.join(' '));
            return !(program.endsWith("route") && arguments.contains("add"));
        });
        QVERIFY(!foreign.configure({"fd00::/8"}, {}));
        QVERIFY(std::none_of(calls.cbegin(), calls.cend(), [](const QString &call) { return call.contains(" delete "); }));
    }
    void desktopIpv6CleanupCanRetry()
    {
        int deletes = 0;
        MacProxyIpv6 policy([&](const QString &program, const QStringList &arguments) {
            if (program.endsWith("route") && arguments.contains("delete")) return ++deletes > 1;
            return true;
        });
        QVERIFY(policy.configure({"fd00::/8"}, {}));
        QVERIFY(!policy.clear());
        QVERIFY(policy.clear());
        QCOMPARE(deletes, 2);
    }
    void desktopIpv6CapturePreservesExceptions()
    {
        QStringList routes;
        QVERIFY(amnezia::routing::proxyIpv6Routes({"::/0", "2001:db8::/32"},
            {"2001:db8:1::/48", "fd00::/8", "2001:db8:2::7/128"}, routes));
        QVERIFY(!routes.contains("::/0"));
        const auto captured = [&](const QString &value) {
            const QHostAddress address(value);
            return std::any_of(routes.cbegin(), routes.cend(), [&](const QString &prefix) {
                return address.isInSubnet(QHostAddress::parseSubnet(prefix));
            });
        };
        QVERIFY(captured("2001:db8:3::1"));
        QVERIFY(captured("fc00::1"));
        QVERIFY(captured("64:ff9b::c000:201"));
        QVERIFY(!captured("2001:db8:1::1234"));
        QVERIFY(!captured("fd12::1"));
        QVERIFY(!captured("2001:db8:2::7"));
        QVERIFY(captured("2001:db8:2::8"));
        // No address may match two owned routes, including overlapping inputs.
        for (int i = 0; i < routes.size(); ++i)
            for (int j = i + 1; j < routes.size(); ++j) {
                const auto a = QHostAddress::parseSubnet(routes[i]);
                const auto b = QHostAddress::parseSubnet(routes[j]);
                QVERIFY(!a.first.isInSubnet(b) && !b.first.isInSubnet(a));
            }
        QVERIFY(amnezia::routing::proxyIpv6Routes({"fd00::/8", "64:ff9b::/96"}, {}, routes));
        QVERIFY(!captured("2001:db8::1"));
        QVERIFY(captured("fd12::1"));
        QVERIFY(captured("64:ff9b::c000:201"));
        QVERIFY(amnezia::routing::proxyIpv6Routes({"::/0"}, {"::/0"}, routes));
        QVERIFY(routes.isEmpty());
        routes = {"unchanged"};
        QVERIFY(!amnezia::routing::proxyIpv6Routes({"::/129"}, {}, routes));
        QVERIFY(!amnezia::routing::proxyIpv6Routes({"::/0"}, {"192.0.2.0/24"}, routes));
        QCOMPARE(routes, QStringList{"unchanged"});
    }
    void portablePoliciesMatchEngineCorpus()
    {
        const auto path = QDir(QFileInfo(QString::fromUtf8(__FILE__)).absolutePath())
            .filePath("../../../native/routing/rules/testdata/portable-cases.json");
        QFile file(path);
        QVERIFY2(file.open(QIODevice::ReadOnly), qPrintable(path));
        const auto cases = QJsonDocument::fromJson(file.readAll()).array();
        QVERIFY(!cases.isEmpty());
        for (auto value : cases) {
            const auto row = value.toObject();
            const auto config = row.value("config").toObject();
            QJsonObject normalized;
            QString error;
            const bool valid = amnezia::routing::normalizeConfig(config, normalized, error);
            QCOMPARE(valid, !row.value("invalid").toBool());
            if (!valid) { QVERIFY(!error.isEmpty()); continue; }
            QCOMPARE(normalized.value("version").toInt(), 2);
            QJsonObject restored;
            const auto exported = QJsonDocument(normalized).toJson();
            QVERIFY(amnezia::routing::normalizeConfig(QJsonDocument::fromJson(exported).object(), restored, error));
            QCOMPARE(restored, normalized);
            // Includes disabled rules, overlapping conditions and source order.
            QCOMPARE(restored.value("rules").toArray().size(), config.value("rules").toArray().size());
            for (auto probe : row.value("probes").toArray()) {
                const auto q = probe.toObject();
                const auto result = amnezia::routing::inspectRule(restored, q.value("domain").toString(),
                    q.value("ip").toString(), QString::number(q.value("port").toInt()), q.value("network").toString());
                QVERIFY2(!result.contains("error"), qPrintable(result.value("error").toString()));
                QCOMPARE(result.value("action").toString(), q.value("action").toString());
                QCOMPARE(result.value("rule").toInt(), q.value("rule").toInt());
            }
        }
    }
    void portValidationAndInspectionErrors()
    {
        QString ports;
        QVERIFY(amnezia::routing::normalizePorts("443, 80-81, 81-82,0080", ports));
        QCOMPARE(ports, QString("80-82,443"));
        for (const auto &bad : {"0", "65536", "1-0", "1-2-3", "1,", ",1", "+1", "1.5", "-1", "80:90"})
            QVERIFY2(!amnezia::routing::normalizePorts(bad, ports), bad);
        const QJsonObject config{{"version", 2}, {"default", "block"}, {"rules", QJsonArray{}}};
        for (const auto &destination : {"*.ru", "https://example.org", "1.2.3.4/24", ""})
            QVERIFY(amnezia::routing::inspectRule(config, destination, "", "443", "tcp").contains("error"));
        QVERIFY(amnezia::routing::inspectRule(config, "example.org", "", "65536", "tcp").contains("error"));
        QVERIFY(amnezia::routing::inspectRule(config, "example.org", "bad", "443", "tcp").contains("error"));
        QCOMPARE(amnezia::routing::inspectRule(config, "example.org", "", "53", "udp").value("reason").toString(), QString("managed_dns"));
    }
    void dnsAlwaysFollowsSiteRoutes()
    {
        const QJsonObject directRule{{"kind", "suffix"}, {"value", "corp.example"}, {"action", "direct"}};
        const QJsonObject routing{{"version", 1}, {"default", "vpn"}, {"rules", QJsonArray{directRule}}};
        const auto config = amnezia::dns::forSiteRoutes(routing, "10.77.0.2");
        QVERIFY(config.value("follow_routing").toBool());
        QVERIFY(config.value("rules").toArray().isEmpty());
        QVERIFY(!config.contains("preserve_network_domains"));
        const auto policies = config.value("policies").toObject();
        QCOMPARE(policies.size(), 2);
        const auto direct = policies.value("direct").toObject();
        QCOMPARE(direct.value("source").toString(), QString("network"));
        QCOMPARE(direct.value("path").toString(), QString("direct"));
        QVERIFY(direct.value("server").toString().isEmpty());
        const auto vpn = policies.value("vpn").toObject();
        QCOMPARE(vpn.value("server").toString(), QString("10.77.0.2"));
        QCOMPARE(vpn.value("path").toString(), QString("vpn"));
        // Reconnect reads the newly selected effective DNS, never a saved copy.
        const auto changed = amnezia::dns::forSiteRoutes(routing, "9.9.9.9");
        QCOMPARE(changed.value("policies").toObject().value("vpn").toObject().value("server").toString(), QString("9.9.9.9"));
        auto inverse = routing; inverse["default"] = "direct"; inverse["rules"] = QJsonArray{};
        QVERIFY(amnezia::dns::forSiteRoutes(inverse, "10.77.0.2").value("follow_routing").toBool());
    }
    void allVpnDnsDoesNotDependOnPhysicalDnsDiscovery()
    {
        for (const auto &rule : QJsonArray{QJsonObject{},
                 QJsonObject{{"kind", "cidr"}, {"value", "192.0.2.0/24"}, {"action", "direct"}},
                 QJsonObject{{"kind", "domain"}, {"value", "disabled.example"}, {"action", "direct"}, {"disabled", true}}}) {
            const QJsonObject routing{{"version", 1}, {"default", "vpn"}, {"rules", QJsonArray{rule}}};
            const auto config = amnezia::dns::forSiteRoutes(routing, "10.77.0.2");
            QCOMPARE(config.value("default").toString(), QString("vpn"));
            QVERIFY(!config.value("follow_routing").toBool());
            QCOMPARE(config.value("policies").toObject().size(), 1);
            QCOMPARE(config.value("policies").toObject().value("vpn").toObject().value("path").toString(), QString("vpn"));
        }
    }
    void conditionalDirectRulesDoNotSelectNetworkDns()
    {
        for (const auto &conditions : {QJsonObject{{"ports", "443"}}, QJsonObject{{"network", "udp"}}}) {
            auto rule = conditions;
            rule.insert("kind", "domain"); rule.insert("value", "conditional.example"); rule.insert("action", "direct");
            const QJsonObject routing{{"version", 2}, {"default", "block"}, {"rules", QJsonArray{rule}}};
            const auto dns = amnezia::dns::forSiteRoutes(routing, "10.77.0.2");
            QVERIFY(!dns.value("follow_routing").toBool());
            QCOMPARE(dns.value("policies").toObject().size(), 1);
            QCOMPARE(dns.value("default").toString(), QString("vpn"));
        }
    }
    void normalizeEditableRules()
    {
        using amnezia::routing::destinationRule;
        const auto suffix = destinationRule("*.EXAMPLE.org.", "direct", false);
        QCOMPARE(suffix.value("kind").toString(), QString("suffix"));
        QCOMPARE(suffix.value("value").toString(), QString("example.org"));
        QVERIFY(suffix.value("disabled").toBool());
        QCOMPARE(destinationRule("192.168.1.97/24", "direct", true).value("value").toString(), QString("192.168.1.0/24"));
        QCOMPARE(destinationRule("2001:db8:abcd::1/32", "vpn", true).value("value").toString(), QString("2001:db8::/32"));
        QCOMPARE(destinationRule("2001:db8::1", "vpn", true).value("value").toString(), QString("2001:db8::1/128"));
        QCOMPARE(destinationRule(QString::fromUtf8("ПРИМЕР.рф"), "vpn", true).value("value").toString(), QString("xn--e1afmkfd.xn--p1ai"));
        for (const auto &bad : {"*ru", "a.*.ru", "a..ru", "https://example.org", "1.2.3.4/99", "fe80::1%eth0"})
            QVERIFY2(destinationRule(bad, "direct", true).isEmpty(), bad);
        QVERIFY(destinationRule("example.org", "fallback", true).isEmpty());
    }
    void migrationPreservesNames()
    {
        const QVariantMap sites{{"example.com", QStringList{"203.0.113.7"}},
                                {"*.ru", QStringList{}}, {"192.168.0.0/16", QStringList{}},
                                {"2001:db8::1", QStringList{}}};
        const auto config = amnezia::routing::fromLegacySites(true, amnezia::RouteMode::VpnAllExceptSites, sites);
        QCOMPARE(config.value("version").toInt(), 1);
        QCOMPARE(config.value("default").toString(), QString("vpn"));
        const auto rules = config.value("rules").toArray();
        QCOMPARE(rules.size(), 4);
        for (auto value : rules) {
            const auto rule = value.toObject();
            QCOMPARE(rule.value("action").toString(), QString("direct"));
            const auto destination = rule.value("value").toString();
            if (destination == "example.com") QCOMPARE(rule.value("kind").toString(), QString("domain"));
            else if (destination == "*.ru") QCOMPARE(rule.value("kind").toString(), QString("suffix"));
            else QCOMPARE(rule.value("kind").toString(), QString("cidr"));
        }
        QVERIFY(!QJsonDocument(config).toJson().contains("203.0.113.7"));
    }
    void inverseAndDisabled()
    {
        const QVariantMap sites{{"example.com", "203.0.113.7"}};
        const auto inverse = amnezia::routing::fromLegacySites(true, amnezia::RouteMode::VpnOnlyForwardSites, sites);
        QCOMPARE(inverse.value("default").toString(), QString("direct"));
        QCOMPARE(inverse.value("rules").toArray().first().toObject().value("action").toString(), QString("vpn"));
        const auto disabled = amnezia::routing::fromLegacySites(false, amnezia::RouteMode::VpnOnlyForwardSites, sites);
        QCOMPARE(disabled.value("default").toString(), QString("vpn"));
        QVERIFY(disabled.value("rules").toArray().isEmpty());
    }
};
QTEST_APPLESS_MAIN(DomainRoutingConfigTest)
#include "testDomainRoutingConfig.moc"
