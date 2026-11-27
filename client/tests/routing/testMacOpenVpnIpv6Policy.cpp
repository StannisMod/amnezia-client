#include <QtTest>
#include "../../platforms/macos/daemon/macopenvpnipv6table.h"

namespace mac6 = amnezia::macOpenVpnIpv6;
namespace {
const QString host = QStringLiteral("2001:db8:42::4");
const QString secondHost = QStringLiteral("64:ff9b::c000:201");
const mac6::Path vpn{QStringLiteral("utun7"), {}};
const mac6::Path native{QStringLiteral("en0"), QHostAddress("fe80::1%en0")};
QString key(const mac6::Route &route) { return route.host + '|' + route.scope; }
struct Fixture {
    QMap<QString, mac6::Route> rows;
    QList<mac6::Route> created;
    int creates = 0, changes = 0, failCreate = 0, failChange = 0;
    int failCreateAfterCommit = 0, failChangeAfterCommit = 0;
    bool failRemoval = false, failPrimaryRemoval = false, corruptSources = false, wrongSelection = false;
    mac6::Api api()
    {
        mac6::Api api;
        api.select = [this](const QString &, const QString &, bool throughVpn) {
            return std::optional<mac6::Path>{throughVpn && !wrongSelection ? vpn : native};
        };
        api.sources = [this](const QString &address) {
            QList<mac6::Path> paths{vpn, native};
            if (corruptSources && rows.contains(address + '|')) paths[1] = vpn;
            return std::optional<QList<mac6::Path>>{paths};
        };
        api.read = [this](const QString &address, const QString &scope) {
            const auto it = rows.constFind(address + '|' + scope);
            return std::optional<mac6::Observed>{{it == rows.cend()
                ? std::optional<mac6::Route>{} : std::optional<mac6::Route>{it.value()}}};
        };
        api.create = [this](const mac6::Route &route) {
            if (++creates == failCreate) return false;
            const auto existing = rows.constFind(key(route));
            if (existing != rows.cend() && (route.scope.isEmpty() || !existing->transient
                || existing->managed || existing->path != route.path)) return false;
            rows.insert(key(route), route); created.append(route);
            return creates != failCreateAfterCommit;
        };
        api.changeOwned = [this](const mac6::Route &before, const mac6::Route &after) {
            if (++changes == failChange || !rows.contains(key(before))) return false;
            if (rows[key(before)] == after) return true;
            if (!(rows[key(before)] == before) || !before.managed) return false;
            rows.insert(key(after), after);
            return changes != failChangeAfterCommit;
        };
        api.removeOwned = [this](const mac6::Route &route) {
            if (failRemoval || (failPrimaryRemoval && route.scope.isEmpty())) return false;
            if (rows.contains(key(route)) && rows[key(route)] == route && route.managed) rows.remove(key(route));
            return true;
        };
        return api;
    }
};
}

class MacOpenVpnIpv6PolicyTest : public QObject {
    Q_OBJECT
private slots:
    void localLinkLocalRouteKeepsItsOwningZoneNotLoopbackIndex()
    {
        const auto exists = [](unsigned index) { return index == 1 || index == 7; };
        QCOMPARE(*mac6::linkLocalZone(7, 0, 1, true, exists), 7u);
        QCOMPARE(*mac6::linkLocalZone(0, 7, 1, true, exists), 7u);
        QCOMPARE(*mac6::linkLocalZone(7, 7, 7, false, exists), 7u);
        QVERIFY(!mac6::linkLocalZone(7, 0, 1, false, exists));
        QVERIFY(!mac6::linkLocalZone(7, 1, 1, true, exists));
        QVERIFY(!mac6::linkLocalZone(8, 0, 1, true, exists));
        QVERIFY(!mac6::linkLocalZone(7, 0, 0, true, exists));
    }
    void unscopedReplacementPreservesPinsAndRestoresOnlyOwnedState()
    {
        const mac6::Route before{host, {}, vpn, true};
        const mac6::Route after{host, {}, native, true};
        const mac6::Route foreign{host, {}, native, false};
        for (int failure = 0; failure < 5; ++failure) {
            QMap<QString, mac6::Route> rows;
            rows.insert(key(before), before);
            const mac6::Route pin{host, vpn.device, vpn, true};
            rows.insert(key(pin), pin);
            int creates = 0;
            auto read = [&]() -> std::optional<mac6::Observed> {
                mac6::Observed result;
                if (rows.contains(key(before))) result.exact = rows.value(key(before));
                return result;
            };
            auto remove = [&](const mac6::Route &row) {
                if (failure == 1) return false;
                if (!(rows.value(key(row)) == row)) return false;
                rows.remove(key(row));
                return true;
            };
            auto create = [&](const mac6::Route &row) {
                ++creates;
                if (creates == 1 && failure == 2) return false;
                if (creates == 1 && failure == 3) {
                    rows.insert(key(row), foreign);
                    return false;
                }
                if (rows.contains(key(row))) return false;
                rows.insert(key(row), row);
                return !(creates == 1 && failure == 4);
            };
            QCOMPARE(mac6::replaceUnscoped(before, after, read, remove, create),
                     failure == 0 || failure == 4);
            QVERIFY(rows.value(key(pin)) == pin);
            QVERIFY(rows.value(key(before)) == (failure == 3 ? foreign
                : failure == 0 || failure == 4 ? after : before));
            QCOMPARE(creates, failure == 1 ? 0 : failure == 2 ? 2 : 1);
        }
    }
    void nativeTableSelectionRespectsScopesAndHandover()
    {
        const mac6::Path wifi{"en1", QHostAddress("fe80::2%en1")};
        QList<mac6::Entry> entries{
            {QHostAddress("::"), 0, native, {}, true, false, false},
            {QHostAddress("::"), 0, wifi, "en1", true, false, false},
            {QHostAddress("::"), 0, vpn, "utun7", true, false, false},
            {QHostAddress(host), 128, vpn, {}, true, false, true}
        };
        const auto live = [](const QString &) { return true; };
        QCOMPARE(*mac6::nativeDevice(entries, "utun7", "en1", live), QString("en0"));
        // A VPN global /128 must not hijack the path of an en0-bound socket.
        const auto oldNative = mac6::sourcePath(entries, QHostAddress(host), "en0");
        QVERIFY(oldNative.path && *oldNative.path == native && !oldNative.ambiguous);
        entries.append({QHostAddress(host), 128, native, "en0", true, false, true});
        QVERIFY(*mac6::sourcePath(entries, QHostAddress(host), "en0").path == native);
        entries[0].path = vpn; // VPN now owns the unscoped default too.
        QCOMPARE(*mac6::nativeDevice(entries, "utun7", "en0", live), QString("en0"));
        const auto afterHandover = [](const QString &name) { return name != "en0"; };
        QCOMPARE(*mac6::nativeDevice(entries, "utun7", "en0", afterHandover), QString("en1"));
        entries.append({QHostAddress("::"), 0, {"en2", QHostAddress("fe80::3%en2")}, "en2", true, false, false});
        QVERIFY(!mac6::nativeDevice(entries, "utun7", "en0", afterHandover));
        // Conflicting equally specific scoped paths are an error, not a guess.
        entries.append({QHostAddress(host), 128, {"en0", QHostAddress("fe80::9%en0")}, "en0", true, false, true});
        QVERIFY(mac6::sourcePath(entries, QHostAddress(host), "en0").ambiguous);
        entries.last().blocked = true;
        QVERIFY(!mac6::sourcePath(entries, QHostAddress(host), "en0").ambiguous);
    }
    void pinsPrecedeUnscopedChangesAndSurviveSwitches()
    {
        Fixture fixture;
        mac6::Policy policy(fixture.api());
        QVERIFY(policy.add("utun7", {host, host}, true));
        QCOMPARE(fixture.rows.size(), 3);
        QCOMPARE(fixture.created.size(), 3);
        QVERIFY(!fixture.created[0].scope.isEmpty());
        QVERIFY(!fixture.created[1].scope.isEmpty());
        QVERIFY(fixture.created[2].scope.isEmpty());
        for (int i = 0; i < 6; ++i) {
            const bool throughVpn = i % 2 != 0;
            QVERIFY(policy.add("utun7", {host}, throughVpn));
            QCOMPARE(fixture.rows.size(), 3);
            QVERIFY(fixture.rows[host + '|'].path == (throughVpn ? vpn : native));
            QVERIFY(fixture.rows[host + "|en0"].path == native);
            QVERIFY(fixture.rows[host + "|utun7"].path == vpn);
        }
        QVERIFY(!policy.add("utun8", {host}, true));
        QVERIFY(policy.clear());
        QVERIFY(fixture.rows.isEmpty());
    }
    void rejectsInvalidBatchBeforeAnyMutation()
    {
        Fixture fixture;
        mac6::Policy policy(fixture.api());
        for (const auto &invalid : {"192.0.2.1", "::", "::1", "ff02::1", "fe80::1", "2001:db8::1%en0", "::ffff:192.0.2.1"})
            QVERIFY(!policy.add("utun7", {host, invalid}, true));
        fixture.wrongSelection = true;
        QVERIFY(!policy.add("utun7", {host}, true));
        QCOMPARE(fixture.creates, 0);
        QCOMPARE(fixture.changes, 0);
        QVERIFY(!mac6::validPath({"-ifscope", {}}));
        QVERIFY(!mac6::validPath({"en0", QHostAddress("fe80::1%en1")}));
    }
    void foreignUnscopedRouteRejectsWholeBatch()
    {
        Fixture fixture;
        const mac6::Route foreign{secondHost, {}, native, false};
        fixture.rows.insert(key(foreign), foreign);
        mac6::Policy policy(fixture.api());
        QVERIFY(!policy.add("utun7", {host, secondHost}, true));
        QCOMPARE(fixture.creates, 0);
        QCOMPARE(fixture.rows.size(), 1);
        QVERIFY(policy.clear());
        QVERIFY(fixture.rows[key(foreign)] == foreign);
    }
    void borrowsScopedRouteAndNeverDeletesExternalReplacement()
    {
        Fixture fixture;
        const mac6::Route borrowed{host, "en0", native, false};
        fixture.rows.insert(key(borrowed), borrowed);
        mac6::Policy policy(fixture.api());
        QVERIFY(policy.add("utun7", {host}, true));
        QCOMPARE(fixture.rows.size(), 3);
        auto replacement = fixture.rows[host + '|'];
        replacement.managed = false;
        fixture.rows[host + '|'] = replacement;
        QVERIFY(!policy.add("utun7", {host}, false));
        QVERIFY(policy.clear());
        QCOMPARE(fixture.rows.size(), 2);
        QVERIFY(fixture.rows[key(borrowed)] == borrowed);
        QVERIFY(fixture.rows[key(replacement)] == replacement);
    }
    void transientKernelCloneBecomesDurablePin()
    {
        Fixture fixture;
        const mac6::Route cache{host, "en0", native, false, true};
        fixture.rows.insert(key(cache), cache);
        mac6::Policy policy(fixture.api());
        QVERIFY(policy.add("utun7", {host}, true));
        const auto pin = fixture.rows[host + "|en0"];
        QVERIFY(pin.managed && !pin.transient && pin.path == native);
        // Simulated expiry removes only cached entries, not the source pin.
        for (auto it = fixture.rows.begin(); it != fixture.rows.end();)
            if (it->transient) it = fixture.rows.erase(it); else ++it;
        QCOMPARE(fixture.rows.size(), 3);
        QVERIFY(policy.add("utun7", {host}, false));
        QVERIFY(policy.clear());
        QVERIFY(fixture.rows.isEmpty());
    }
    void secondChangeFailureRestoresWholeBatch()
    {
        Fixture fixture;
        mac6::Policy policy(fixture.api());
        QVERIFY(policy.add("utun7", {host, secondHost}, true));
        const auto original = fixture.rows;
        fixture.failChange = 2;
        QVERIFY(!policy.add("utun7", {host, secondHost}, false));
        QVERIFY(fixture.rows == original);
        fixture.failChange = 0;
        fixture.failChangeAfterCommit = fixture.changes + 1;
        QVERIFY(!policy.add("utun7", {host, secondHost}, false));
        QVERIFY(fixture.rows == original);
        fixture.failChangeAfterCommit = 0;
        QVERIFY(policy.add("utun7", {host, secondHost}, false));
        QVERIFY(policy.clear());
        QVERIFY(fixture.rows.isEmpty());
    }
    void failedCleanupBlocksUpdatesUntilReleased()
    {
        Fixture fixture;
        mac6::Policy policy(fixture.api());
        fixture.failCreate = 2;
        fixture.failRemoval = true;
        QVERIFY(!policy.add("utun7", {host}, true));
        QCOMPARE(fixture.rows.size(), 1);
        const auto creates = fixture.creates;
        QVERIFY(!policy.add("utun7", {secondHost}, true));
        QCOMPARE(fixture.creates, creates);
        fixture.failRemoval = false;
        QVERIFY(policy.clear());
        QVERIFY(fixture.rows.isEmpty());
        fixture.failCreate = 0;
        fixture.failCreateAfterCommit = fixture.creates + 1;
        QVERIFY(!policy.add("utun7", {host}, true));
        QVERIFY(fixture.rows.isEmpty());
        fixture.failCreateAfterCommit = 0;
        QVERIFY(policy.add("utun7", {host}, true));
        fixture.failPrimaryRemoval = true;
        QVERIFY(!policy.clear());
        QCOMPARE(fixture.rows.size(), 3); // Retain pins while the primary remains.
        fixture.failPrimaryRemoval = false;
        QVERIFY(policy.clear());
        QVERIFY(fixture.rows.isEmpty());
    }
    void changedSourcePathRollsBackRatherThanLosingOldSockets()
    {
        Fixture fixture;
        mac6::Policy policy(fixture.api());
        fixture.corruptSources = true;
        QVERIFY(!policy.add("utun7", {host}, true));
        QVERIFY(fixture.rows.isEmpty());
        fixture.corruptSources = false;
        QVERIFY(policy.add("utun7", {host}, true));
        QVERIFY(policy.clear());
    }
};
QTEST_GUILESS_MAIN(MacOpenVpnIpv6PolicyTest)
#include "testMacOpenVpnIpv6Policy.moc"
