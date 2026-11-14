#pragma once

#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkInterface>
#include <QProcess>
#include <QMap>
#include <QSet>
#include <QElapsedTimer>
#include "linuxroutingtable.h"
#include <memory>
#include <map>
#include <vector>

// Per-OpenVPN-process host routes. Never replace an existing route, and retain
// old DNS destinations until the process exits so existing TCP keeps its path.
class LinuxOpenVpnIpv6Routes {
public:
    ~LinuxOpenVpnIpv6Routes() = default;
    LinuxOpenVpnIpv6Routes() = default;
    LinuxOpenVpnIpv6Routes(const LinuxOpenVpnIpv6Routes &) = delete;
    LinuxOpenVpnIpv6Routes &operator=(const LinuxOpenVpnIpv6Routes &) = delete;

    bool add(const QString &localIpv4, const QStringList &hosts, bool throughVpn)
    {
        if (QHostAddress(localIpv4).protocol() != QAbstractSocket::IPv4Protocol) return false;
        if (hosts.size() > 128 || m_owned.size() + hosts.size() > 4096) return false;
        QString tunnel;
        for (const auto &iface : QNetworkInterface::allInterfaces())
            for (const auto &address : iface.addressEntries())
                if (address.ip() == QHostAddress(localIpv4) && iface.flags().testFlag(QNetworkInterface::IsPointToPoint))
                    tunnel = iface.name();
        if (tunnel.isEmpty()) return false;
        QStringList prefixes;
        for (const auto &host : hosts) {
            const QHostAddress address(host);
            if (address.protocol() != QAbstractSocket::IPv6Protocol || !address.scopeId().isEmpty()
                || address.isMulticast() || address.isLoopback() || address == QHostAddress::AnyIPv6) return false;
            prefixes << address.toString() + "/128";
        }
        prefixes.removeDuplicates();
        // Install the destination table first. Source pins added afterwards
        // take priority and keep established tunnel sockets on their old path.
        if (!m_routesTable.ensureFamily("-6")) return false;
        if (m_sourcePins.empty()) {
            for (const auto &entry : QNetworkInterface::interfaceFromName(tunnel).addressEntries()) {
                const auto address = entry.ip();
                if (address.protocol() != QAbstractSocket::IPv6Protocol || address.isLinkLocal()) continue;
                auto pin = std::make_unique<LinuxRoutingTable>();
                if (!pin->ensureFamily("-6", address.toString() + "/128")
                    || !run({"-6", "route", "add", "default", "dev", tunnel, "table", QString::number(pin->table())})) return false;
                m_sourcePins.push_back(std::move(pin));
            }
            if (m_sourcePins.empty()) return false;
        }
        // Unbound new sockets select their source from the destination route.
        // Already bound native sockets must retain their previous per-host
        // path as well; pinning only tunnel sources protects the reverse case.
        if (!pinNativeSources(prefixes, tunnel)) return false;
        QStringList path{"dev", tunnel};
        if (!throughVpn) {
            QByteArray output;
            if (!run({"-6", "-j", "route", "show", "table", "main", "default"}, &output)) return false;
            const auto routes = QJsonDocument::fromJson(output).array();
            double bestMetric = 1e20;
            path.clear();
            for (const auto &value : routes) {
                const auto route = value.toObject();
                const auto device = route.value("dev").toString();
                const auto gateway = route.value("gateway").toString();
                const auto metric = route.value("metric").toDouble(1024);
                if (device.isEmpty() || device == tunnel || metric >= bestMetric) continue;
                if (!gateway.isEmpty() && QHostAddress(gateway).protocol() != QAbstractSocket::IPv6Protocol) continue;
                path = {"dev", device};
                if (!gateway.isEmpty()) path << "via" << gateway << "onlink";
                bestMetric = metric;
            }
            if (path.isEmpty()) return false;
        }
        QStringList added;
        for (const auto &prefix : prefixes) {
            if (m_owned.contains(prefix)) {
                if (m_owned[prefix] != path) { rollback(added); return false; }
                continue;
            }
            if (!run(QStringList{"-6", "route", "add", prefix, "table", QString::number(m_routesTable.table()), "metric", "1"} + path)) {
                rollback(added); return false;
            }
            m_owned.insert(prefix, path);
            added << prefix;
        }
        return true;
    }
private:
    struct NativePin {
        std::unique_ptr<LinuxRoutingTable> table;
        QSet<QString> prefixes;
    };
    bool pinNativeSources(const QStringList &prefixes, const QString &tunnel)
    {
        QElapsedTimer deadline;
        deadline.start();
        for (const auto &iface : QNetworkInterface::allInterfaces()) {
            if (iface.name() == tunnel || !iface.flags().testFlag(QNetworkInterface::IsUp)
                || iface.flags().testFlag(QNetworkInterface::IsLoopBack)) continue;
            for (const auto &entry : iface.addressEntries()) {
                const auto address = entry.ip();
                if (address.protocol() != QAbstractSocket::IPv6Protocol || address.isLinkLocal()
                    || address.isMulticast() || address.isLoopback() || address.isNull()) continue;
                const auto source = address.toString();
                for (const auto &prefix : prefixes) {
                    auto found = m_nativePins.find(source);
                    if (found != m_nativePins.end() && found->second.prefixes.contains(prefix)) continue;
                    if (deadline.elapsed() > 15000) return false;
                    QProcess lookup;
                    lookup.start("ip", {"-6", "-j", "route", "get", prefix.section('/', 0, 0), "from", source});
                    if (!lookup.waitForStarted(3000) || !lookup.waitForFinished(3000)) {
                        lookup.kill(); lookup.waitForFinished(1000); return false;
                    }
                    if (lookup.exitStatus() != QProcess::NormalExit) return false;
                    // iproute2 returns 2 when no path exists. There is then no
                    // previously usable source path to preserve.
                    if (lookup.exitCode() == 2) continue;
                    if (lookup.exitCode() != 0) return false;
                    QJsonParseError error;
                    const auto document = QJsonDocument::fromJson(lookup.readAllStandardOutput(), &error);
                    if (error.error != QJsonParseError::NoError || !document.isArray()
                        || document.array().size() != 1) return false;
                    const auto route = document.array().first().toObject();
                    const auto device = route.value("dev").toString();
                    const auto gateway = route.value("gateway").toString();
                    if (device.isEmpty() || (!gateway.isEmpty()
                        && QHostAddress(gateway).protocol() != QAbstractSocket::IPv6Protocol)) return false;
                    if (found == m_nativePins.end()) {
                        if (m_nativePins.size() >= 64) return false;
                        NativePin pin;
                        pin.table = std::make_unique<LinuxRoutingTable>();
                        if (!pin.table->ensureFamily("-6", source + "/128")) return false;
                        found = m_nativePins.emplace(source, std::move(pin)).first;
                    }
                    QStringList arguments{"-6", "route", "add", prefix, "table",
                        QString::number(found->second.table->table()), "dev", device};
                    if (!gateway.isEmpty()) arguments << "via" << gateway << "onlink";
                    if (!run(arguments)) return false;
                    found->second.prefixes.insert(prefix);
                }
            }
        }
        return true;
    }
    void rollback(const QStringList &prefixes)
    {
        for (const auto &prefix : prefixes)
            if (run(QStringList{"-6", "route", "del", prefix, "table", QString::number(m_routesTable.table()), "metric", "1"} + m_owned.value(prefix)))
                m_owned.remove(prefix);
    }
    static bool run(const QStringList &arguments, QByteArray *output = nullptr)
    {
        QProcess process;
        process.start("ip", arguments);
        if (!process.waitForStarted(3000) || !process.waitForFinished(3000)) {
            process.kill(); process.waitForFinished(1000); return false;
        }
        if (output) *output = process.readAllStandardOutput();
        return process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0;
    }
    QMap<QString, QStringList> m_owned;
    std::vector<std::unique_ptr<LinuxRoutingTable>> m_sourcePins;
    std::map<QString, NativePin> m_nativePins;
    // Destroy the destination table before releasing source pins. Cleanup is
    // bounded by table count, not the number of historical DNS destinations.
    LinuxRoutingTable m_routesTable;
};
