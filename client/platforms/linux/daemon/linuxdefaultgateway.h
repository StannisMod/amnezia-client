#pragma once

#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkInterface>
#include <QProcess>
#include <limits>

namespace amnezia::linuxNetwork {
inline QPair<QString, QNetworkInterface> defaultGateway()
{
    // Keep IPv4 preference for existing IPv4-only callers. An IPv6-only
    // uplink still returns its real IPv6 gateway and interface.
    for (const auto &family : {QStringLiteral("-4"), QStringLiteral("-6")}) {
        QProcess process;
        process.start("ip", {family, "-j", "route", "show", "table", "main", "default"});
        if (!process.waitForStarted(1000) || !process.waitForFinished(2000)) {
            process.kill(); process.waitForFinished(1000); continue;
        }
        if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) continue;
        QJsonParseError error;
        const auto document = QJsonDocument::fromJson(process.readAllStandardOutput(), &error);
        if (error.error != QJsonParseError::NoError || !document.isArray()) continue;
        QPair<QString,QNetworkInterface> best;
        qint64 bestMetric = std::numeric_limits<qint64>::max();
        for (const auto &value : document.array()) {
            const auto route = value.toObject();
            if (route.value("type").toString("unicast") != "unicast") continue;
            const auto destination = route.value("dst").toString();
            if (destination != "default" && destination != (family == "-4" ? "0.0.0.0/0" : "::/0")) continue;
            if (route.value("flags").toArray().contains("linkdown")) continue;
            const auto metric = route.value("metric").toInteger(0);
            if (metric < 0 || metric > std::numeric_limits<quint32>::max()) continue;
            if (metric >= bestMetric) continue;
            auto hops = route.value("nexthops").toArray();
            if (hops.isEmpty()) hops.append(route);
            for (const auto &hopValue : hops) {
                const auto hop = hopValue.toObject();
                if (hop.value("flags").toArray().contains("dead") || hop.value("flags").toArray().contains("linkdown")) continue;
                const auto iface = QNetworkInterface::interfaceFromName(hop.value("dev").toString());
                if (!iface.isValid() || !iface.flags().testFlag(QNetworkInterface::IsUp)) continue;
                const auto gateway = hop.value("gateway").toString();
                if (!gateway.isEmpty() && QHostAddress(gateway).protocol() !=
                        (family == "-4" ? QAbstractSocket::IPv4Protocol : QAbstractSocket::IPv6Protocol)) continue;
                best = {gateway, iface}; bestMetric = metric;
                break;
            }
        }
        if (best.second.isValid()) return best;
    }
    return {};
}
}
