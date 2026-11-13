#include <QCoreApplication>
#include <QRemoteObjectNode>
#include <QProcess>
#include <QJsonArray>
#include "rep_ipc_interface_replica.h"

// Disposable CI client of the real installed service's existing QtRO API.
// It sends no user profile or credentials and adds no production IPC methods.
int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    if (argc != 2) return 2;
    const QString mode(argv[1]);
    if (mode != "on" && mode != "off" && mode != "proxy-ipv6") return 2;
    if (mode == "proxy-ipv6" && qEnvironmentVariable("AMNEZIA_PROXY_ROUTE_TEST") != "isolated-docker") return 2;
    QRemoteObjectNode node;
#ifdef Q_OS_WIN
    node.connectToNode(QUrl("local:local:AmneziaVpnIpcInterface"));
#else
    node.connectToNode(QUrl("local:/tmp/local:AmneziaVpnIpcInterface"));
#endif
    QScopedPointer<IpcInterfaceReplica> replica(node.acquire<IpcInterfaceReplica>());
    if (!replica->waitForSource(8000)) return 3;
#ifdef Q_OS_LINUX
    if (mode == "proxy-ipv6") {
        auto ok = [](auto call) { return call.waitForFinished(12000) && call.returnValue(); };
        auto ip = [](const QStringList &args) {
            QProcess p; p.start("ip", args);
            if (!p.waitForFinished(5000) || p.exitCode() != 0) return QByteArray();
            return p.readAllStandardOutput();
        };
        auto ip6tables = [](const QStringList &args) {
            QProcess p; p.start("ip6tables", args);
            return p.waitForFinished(5000) && p.exitCode() == 0;
        };
        const auto originalRules = ip({"-6", "rule", "show"});
        if (!ok(replica->createTun("tun2", "198.18.0.1"))) return 10;
        if (!ok(replica->configureProxyIpv6({"::/0"}, {"2001:db8:2::/64"}))) return 11;
        if (!ip({"-6", "route", "get", "fd42::2"}).contains("dev tun2")) return 12;
        const auto directDevice = qEnvironmentVariable("AMNEZIA_PROXY_DIRECT_DEVICE", "lan0").toUtf8();
        if (!ip({"-6", "route", "get", "2001:db8:2::42"}).contains("dev " + directDevice)) return 13;
        const QJsonObject config{{"splitTunnelType",0},{"splitTunnelSites",QJsonArray()},
            {"dns1","2606:4700:4700::1111"},{"vpnServer","2001:db8:1::42"},{"proxyIpv6",true}};
        if (!ok(replica->enableKillSwitch(config,0))) return 14;
        if (!ip6tables({"-C","amnvpn.a.200.allowVPN","-j","amnvpn.200.allowVPN"})) return 15;
        if (!ip6tables({"-C","amnvpn.110.allowNets","-d","2001:db8:1::42/128","-j","ACCEPT"})) return 16;
        if (!ip6tables({"-C","amnvpn.320.allowDNS","-o","tun2+","-d","2606:4700:4700::1111/128","-p","udp","--dport","53","-j","ACCEPT"})) return 17;
        if (ip6tables({"-C","amnvpn.a.250.blockIPv6","-j","amnvpn.250.blockIPv6"})) return 18;
        if (!ip6tables({"-C","amnvpn.a.100.blockAll","-j","amnvpn.100.blockAll"})) return 19;
        if (!ok(replica->disableKillSwitch()) || !ok(replica->deleteTun("tun2"))) return 20;
        if (ip({"-6","rule","show"}) != originalRules) return 21;
        qInfo("LINUX_PROXY_IPV6_IPC_PASS");
        return 0;
    }
#endif
    auto call = replica->refreshKillSwitch(QString(argv[1]) == "on");
    if (!call.waitForFinished(12000) || !call.returnValue()) return 4;
    return 0;
}
